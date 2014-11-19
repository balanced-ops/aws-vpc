#!/usr/bin/env python

# Converted from VPC_With_VPN_Connection.template located at:
# http://aws.amazon.com/cloudformation/aws-cloudformation-templates/

"""
This template is for generating a new balanced VPC.

Generate:

    python vpc.py > vpc.json

Upload:

    aws s3 cp vpc.json s3://some-bucket/

Create:

    AWS_DEFAULT_REGION=us-west-2 aws cloudformation create-stack
    --template-url https://s3-us-west-1.amazonaws
    .com/some-bucket/vpc.json --stack-name prod-vpc-c
    --parameters ParameterKey=KeyName,ParameterValue=your-key-name

"""

from troposphere import Join, Output, FindInMap, Base64, If
from troposphere import Parameter, Ref, Tags, Template, ec2, autoscaling


# TODO: dehardcode this shit
REGION = 'us-west-2'
AVAILABILITY_ZONES = ['a', 'b', 'c']
SUBNET_BASE = '10.4'
VPC_NAME = 'prod-vpc'

assert len(AVAILABILITY_ZONES) < 6  # This should really be no more than 5


# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
class PROTOCOLS(object):
    ALL = -1
    TCP = 6
    ICMP = 1


class Networking(object):
    DNS = (
        'dns', 53, 53, PROTOCOLS.ALL, False, '0.0.0.0/0'
    )
    INBOUND_ANYWHERE = (
        'in', 1024, 65535, PROTOCOLS.ALL, False, '0.0.0.0/0'
    )
    OUTBOUND_ANYWHERE = (
        'out', 1024, 65535, PROTOCOLS.ALL, True, '0.0.0.0/0'
    )
    SSH_FROM_ANYWHERE = (
        'ssh', 22, 22, PROTOCOLS.TCP, False, '0.0.0.0/0'
    )
    HTTPS_FROM_OFFICE = (
        'https', 443, 443, PROTOCOLS.TCP, False, '199.241.202.154/32'
    )


class SubnetTemplate(object):

    ACL_RULE_COUNT = 0

    BASE_TAGS = dict(
        application=Ref('AWS::StackName'),
        stack=VPC_NAME,
    )

    ROUTING_TABLE = 'routingTable'

    def __init__(self, name, base_subnet_offset,
                 routing_table=None,
                 *networking_rules, **tags):
        self.name = name
        self.sanitized_name = name.replace('-', '')
        self.base_subnet_offset = base_subnet_offset
        self.networking_rules = networking_rules or (
            Networking.INBOUND_ANYWHERE,
            Networking.OUTBOUND_ANYWHERE,
        )
        self.ROUTING_TABLE = routing_table or self.ROUTING_TABLE
        tags.update(self.BASE_TAGS)
        self.tags = tags

    def subnet_cidrs(self):
        """
        Subnet CIDRs are generated via C-class, which means 254 USABLE
        IPs per subnet CIDR.

        :return: generator that builds subnet CIDRs via C-class, sequentially
                 incrementing to each availability zone.
        """
        return (
            '{}.{}.0/24'.format(SUBNET_BASE, x)
            for x in xrange(
                self.base_subnet_offset,
                self.base_subnet_offset + len(AVAILABILITY_ZONES)
            )
        )

    def _create_subnets(self):
        # create a subnet in every assigned AZ
        for subnet_cidr, az in zip(self.subnet_cidrs(), AVAILABILITY_ZONES):
            subnet = t.add_resource(ec2.Subnet(
                self.sanitized_name + az,
                VpcId=Ref('VPC'),
                AvailabilityZone=REGION + az,
                CidrBlock=subnet_cidr,
                Tags=Tags(Name=self.sanitized_name + az, **self.tags)
            ))
            # terrible hack - if this is the NAT routing table there isn't a
            # per-az routingTable / NAT combo to associate with.
            routingTable = (
                self.ROUTING_TABLE + az
                if self.ROUTING_TABLE == 'routingTable'
                else self.ROUTING_TABLE
            )
            t.add_resource(
                ec2.SubnetRouteTableAssociation(
                    self.sanitized_name + az + 'subnetRouteTableAssociation',
                    SubnetId=Ref(self.sanitized_name + az),
                    RouteTableId=Ref(routingTable),
                )
            )
            yield subnet

    def create_network_acls(self):
        # do assigned networking acl rules
        for rule_name, from_port, to_port, protocol, egress, cidr in (
                self.networking_rules
        ):
            self.ACL_RULE_COUNT += 1
            t.add_resource(ec2.NetworkAclEntry(
                self.sanitized_name + rule_name + 'public',
                CidrBlock=cidr,
                NetworkAclId=Ref(self.sanitized_name + 'Acl'),
                Egress=egress,
                RuleNumber=self.ACL_RULE_COUNT,
                Protocol=protocol,
                PortRange=ec2.PortRange(
                    self.sanitized_name + 'public',
                    From=from_port,
                    To=to_port,
                ),
                RuleAction='ALLOW',
            ))

        # generate acl
        network_acl = t.add_resource(ec2.NetworkAcl(
            self.sanitized_name + 'Acl',
            VpcId=Ref('VPC'),
            Tags=Tags(Name=self.sanitized_name + 'Acl', **self.tags)
        ))
        return network_acl

    @classmethod
    def _associate(cls, subnets, network_acl):
        [
            t.add_resource(
                ec2.SubnetNetworkAclAssociation(
                    subnet.name + 'NetworkAclAssociation',
                    SubnetId=Ref(subnet),
                    NetworkAclId=Ref(network_acl),
                )
            )
            for subnet in subnets
        ]

    def create(self):
        new_subnets = self._create_subnets()
        new_network_acl = self.create_network_acls()
        self._associate(new_subnets, new_network_acl)
        return new_subnets


t = Template()

t.add_version('2010-09-09')

t.add_description('AWS CloudFormation VPC Template.')

VPNAddress = t.add_parameter(Parameter(
    'VPNAddress',
    Type='String',
    Description='IP Address of your VPN device',
    Default='199.241.202.154',
    MinLength='7',
    AllowedPattern='(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})',
    MaxLength='15',
    ConstraintDescription='must be a valid IP address of the form x.x.x.x',
))

OnPremiseCIDR = t.add_parameter(Parameter(
    'OnPremiseCIDR',
    ConstraintDescription=(
        'must be a valid IP CIDR range of the form x.x.x.x/x.'),
    Description='IP Address range for your existing infrastructure',
    Default='10.1.0.0/16',
    MinLength='9',
    AllowedPattern='(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})',
    MaxLength='18',
    Type='String',
))

t.add_parameter([
    Parameter(
        'IAMRole',
        Description='IAM role name',
        Type='String',
        Default='nat',
    ),
    Parameter(
        'Tag',
        Description='Stack tag',
        Type='String',
        Default='bvpc',
    ),
    Parameter(
        'Env',
        Description='Environment.',
        AllowedValues=['test', 'prod'],
        Type='String',
        Default='test'
    ),
    Parameter(
        'KeyName',
        Description=(
            'Name of existing EC2 KeyPair to enable SSH access to NAT instances'
        ),
        Type='String',
    ),
    Parameter(
        'InstanceType',
        Description='Instance type',
        Type='String',
        AllowedValues=[
            't1.micro',
            't2.micro', 't2.small', 't2.medium',
            'm1.small', 'm3.medium', 'm3.large',
        ],
        Default='t2.micro',
    ),
    Parameter(
        'InternalDomain',
        Description='Internal Domain',
        Type='String',
        Default='vandelay.io'
    )
])

vpc_cidr = t.add_parameter(Parameter(
    'VPCCIDR',
    ConstraintDescription=(
        'must be a valid IP CIDR range of the form x.x.x.x/x.'),
    Description='IP Address range for the VPN connected VPC',
    Default=SUBNET_BASE + '.0.0/16',
    MinLength='9',
    AllowedPattern='(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})',
    MaxLength='18',
    Type='String',
))

public_cidr = t.add_parameter(Parameter(
    'publiccidr',
    Description='IP Address range for the the whole world',
    Default='0.0.0.0/0',
    Type='String',
))

SubnetCIDR = t.add_parameter(Parameter(
    'SubnetCIDR',
    ConstraintDescription=(
        'must be a valid IP CIDR range of the form x.x.x.x/x.'),
    Description='IP Address range for the VPN connected Subnet',
    Default=SUBNET_BASE + '.254.0/24',
    MinLength='9',
    AllowedPattern='(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})',
    MaxLength='18',
    Type='String',
))

dhcp = t.add_resource(ec2.DHCPOptions(
    'DHCP',
    DomainName=Join('.', [Ref('AWS::StackName'), Ref('InternalDomain')]),
    DomainNameServers=['AmazonProvidedDNS'],
))

t.add_resource(ec2.VPCDHCPOptionsAssociation(
    'dhcpAssociation',
    DhcpOptionsId=Ref('DHCP'),
    VpcId=Ref('VPC'),
))

# These are Ubuntu 14.04 LTS HVM instances
t.add_mapping('RegionMap', {
    'us-west-1': {
        'AMI': 'ami-796e653c',
        'AvailabilityZones': ['us-west-1a', 'us-west-1b'],
    },
    'us-west-2': {
        'AMI': 'ami-39501209',
        'AvailabilityZones': ['us-west-2a', 'us-west-2b', 'us-west-2c'],
    },
    'eu-west-1': {
        'AMI': 'ami-f4b11183',
        'AvailabilityZones': ['eu-west-2a', 'eu-west-2b', 'eu-west-2c'],
    },
    'us-east-1': {
        'AMI': 'ami-9aaa1cf2',
        'AvailabilityZones': ['us-east-1a', 'us-east-1b', 'us-east-1e'],
    },
})

t.add_resource(ec2.InternetGateway(
    'internetGateway',
    Tags=Tags(
        Name='internetGateway',
        Application=Ref('AWS::StackName'),
    )
))

t.add_resource(ec2.VPCGatewayAttachment(
    'gatewayAttachment',
    InternetGatewayId=Ref('internetGateway'),
    VpcId=Ref('VPC'),
))

for zone in AVAILABILITY_ZONES:
    t.add_resource(ec2.RouteTable(
        'routingTable' + zone,
        VpcId=Ref('VPC'),
        Tags=Tags(
            Name='routingTable' + zone,
            Application=Ref('AWS::StackName'),
            Region=REGION + zone
        )
    ))

    t.add_resource(ec2.Route(
        'worldwideroute' + zone,
        DestinationCidrBlock='0.0.0.0/0',
        InstanceId=Ref('NAT' + zone),
        RouteTableId=Ref('routingTable' + zone),
    ))

t.add_resource(ec2.RouteTable(
    'natRoutingTable',
    VpcId=Ref('VPC'),
    Tags=Tags(
        Name='natRoutingTable',
        Application=Ref('AWS::StackName'),
    )
))

t.add_resource(ec2.Route(
    'natroute',
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=Ref('internetGateway'),
    RouteTableId=Ref('natRoutingTable'),
))


def subnet_templates():
    #: prod subnets start at CIDR /16
    start = 0
    #: the max number of availability zones per subnet
    step = 10

    return (
        SubnetTemplate('nat',
                       start,
                       'natRoutingTable',
                       Networking.SSH_FROM_ANYWHERE,
                       Networking.OUTBOUND_ANYWHERE,
                       Networking.INBOUND_ANYWHERE,
                       Networking.DNS,
                       role='nat'),

        # DMZ (internet facing traffic)
        # This does not route via the NATs, traffic goes directly to these
        # instances. Use this for ELBs and single servers that directly handle
        # traffic.
        SubnetTemplate('dmz',
                       start + step * 1,
                       role='dmz',
                       routing_table='natRoutingTable'),

        # api (oltp requests)
        SubnetTemplate('oltp',
                       start + step * 2,
                       role='oltp'),

        # workers (offline requests)
        SubnetTemplate('offline',
                       start + (step * 3),
                       role='offline'),

        # infra (datastores etc)
        SubnetTemplate('infra',
                       start + (step * 4),
                       role='infra'),

    )


for subnet in subnet_templates():
    new_subnets = subnet.create()
    for subnet in new_subnets:
        t.add_output(Output(
            subnet.name,
            Description='SubnetId of the VPN connected subnet',
            Value=Ref(subnet),
        ))

ec2.CustomerGateway = t.add_resource(ec2.CustomerGateway(
    'CustomerGateway',
    BgpAsn='65000',
    IpAddress=Ref(VPNAddress),
    Type='ipsec.1',
    Tags=Tags(
        Application=Ref('AWS::StackName'),
        VPN=Join('', ['Gateway to ', Ref(VPNAddress)]),
    )
))

VPC = t.add_resource(ec2.VPC(
    'VPC',
    EnableDnsSupport='true',
    CidrBlock=Ref(vpc_cidr),
    EnableDnsHostnames='true',
    Tags=Tags(
        Application=Ref('AWS::StackName'),
        Network='VPN Connected VPC',
    )
))

VPNGateway = t.add_resource(ec2.VPNGateway(
    'VPNGateway',
    Type='ipsec.1',
    Tags=Tags(
        Application=Ref('AWS::StackName'),
    )
))

VPCId = t.add_output(Output(
    'VPCId',
    Description='VPCId of the newly created VPC',
    Value=Ref(VPC),
))

ssh_sgrp = t.add_resource(ec2.SecurityGroup(
    'SSHSecurityGroup',
    GroupDescription=Join(' ', [Ref('AWS::StackName'), 'ssh']),
    VpcId=Ref('VPC'),
    SecurityGroupIngress=[
        ec2.SecurityGroupRule(
            'SSH',
            IpProtocol='tcp',
            FromPort=22,
            ToPort=22,
            CidrIp=Ref(public_cidr),
        ),
    ],
    Tags=Tags(
        Name='SSHSecurityGroup',
        role='ssh',
    )
))

# NATs

nat_sgrp = t.add_resource(ec2.SecurityGroup(
    'NATSecurityGroup',
    GroupDescription=Join(' ', [Ref('AWS::StackName'), 'nat']),
    VpcId=Ref('VPC'),
    SecurityGroupIngress=[
        ec2.SecurityGroupRule(
            IpProtocol='icmp',
            FromPort='-1',
            ToPort='-1',
            CidrIp=Ref(public_cidr),
        ),
        ec2.SecurityGroupRule(
            'SSH',
            IpProtocol='tcp',
            FromPort=22,
            ToPort=22,
            CidrIp=Ref(public_cidr),
        ),
        ec2.SecurityGroupRule(
            'ALL',
            IpProtocol=str(PROTOCOLS.ALL),
            FromPort=0,
            ToPort=65535,
            CidrIp=Ref(vpc_cidr),
        ),
    ],
    Tags=Tags(
        Name='NATSecurityGroup',
        role='nat',
    )
))


for az in AVAILABILITY_ZONES:
    t.add_resource(ec2.EIP(
        'NATEIP' + az,
        Domain='vpc',
        InstanceId=Ref('NAT' + az)
    ))

    ec2_instance = t.add_resource(ec2.Instance(
        'NAT' + az,
        ImageId=FindInMap('RegionMap', Ref('AWS::Region'), 'AMI'),
        InstanceType=Ref('InstanceType'),
        KeyName=Ref('KeyName'),
        IamInstanceProfile=Ref('IAMRole'),
        SubnetId=Ref('nat' + az),
        SecurityGroupIds=[Ref(nat_sgrp), Ref(ssh_sgrp)],
        SourceDestCheck=False,
        Tags=Tags(
            Name='NAT' + az,
            role='nat',
        ),
        DependsOn=['gatewayAttachment', 'DHCP'],
        UserData=Base64(Join('', [
            '#!/bin/bash -v\n',
            'set -e -x\n',
            'cfn-init',
            ' --region ', Ref('AWS::Region'),
            ' --stack ', Ref('AWS::StackName'),
            ' --resource ', 'NAT' + az,
            ' --verbose', '\n',
            'result=$?', '\n',
        ])),
        Metadata={},
    ))


print(t.to_json())
