package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	log "github.com/sirupsen/logrus"
)

const (
	defaultTimeOut = 20
	defaultRetries = 3
)

func convertError(err error) string {
	if awsErr, ok := err.(awserr.Error); ok {
		return fmt.Sprintf("%s: %s", awsErr.Code(), awsErr.Message())
	}

	return fmt.Sprintf("%v", err.Error())
}

func retriable(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		switch awsErr.Code() {
		case "InternalError":
			return true
		case "InternalFailure":
			return true
		case "RequestLimitExceeded":
			return true
		case "ServiceUnavailable":
			return true
		case "Unavailable":
			return true
		}
	}

	return false
}

func checkSourceDestinationValueIsDisable(check string) bool {
	return check == "disable"
}

func UpdateSrcDstCheck(check string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeOut*time.Second)
	defer cancel()

	awsSession, err := awssession.NewSession()
	if err != nil {
		return fmt.Errorf("error creating AWS session: %v", err)
	}

    cli, err := NewEc2MetadataClient(awsSession)
	if err != nil {
		return err
	}

	if !cli.ec2MetadataSvc.AvailableWithContext(ctx) {
		return fmt.Errorf("EC2 metadata service is unavailable or not running on an EC2 instance")
	}

	ec2Region, err := cli.getEC2Region(ctx)
	if err != nil {
		return fmt.Errorf("error getting ec2 region: %s", convertError(err))
	}

	ec2Id, err := cli.getEC2InstanceID(ctx)
	if err != nil {
		return fmt.Errorf("error getting ec2 instance-id: %s", convertError(err))
	}

	ec2Cli, err := NewEc2Client(awsSession, ec2Region, ec2Id)
	if err != nil {
		return err
	}

	ec2NetId, err := ec2Cli.getEC2NetworkInterfaceId(ctx)
	if err != nil {
		return fmt.Errorf("error getting ec2 network-interface-id: %s", convertError(err))
	}

	checkVal := !checkSourceDestinationValueIsDisable(check)
	err = ec2Cli.setEC2SourceDestinationCheck(ctx, ec2NetId, checkVal)
	if err != nil {
		return fmt.Errorf("error setting src-dst-check for network-interface-id: %s", convertError(err))
	}

	log.Infof("Successfully set source-destination-check to %t on network-interface-id: %s", checkVal, ec2NetId)
	return nil
}

type ec2MetadataClient struct {
	ec2MetadataSvc *ec2metadata.EC2Metadata
}

func NewEc2MetadataClient(awsSession *awssession.Session) (*ec2MetadataClient, error) {
	svc := ec2metadata.New(awsSession)
	if svc == nil {
		return nil, fmt.Errorf("error connecting to EC2 Metadata service")
	}

	return &ec2MetadataClient{
		ec2MetadataSvc: svc,
	}, nil
}

func (c *ec2MetadataClient) getEC2InstanceID(ctx context.Context) (string, error) {
	idDoc, err := c.ec2MetadataSvc.GetInstanceIdentityDocumentWithContext(ctx)
	if err != nil {
		return "", err
	}
	log.Debugf("ec2-instance-id: %s", idDoc.InstanceID)
	return idDoc.InstanceID, nil
}

func (c *ec2MetadataClient) getEC2Region(ctx context.Context) (string, error) {
	region, err := c.ec2MetadataSvc.RegionWithContext(ctx)
	if err != nil {
		return "", err
	}
	log.Debugf("region: %s", region)
	return region, nil
}

type ec2Client struct {
	ec2Svc        *ec2.EC2
	ec2Region     string
	ec2InstanceId string
}

func NewEc2Client(awsSession *awssession.Session, region, instanceId string) (*ec2Client, error) {
	ec2Svc := ec2.New(awsSession, aws.NewConfig().WithRegion(region))
	if ec2Svc == nil {
		return nil, fmt.Errorf("error connecting to EC2 service")
	}

	return &ec2Client{
		ec2Svc:        ec2Svc,
		ec2Region:     region,
		ec2InstanceId: instanceId,
	}, nil
}

func (c *ec2Client) getEC2NetworkInterfaceId(ctx context.Context) (networkInstanceId string, err error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(c.ec2InstanceId),
		},
		Filters: []*ec2.Filter{
			{
				Name: aws.String("network-interface.attachment.device-index"),
				Values: []*string{
					aws.String("0"), // Only device-id-0
				},
			},
		},
	}

	i := 0
retry:
	out, err := c.ec2Svc.DescribeInstancesWithContext(ctx, input)
	if err != nil {
		if retriable(err) && i < defaultRetries {
			log.WithField("instance-id", c.ec2InstanceId).Debug("retrying getting network-interface-id")
			i++
			goto retry
		}
		return "", err
	}

	if len(out.Reservations) <= 0 {
		return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.ec2InstanceId)
	}

	var interfaceId string
	for _, instance := range out.Reservations[0].Instances {
		if len(instance.NetworkInterfaces) == 0 {
			return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.ec2InstanceId)
		}
		for _, networkInterface := range instance.NetworkInterfaces {
			if *(networkInterface.Attachment.DeviceIndex) == 0 {
				interfaceId = *(networkInterface.NetworkInterfaceId)
				if interfaceId != "" {
					log.Debugf("instance-id: %s, network-interface-id: %s", c.ec2InstanceId, interfaceId)
					return interfaceId, nil
				}
			}
			log.Debugf("instance-id: %s, network-interface-id: %s", c.ec2InstanceId, interfaceId)
		}
		if interfaceId == "" {
			return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", c.ec2InstanceId)
		}
	}
	return interfaceId, nil
}

func (c *ec2Client) setEC2SourceDestinationCheck(ctx context.Context, ec2NetId string, checkVal bool) error {
	input := &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(ec2NetId),
		SourceDestCheck: &ec2.AttributeBooleanValue{
			Value: aws.Bool(checkVal),
		},
	}

	i := 0
retry:
	_, err := c.ec2Svc.ModifyNetworkInterfaceAttributeWithContext(ctx, input)
	if err != nil {
		if retriable(err) && i < defaultRetries {
			log.WithField("net-instance-id", ec2NetId).Debug("retrying setting source-destination-check")
			i++
			goto retry
		}
		return err
	}
	return nil
}
