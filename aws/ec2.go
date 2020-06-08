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

func getEC2InstanceID(ctx context.Context, svc *ec2metadata.EC2Metadata) (string, error) {
	idDoc, err := svc.GetInstanceIdentityDocumentWithContext(ctx)
	if err != nil {
		return "", err
	}
	log.Infof("ec2-instance-id: %s", idDoc.InstanceID)
	return idDoc.InstanceID, nil
}

func getEC2Region(ctx context.Context, svc *ec2metadata.EC2Metadata) (string, error) {
	region, err := svc.RegionWithContext(ctx)
	if err != nil {
		return "", err
	}
	log.Infof("region: %s", region)
	return region, nil
}

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

func getEC2NetworkInterfaceId(ctx context.Context, svc *ec2.EC2, instanceId string) (networkInstanceId string, err error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
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
	out, err := svc.DescribeInstancesWithContext(ctx, input)
	if err != nil {
		if retriable(err) && i < defaultRetries {
			log.WithField("instance-id", instanceId).Info("retrying getting network-interface-id")
			i++
			goto retry
		}
		return "", err
	}

	if len(out.Reservations) <= 0 {
		return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", instanceId)
	}

	var interfaceId string
	for _, instance := range out.Reservations[0].Instances {
		if len(instance.NetworkInterfaces) == 0 {
			return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", instanceId)
		}
		for _, networkInterface := range instance.NetworkInterfaces {
			if *(networkInterface.Attachment.DeviceIndex) == 0 {
				interfaceId = *(networkInterface.NetworkInterfaceId)
				if interfaceId != "" {
					log.Infof("instance-id: %s, network-interface-id: %s", instanceId, interfaceId)
					return interfaceId, nil
				}
			}
			log.Infof("instance-id: %s, network-interface-id: %s", instanceId, interfaceId)
		}
		if interfaceId == "" {
			return "", fmt.Errorf("no network-interface-id found for EC2 instance %s", instanceId)
		}
	}
	return interfaceId, nil
}

func setEC2SourceDestinationCheck(ctx context.Context, svc *ec2.EC2, ec2NetId string, checkVal bool) error {
	input := &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(ec2NetId),
		SourceDestCheck: &ec2.AttributeBooleanValue{
			Value: aws.Bool(checkVal),
		},
	}

	i := 0
retry:
	_, err := svc.ModifyNetworkInterfaceAttributeWithContext(ctx, input)
	if err != nil {
		if retriable(err) && i < defaultRetries {
			log.WithField("net-instance-id", ec2NetId).Infof("retrying setting source-destination-check")
			i++
			goto retry
		}
		return err
	}

	log.Infof("set source-destination-check to %v on network-interface-id: %s", checkVal, ec2NetId)
	return nil
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

	ec2MetadataSvc := ec2metadata.New(awsSession)
	if ec2MetadataSvc == nil {
		return fmt.Errorf("error connecting to EC2 Metadata service: %v", err)
	}

	if !ec2MetadataSvc.AvailableWithContext(ctx) {
		return fmt.Errorf("EC2 metadata service is unavailable")
	}

	ec2Region, err := getEC2Region(ctx, ec2MetadataSvc)
	if err != nil {
		return fmt.Errorf("error getting ec2 region: %s", convertError(err))
	}

	ec2Id, err := getEC2InstanceID(ctx, ec2MetadataSvc)
	if err != nil {
		return fmt.Errorf("error getting ec2 instance-id: %s", convertError(err))
	}

	ec2Svc := ec2.New(awsSession, aws.NewConfig().WithRegion(ec2Region))
	if ec2Svc == nil {
		return fmt.Errorf("error connecting to EC2 service")
	}

	ec2NetId, err := getEC2NetworkInterfaceId(ctx, ec2Svc, ec2Id)
	if err != nil {
		return fmt.Errorf("error getting ec2 network-interface-id: %s", convertError(err))
	}

	checkVal := !checkSourceDestinationValueIsDisable(check)
	err = setEC2SourceDestinationCheck(ctx, ec2Svc, ec2NetId, checkVal)
	if err != nil {
		return fmt.Errorf("error setting src-dst-check for network-interface-id: %s", convertError(err))
	}

	return nil
}
