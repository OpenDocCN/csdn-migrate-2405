# Python 无服务器微服务构建指南（二）

> 原文：[`zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09`](https://zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：部署您的无服务器堆栈

在上一章中，我们使用 API Gateway、Lambda 和 DynamoDB 创建了一个完全功能的无服务器数据 API，并使用 IAM 角色进行了测试。然而，大部分的代码和配置都是手动部署的；这个过程容易出错，不可重复，也不可扩展。

在本章中，我们将向您展示如何仅使用代码和配置来部署所有这些基础设施。涵盖的主题如下：

+   无服务器堆栈构建和部署选项概述

+   创建配置文件、S3 存储桶、IAM 策略和 IAM 角色资源

+   使用 API Gateway、Lambda 和 DynamoDB 构建和部署

# 无服务器堆栈构建和部署选项概述

在本节中，我们将讨论手动配置基础设施、基础设施即代码、使用无服务器应用程序模型构建和部署，以及使用替代选项构建和部署时面临的挑战。

# 手动配置基础设施

配置基础设施的挑战在于它曾经是一个非常手动的过程。例如，管理员会按照手册中描述的步骤点击用户界面上的项目，运行一系列命令，或者登录服务器并编辑配置文件。随着云计算和开始扩展的 Web 框架的增长，这变得越来越具有挑战性。这可以通过单片架构和它们共享的 Web 服务器或应用服务器来完成。然而，使用微服务架构，使用不同语言开发的不同 Web 服务器和数据库，以及运行的数千个服务需要独立测试、构建和部署。

手动部署服务在成本方面需要付出很多努力，也很难在规模上维护这样的配置。服务的部署变得更加缓慢，也更难从任何错误中恢复，因为您可能需要管理员通过 SSH 远程连接到您的服务器，重新启动机器，或者尝试理解问题所在，并多次更改多台机器的配置。测试和使任何过程可重复也非常困难。无论是使用用户界面还是编辑一个服务器上的配置文件进行的任何配置更改，都不太可重复，也容易出现人为错误或配置错误。例如，在之前的章节中我们使用了 AWS 管理控制台。如果您在任何配置中出现错误，您将不得不返回诊断问题并进行修复，这将非常耗时。

在下一节中，我们将讨论基础设施即代码以及它如何帮助解决手动配置基础设施或部署服务时遇到的问题。

# 基础设施即代码

基础设施即代码基本上是通过定义文件或代码来管理和配置资源的过程。它提供了一种集中管理配置的方式，涉及实施和版本控制。突然之间，资源管理和配置变得更像是软件开发生命周期中的敏捷过程。所有更改都经过验证、测试，并作为发布过程的一部分进行配置，并使用标准的部署流程。这也提供了将用于在一个区域部署基础设施的配置复制到另一个区域的能力。

例如，假设您使用代码和配置在北弗吉尼亚地区部署基础设施，您可以轻松修改它以使其在爱尔兰地区运行。这使您能够快速扩展基础设施周围的配置，从而导致了术语 DevOps 的发展。这是开发人员在配置方面更加参与，特别是在基础设施周围，而运维团队（或运维团队）在开发过程中更加参与。以下图表显示了基础设施即代码的不同优势：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/9baf9c90-8f05-41e9-a1ed-ce1d4e83c094.png)

使用基础设施即代码有许多好处。第一个是成本降低，因为您在简单和重复的任务上花费的精力要少得多。在扩展或部署类似基础设施时，您还可以降低成本。

在构建任何系统时，我通常喜欢构建它以便它可以在两个环境中运行。一旦它在两个环境中运行，它就可以在许多环境中运行。例如，如果您使用命名约定作为每个环境的前缀或变量构建代码，例如**dev**代表**development**，**stg**代表**staging**，并在部署时进行替换，那么我们以后可以轻松地为**production**添加**prd**前缀。始终强烈建议使用标准命名约定。另一个例子可能是始终将三个字符作为约定或规则，这样您就不会陷入具有多个前缀的情况，例如 prod 或 production，这可能会引入意外错误。在配置文件中，将被替换的环境变量可能看起来像`${env}`。

另一个要点是执行速度；也就是说，您的管理员或 DevOps 团队实际上可以比以前更快地发布基础设施和服务。此外，通过在每个步骤进行跟踪、验证和测试，有助于减少错误和问题的数量。总的来说，这有助于降低风险并提高安全性。由于有了这种可追溯性，您可以了解部署了什么，以及它是否成功，或者它是否导致问题并应该回滚。

# 使用无服务器应用程序模型（SAM）构建和部署

最近出现的一个工具是由 AWS 维护的 SAM（[`github.com/awslabs/serverless-application-model`](https://github.com/awslabs/serverless-application-model)）。它允许您构建和部署无服务器堆栈。它提供了一种简化的方式来定义和部署任何无服务器资源或应用程序。在其基础上，它采用了云形成，但使用的源代码行数比使用 AWS 命令行要少。使用 SAM 模板文件的基本概念是它可以是包含所有无服务器配置的 JSON 或 YAML 文件，其吉祥物是松鼠 SAM。

# 使用备选选项构建和部署

部署 AWS 无服务器堆栈有替代选项。第一个选项是 AWS 命令行界面（CLI）。当您的组织不想为所有内容或部分无服务器堆栈使用云形成堆栈时，AWS CLI 是一个选择。AWS CLI 在功能发布方面通常领先于 SAM。因此，在本书中，我使用一些命令来补充 SAM 中尚未构建的部分。

Serverless Framework，最初称为 JAWS，是使用 Node.js 技术构建的。它在最初发布时领先于时代，但现在随着 AWS SAM 的出现，它是由第三方维护的 AWS 顶层附加层。然而，它确实允许您使用其他云提供商的其他功能，例如 Google 和 Azure，这是一个很棒的功能，但我个人质疑在不同云提供商之间重用函数代码的事件源、安全性和数据形状都是不同的。

Chalice 和 Zappa 是基于 Python 的 AWS 框架，类似于 Python Flask 和 Bottle 微型 Web 框架，但它们又是 AWS 的另一种抽象。您需要等待任何改进通过。

此外，还存在一种风险，即依赖这些框架当 AWS 功能被弃用时。您需要与它们保持同步，或者依赖于这些其他框架的开源贡献者来实际进行更改或直接贡献。如果我必须选择一个，我会选择 SAM，但我也接受一些人更喜欢无服务器。

SAM 需要一个 S3 存储桶来进行包部署，Lambda 需要 IAM 策略和 IAM 角色。接下来让我们来看看这些。

# 创建配置文件、S3 存储桶、IAM 策略和 IAM 角色资源

我们首先设置一个 S3 存储桶，用于保存 Lambda 部署包的源代码。IAM 策略和角色允许 API Gateway 调用 Lambda，并允许 Lambda 访问 DynamoDB。我们使用 AWS 管理控制台设置它们；在这里，我们将使用 AWS CLI 和 SAM。

本章中使用的代码、shell 脚本和配置文件都可以在`./serverless-microservice-data-api/`文件夹下找到。

# 创建 AWS 凭据配置文件

按照以下步骤创建 AWS 凭据配置文件：

1.  创建名为`demo`的 AWS 配置文件：

```py
$ aws configure --profile demo
```

1.  在`Chapter 1`中重新输入与`newuser`相关的相同的 AWS `aws_access_key_id`和`aws_secret_access_key`详细信息。

或者，您可以通过复制`[default]`来复制`[default]`配置文件，并创建一个`[demo]`的新条目，如下所示：

```py
 $ vi ~/.aws/credentials
      [default]
      aws_access_key_id =
      AAAAAAAAAAAAAAAAAAAA
      aws_secret_access_key =
      1111111111111111111111111111111111111111

      [demo]
      aws_access_key_id =
      AAAAAAAAAAAAAAAAAAAA
      aws_secret_access_key =
      1111111111111111111111111111111111111111
```

本书提供的代码需要一个配置文件名称（这里是`demo`）来使用正确的密钥；如果您使用其他配置文件名称，请在每个项目的 shell 脚本`common-variables.sh`中更改它。

# 创建一个 S3 存储桶

要部署 Lambda 源代码，您需要使用现有的 S3 存储桶或创建一个新的——使用以下代码来创建一个：

```py
$ aws s3api create-bucket --bucket <you-bucket-name> --profile demo --create-bucket-configuration LocationConstraint=<your-aws-region> --region <your-aws-region>
```

确保`<your-bucket-name>`是可寻址的，它必须遵循 DNS 命名约定。要选择您的 AWS 区域，请参考 AWS 区域和终端点（[`docs.aws.amazon.com/general/latest/gr/rande.html`](https://docs.aws.amazon.com/general/latest/gr/rande.html)）。通常，美国用户可以使用`us-east-1`，欧洲用户可以使用`eu-west-1`。

# 为您的 AWS 账户设置配置文件

我已经为`./bash/`下的每个无服务器项目创建了一个名为`common-variables.sh`的配置文件，该文件创建了 AWS CLI 和 SAM 使用的环境变量。您需要使用您的 AWS 账户详细信息对它们进行修改。这样做是为了为在多个地区支持多个 AWS 账户打下基础。以下是`common-variables.sh`的示例：

```py
#!/bin/sh
export profile="demo"
export region="<your-aws-region>"
export aws_account_id=$(aws sts get-caller-identity --query 'Account' --profile $profile | tr -d '\"')
# export aws_account_id="<your-aws-accountid>"
export template="lambda-dynamo-data-api"
export bucket="<you-bucket-name>"
export prefix="tmp/sam"

# Lambda settings
export zip_file="lambda-dynamo-data-api.zip"
export files="lambda_return_dynamo_records.py"

```

让我们试着理解这段代码：

+   使用您的 AWS 区域（例如`us-east-1`）更新`<your-aws-region>`。

+   我正在动态确定`aws_account_id`，但您也可以像注释中所示那样硬编码它，在这种情况下，请取消注释该行，并将`<your-aws-accountid>`更新为您的 AWS 账户 ID。如果您不知道它，您可以在 AWS 管理控制台|支持|支持中心屏幕中找到您的账户号码。

+   `template`是我们将使用的 SAM 模板的名称。

+   `bucket`和`prefix`定义了部署的 Lambda 包的位置。

# 更新策略和假定角色文件

您需要更改存储在`./IAM`文件夹下的 IAM 策略文档中的 AWS `aws_account_id`（当前设置为`000000000000`）。此外，当前设置为`eu-west-1`的区域也必须更改。

要替换您的`aws_account_id`（假设您的 AWS `aws_account_id`是`111111111111`），您可以手动执行，也可以运行以下命令：

```py
$ find ./ -type f -exec sed -i '' -e 's/000000000000/111111111111/' {} \;
```

# 创建 IAM 角色和策略

我们在 AWS 管理控制台中手动创建了 IAM 策略和角色。现在我们将看看如何使用 AWS CLI 创建这些。

以下是我们在`./IAM/`目录下创建的 JSON 策略`dynamo-readonly-user-visits.json`：

```py
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchGetItem",
                "dynamodb:DescribeTable",
                "dynamodb:GetItem",
                "dynamodb:Query",
                "dynamodb:Scan"
            ],
            "Resource": [
                "arn:aws:dynamodb:eu-west-1:000000000000:
                 table/user-visits",
                "arn:aws:dynamodb:eu-west-1:000000000000:
                 table/user-visits-sam"         
            ]
        }
    ]
}
```

总结一下策略，它表示我们对两个名为`user-visits`的 DynamoDB 表具有`Query`和`Scan`访问权限，这些表可以手动创建或在 Python 中创建，以及我们将在本章中使用 SAM 创建的`user-visits-sam`。

创建一个允许 Lambda 函数将日志写入 CloudWatch 日志的策略。创建一个名为`lambda-cloud-write.json`的文件，内容如下：

```py
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
    ],
      "Resource": [
        "arn:aws:logs:*:*:*"
    ]
  },
  {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:PutMetricData"
      ],
      "Resource": "*"
    }
 ]
}
```

创建 IAM 角色时，还需要指定它可以承担的 IAM 角色类型。我们创建了一个名为`assume-role-lambda.json`的文件，这被称为受信任的实体：

```py
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

将上述内容定义为 JSON 代码使我们能够在 AWS 中对安全性和权限进行版本控制。此外，如果有人错误地删除了它们，我们可以在 AWS 中简单地重新创建它们。

我们现在将创建一个名为`create-role.sh`的 shell 脚本，在`./bash`文件夹下，以创建一个 Lambda IAM 角色和三个 IAM 策略，并将它们附加到 IAM 角色：

```py
#!/bin/sh
#This Script creates a Lambda role and attaches the policies

#import environment variables
. ./common-variables.sh

#Setup Lambda Role
role_name=lambda-dynamo-data-api
aws iam create-role --role-name ${role_name} \
    --assume-role-policy-document file://../../IAM/assume-role-lambda.json \
    --profile $profile || true

sleep 1
#Add and attach DynamoDB Policy
dynamo_policy=dynamo-readonly-user-visits
aws iam create-policy --policy-name $dynamo_policy \
    --policy-document file://../../IAM/$dynamo_policy.json \
    --profile $profile || true

role_policy_arn="arn:aws:iam::$aws_account_id:policy/$dynamo_policy"
aws iam attach-role-policy \
    --role-name "${role_name}" \
    --policy-arn "${role_policy_arn}"  --profile ${profile} || true

#Add and attach cloudwatch_policy
cloudwatch_policy=lambda-cloud-write
aws iam create-policy --policy-name $cloudwatch_policy \
    --policy-document file://../../IAM/$cloudwatch_policy.json \
    --profile $profile || true

role_policy_arn="arn:aws:iam::$aws_account_id:policy/$cloudwatch_policy"
aws iam attach-role-policy \
    --role-name "${role_name}" \
    --policy-arn "${role_policy_arn}"  --profile ${profile} || true
```

使用`./create-role.sh`执行脚本。它将创建一个 IAM 角色和三个 IAM 策略，并将它们附加到 IAM 角色。请注意，此处的代码是有意幂等的，因为策略更改需要谨慎管理，因为它们可能会影响其他人。

请注意，还可以在 SAM 模板中创建 IAM 角色，但是使用 AWS CLI 意味着在删除无服务器堆栈时可以重用角色和策略，而不是删除它们。如果将它们检入 Git 标准命名约定，则可以添加版本控制，并通过集中创建来帮助支持团队。

# 检查 IAM 角色和策略

AWS CLI 会在创建 IAM 角色和策略时给您反馈，但您也可以在 AWS 管理控制台中检查：

1.  登录 AWS 管理控制台，并在[`console.aws.amazon.com/iam/`](https://console.aws.amazon.com/iam/)上打开 IAM 控制台。

1.  在 IAM 导航窗格中，选择角色。

1.  从角色列表中选择`lambda-dynamo-data-api`。

1.  在权限选项卡下选择显示更多权限策略。

您应该看到以下三个附加的策略：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/67b3fe80-4e4b-475e-aece-57205716093b.png)

# 使用 API Gateway，Lambda 和 DynamoDB 构建和部署

部署无服务器堆栈涉及三个步骤：

1.  将 Lambda 构建为 ZIP 包

1.  使用 SAM 和 CloudFormation 打包您的无服务器堆栈

1.  使用 SAM 和 CloudFormation 部署您的无服务器堆栈

# 将 Lambda 构建为 ZIP 包

如果尚未安装 ZIP，请安装 ZIP。对于 Ubuntu/Debian，您可以使用`sudo apt-get install zip -y`。创建一个名为`create-lambda-package.sh`的文件，内容如下：

```py
#!/bin/sh
#setup environment variables
. ./common-variables.sh

#Create Lambda package and exclude the tests to reduce package size
(cd ../../lambda_dynamo_read;
mkdir -p ../package/
zip -FSr ../package/"${zip_file}" ${files} -x *tests/*)
```

这将仅在源代码发生更改时创建 Lambda 代码的 ZIP 文件。这是将部署到 AWS 的内容，并且在需要打包第三方库时，将这些命令分开具有优势。

# SAM YAML 模板

我们将使用 SAM 模板创建无服务器堆栈。SAM 使用 YAML 或 JSON，并允许您定义 Lambda 函数和 API Gateway 设置，以及创建 DynamoDB 表。模板如下所示：

```py
AWSTemplateFormatVersion: '2010-09-09'
Transform: 'AWS::Serverless-2016-10-31'
Description: >-
  This Lambda is invoked by API Gateway and queries DynamoDB.
Parameters:
    AccountId:
        Type: String
Resources:
  lambdadynamodataapi:
    Type: AWS::Serverless::Function
    Properties:
      Handler: lambda_return_dynamo_records.lambda_handler
      Runtime: python3.6
      CodeUri: ../../package/lambda-dynamo-data-api.zip
      FunctionName: lambda-dynamo-data-api-sam
      Description: >-
        This Lambda is invoked by API Gateway and queries DynamoDB.
      MemorySize: 128
      Timeout: 3  
      Role: !Sub 'arn:aws:iam::${AccountId}:
                  role/lambda-dynamo-data-api'
      Environment:
        Variables:
          environment: dev
      Events:
        CatchAll:
          Type: Api
          Properties:
            Path: /visits/{resourceId}
            Method: GET
  DynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: user-visits-sam
      SSESpecification:
        SSEEnabled: True
      AttributeDefinitions:
        - AttributeName: EventId
          AttributeType: S
        - AttributeName: EventDay
          AttributeType: N
      KeySchema:
        - AttributeName: EventId
          KeyType: HASH
        - AttributeName: EventDay
          KeyType: RANGE
      ProvisionedThroughput:
        ReadCapacityUnits: 1
        WriteCapacityUnits: 1
```

从上到下，我们首先指定模板类型，描述，并传递一个字符串参数`AccountId`。然后，我们指定 Lambda 的细节，例如`Handler`，这是入口点，ZIP 代码的位置，并为函数指定名称和描述。然后，我们选择 128 MB 的 RAM，因为这是一个概念验证，我们不需要更多的内存；我们为超时指定`3`。之后，即使 Lambda 仍在运行，它也会终止；这限制了成本，并且是合理的，因为我们期望同步响应。然后，我们有 IAM Lambda 执行角色，其中包含`${AccountId}`参数，该参数在部署无服务器堆栈时传递。

我们看到如何添加将在 Lambda 函数中可用的环境变量。变量是`environment: dev`。

然后我们有 Lambda 函数的触发器或事件源。在这里，我们创建了一个 API Gateway，其中包含`/visits/{resourceId}`路径的资源，使用`GET`方法调用一个带有`resourceId`的 Lambda 函数，该`resourceId`将是`EventId`。

最后，我们使用 Python 创建了一个 DynamoDB 表，其中`EventId`的哈希数据类型为`string`，`EventDay`的范围数据类型为`number`。为了降低成本（或免费），我将读取和写入容量设置为`1`。

因此，在一个 SAM YAML 文件中，我们已经配置了 Lambda，具有其 Lambda 集成的 API Gateway，并创建了一个新的 DynamoDB 表。

对于 DynamoDB，我强烈建议在 SAM 创建的资源末尾附加`sam`，以便知道其来源。我还建议，如果 DynamoDB 表在服务之间共享，最好使用 Boto3 或 AWS CLI 进行创建。这是因为删除一个无服务器堆栈可能意味着该表对所有服务都被删除。

# 打包和部署您的无服务器堆栈

一旦具有策略的 IAM 角色，具有 Lambda 代码的 ZIP 包和 SAM 模板都创建好了，您只需要运行两个 CloudFormation 命令来打包和部署您的无服务器堆栈。

第一个命令将 Lambda 代码与 SAM 模板打包并推送到 S3：

```py
$ aws cloudformation package --template-file $template.yaml \
    --output-template-file ../../package/$template-output.yaml \
    --s3-bucket $bucket --s3-prefix backend \
    --region $region --profile $profile

Successfully packaged artifacts and wrote output template to file ../../package/lambda-dynamo-data-api-output.yaml.
Execute the following command to deploy the packaged template
aws cloudformation deploy --template-file /mnt/c/serverless-microservice-data-api/package/lambda-dynamo-data-api-output.yaml --stack-name <YOUR STACK NAME>
```

第二个命令将其部署到 AWS：

```py
$ aws cloudformation deploy --template-file ../../package/$template-output.yaml \
    --stack-name $template --capabilities CAPABILITY_IAM \
    --parameter-overrides AccountId=${aws_account_id} \
    --region $region --profile $profile

Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - lambda-dynamo-data-api
```

SAM 中的一个很棒的功能是能够使用参数。在这里，当我们使用`--parameter-overrides AccountId=${aws_account_id}`部署堆栈时就可以实现。好处是我们可以在多个环境中重用相同的 SAM 模板，例如 AWS 帐户和区域，以及任何其他参数。

您可以通过检查 AWS 管理控制台来验证堆栈是否已正确部署到 AWS：

1.  登录到 AWS 管理控制台[`console.aws.amazon.com/cloudformation/`](https://console.aws.amazon.com/cloudformation/)。

1.  选择管理和治理| CloudFormation 或在“查找服务”下搜索 CloudFormation。

1.  在 CloudFormation 窗格中，选择 lambda-dynamo-data-api。

1.  选择事件。这显示了不同的事件，并且在部署堆栈时非常有用。通常，这将是命名冲突（例如，具有相同名称的 DynamoDB 表存在）或 IAM 相关问题（例如，角色不存在）。

1.  选择资源。这显示了由此 CloudFormation 堆栈管理的资源：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/31906f76-725d-4686-b076-afb5dab963e7.png)

您还可以直接检查 AWS 管理控制台，以确保 API Gateway，Lambda 函数和 DynamoDB 表已正确创建。

例如，这是我们使用 Python 创建的相同 Lambda，但由 SAM 部署和管理。除非您正在进行概念验证，建议进一步的更改通过配置更改而不是 AWS 管理控制台中的更改进行管理，因为这将破坏基础架构作为代码和自动化：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/7d50d164-b37e-440d-8c4f-89cd41154572.png)

# 将所有内容放在一起

在本章中，我们部署了一个完全可工作的无服务器堆栈，无需使用用户界面配置任何设置。这是部署基础设施和代码的推荐方式，因为它更具可重复性，可扩展性，并且不太容易出错。它还允许您在一切都在 Git 中进行版本控制时执行诸如还原配置之类的操作。

`./serverless-microservice-data-api/bash`文件夹下提供的 shell 脚本：

+   `common-variables.sh`：其他脚本使用的环境变量

+   `create-role.sh`：Lambda IAM 角色创建并附加了三个策略

+   `lambda-dynamo-data-api.yaml`：定义 SAM YAML 模板

+   `create-lambda-package.sh`：创建 Lambda ZIP 包

+   `build-package-deploy-lambda-dynamo-data-api.sh`：编排 Lambda ZIP 的构建，打包和部署

以下是`build-package-deploy-lambda-dynamo-data-api.sh`的内容，当您修改 Lambda 代码或其他 SAM 配置设置时，可以运行它：

```py
#!/usr/bin/env bash

# Variables
. ./common-variables.sh

#Create Zip file of your Lambda code (works on Windows and Linux)
./create-lambda-package.sh

#Package your Serverless Stack using SAM + Cloudformation
aws cloudformation package --template-file $template.yaml \
    --output-template-file ../../package/$template-output.yaml \
    --s3-bucket $bucket --s3-prefix backend \
    --region $region --profile $profile

#Deploy your Serverless Stack using SAM + Cloudformation
aws cloudformation deploy --template-file ../../package/$template-output.yaml \
    --stack-name $template --capabilities CAPABILITY_IAM \
    --parameter-overrides AccountId=${aws_account_id} \
    --region $region --profile $profile
```

# 手动测试无服务器微服务

测试步骤如下：

1.  登录到 AWS 管理控制台，在[`console.aws.amazon.com/apigateway/`](https://console.aws.amazon.com/apigateway/)打开 API Gateway 控制台。

1.  在 Amazon API Gateway 导航窗格中，选择 API | lambda-dynamo-data-api | Stages。

1.  在`Prod/visits/{resourceId}/GET`下选择 GET 以获取调用 URL，应该看起来像`https://{restapi_id}.execute-api.{region}.amazonaws.com/Prod/visits/{resourceId}`。

1.  打开一个新的浏览器选项卡，输入`https://{restapi_id}.execute-api.{region}.amazonaws.com/Prod/visits/{resourceId}` URL。您将获得`{"message":"resource_id not a number"}`响应正文。这是因为我们在查询 DynamoDB 之前通过`parse_parameters()` URL 函数验证了`resource_id`，以确保它是一个数字。

1.  打开一个新的浏览器选项卡，输入`https://{restapi_id}.execute-api.{region}.amazonaws.com/Prod/visits/324` URL。由于我们使用了正确的`resourceId`，您应该在浏览器选项卡中看到[ ]。

为什么我们没有得到数据？

好吧，没有数据加载到`user-visits-sam` DynamoDB 表中，这就是为什么！

运行`python3 ./aws_dynamo/dynamo_modify_items.py`将一些记录加载到`user-visits-sam` DynamoDB 表中。

以下是`dynamo_modify_items.py`的内容：

```py
from boto3 import resource

class DynamoRepository:
    def __init__(self, target_dynamo_table, region='eu-west-1'):
        self.dynamodb = resource(service_name='dynamodb', region_name=region)
        self.target_dynamo_table = target_dynamo_table
        self.table = self.dynamodb.Table(self.target_dynamo_table)

    def update_dynamo_event_counter(self, event_name, 
            event_datetime, event_count=1):
        return self.table.update_item(
            Key={
                'EventId': event_name,
                'EventDay': event_datetime
            },
            ExpressionAttributeValues={":eventCount": event_count},
            UpdateExpression="ADD EventCount :eventCount")

def main():
    table_name = 'user-visits-sam'
    dynamo_repo = DynamoRepository(table_name)
    print(dynamo_repo.update_dynamo_event_counter('324', 20171001))
    print(dynamo_repo.update_dynamo_event_counter('324', 20171001, 2))
    print(dynamo_repo.update_dynamo_event_counter('324', 20171002, 5))

if __name__ == '__main__':
    main()
```

现在在浏览器中转到相同的端点，您应该会收到以下数据：

```py
[{"EventCount": 3, "EventDay": 20171001, "EventId": "324"}, {"EventCount": 5, "EventDay": 20171002, "EventId": "324"}]
```

打开一个新的浏览器选项卡，输入`https://{restapi_id}.execute-api.{region}.amazonaws.com/Prod/visits/324?startDate=20171002` URL。由于我们添加了`startDate=20171002`参数，您应该在浏览器选项卡中看到以下内容：

```py
[{"EventCount": 5, "EventDay": 20171002, "EventId": "324"}]
```

# 进行代码和配置更改

代码很少保持静态，因为会出现新的需求和业务请求。为了说明对更改的良好支持，假设我们对 Lambda 函数 Python 代码进行了一些更改，现在想要使用 Python 3.7，而不是 Python 3.6。

我们可以通过三个步骤更新代码，配置和堆栈：

1.  更改`lambda_return_dynamo_records.py`的 Python 代码，使其符合 Python 3.7。

1.  更改`lambda-dynamo-data-api.yaml`的 SAM 模板如下：

```py
      Resources:
        lambdadynamodataapi:
          Type: AWS::Serverless::Function
          Properties:
            Handler: lambda_return_dynamo_records.lambda_handler
            Runtime: python3.7
```

1.  运行`./build-package-deploy-lambda-dynamo-data-api.sh`。这将重新构建 Lambda ZIP 包，因为代码已更改。打包和部署代码和 SAM 配置，然后 CloudFormation 将管理和部署更改。

# 删除无服务器堆栈

当您不再需要您的无服务器堆栈时，您可以在 AWS 管理控制台的 CloudFormation 下删除它：

1.  登录到 AWS 管理控制台，在[`console.aws.amazon.com/cloudformation/`](https://console.aws.amazon.com/cloudformation/)打开 CloudFormation 控制台。

1.  从列表中选择 lambda-dynamo-data-api。

1.  选择操作，然后选择删除堆栈。

1.  在提示时选择是，删除。

或者，您可以使用`./delete-stack.sh`运行以下 shell 脚本：

```py
#!/usr/bin/env bash
. ./common-variables.sh
aws cloudformation delete-stack --stack-name $template --region $region --profile $profile
```

# 摘要

现在您对手动部署无服务器堆栈以可重复和一致的方式有了更深入的理解和一些实际经验，使用基础设施即代码原则。您可以根据组织的无服务器微服务需求进行调整。您了解了服务部署选项，并使用 AWS CLI 创建了存储桶、IAM 角色和 IAM 策略，以及使用 AWS SAM 部署了 API Gateway、Lambda 和 DynamoDB。您还看到了如何轻松修改 SAM 模板文件以在整个堆栈中传播更改。本书提供了完整的 Python 源代码、IAM 策略、角色、Linux 和 shell 脚本，因此您可以根据自己的需求进行调整。现在，您可以利用它们，而无需手动使用 AWS 管理控制台 GUI，并且只需要在部署其他无服务器微服务时修改脚本。

现在我们已经向您展示了如何部署堆栈，非常重要的是您知道代码是否按预期运行和执行，特别是随着代码库的增长，并且将在生产环境中使用。我们还没有涵盖自动部署和测试的机制。因此，在下一章中，我们将讨论并介绍您在无服务器微服务上应该使用的不同类型的测试。


# 第四章：测试您的无服务器微服务

在上一章中，我们使用 API Gateway、Lambda 和 DynamoDB 创建了一个完全功能的无服务器数据 API，并将其部署到了 AWS CLI。我们展示的测试是在 AWS 管理控制台和浏览器中进行的，这对于少量简单代码开发作为概念验证是可以的，但不建议用于开发或生产系统。

对于开发人员来说，首先在本地开发和测试要高效得多，对于持续交付来说，自动化测试至关重要。本章就是关于测试的。

测试可能很容易覆盖整本书，但我们将保持非常实用的方式，并专注于测试您的无服务器代码和我们在第三章中部署的数据 API，*部署您的无服务器堆栈*。这将包括单元测试、模拟、本地调试、集成测试，在 Docker 容器中本地运行 Lambda 或无服务器 API 的 HTTP 服务器，以及负载测试。

在本章中，我们将涵盖以下主题：

+   对 Python Lambda 代码进行单元测试

+   在本地运行和调试您的 AWS Lambda 代码

+   使用真实测试数据进行集成测试

+   AWS **无服务器应用程序模型**（**SAM**）CLI

+   规模化加载和端到端测试

+   减少 API 延迟的策略

+   清理

# 对 Python Lambda 代码进行单元测试

在本节中，我们将讨论为什么测试很重要，以及我们可以用于测试、单元测试和模拟的示例数据。

# 为什么测试很重要？

想想在不同国家的大型分布式开发团队中进行的协作和团队合作，想象一下他们想要在同一个源代码仓库上进行协作，并在不同的时间检查代码更改。对于这些团队来说，理解代码并能够在本地测试以查看其工作原理非常重要，他们的更改是否会影响现有服务，以及代码是否仍然按预期工作。

测试对于确保交付或用户体验中有**质量**很重要。通过进行大量测试，您可以及早发现缺陷并加以修复。例如，如果检测到了重大错误，您可以决定不发布最近的更新，并在发布之前修复问题。

另一个重要的点是**可用性**。例如，您的客户可能有性能或非功能性要求。例如，想象一个电子商务网站，您可以在其中添加商品，但必须等待整整一分钟才能将其添加到购物篮中。在大多数情况下，这是不可接受的，用户会失去对平台的信任。理想情况下，您将有一个测试流程，以确保延迟仍然很低，网站响应迅速。需要测试的其他示例包括不按预期工作的功能或用户界面缺陷，这些缺陷会阻止用户完成他们想要做的任务。

拥有**更短的发布周期**很重要。使用自动化，您可以自动且一致地运行一千次测试，而不需要人工手动测试站点的不同部分，手动测试 API，或在任何发布之前严格检查代码。在每次发布到生产环境之前，您都会运行这一千次测试，这样您就会更有信心，一切都按预期工作，如果您在生产中发现了这一千次测试忽略的问题，您可以修复它并为该场景添加一个新的测试。

# 测试类型

测试可以手动完成，就像我们在 AWS 管理控制台中所做的那样，这容易出错且不可扩展。通常，测试是使用预先编写的测试套件自动化的，并且对于持续集成和持续交付至关重要。

有许多可用的软件测试定义和类型；涵盖它们可能需要整本书。在这里，我们将专注于对我们的无服务器堆栈相关的三种主要类型：

+   **单元测试**：对单个软件模块进行低级别测试，通常由开发人员完成，并在**测试驱动开发**（**TDD**）中使用。这些类型的测试通常执行速度很快。

+   **集成测试**：验证集成后所有组合服务是否正常工作。这些通常更昂贵，因为需要运行许多服务。

+   **负载测试**：这是一种非功能性测试，用于检查系统在重负载下的性能。有时也被称为性能或压力测试，因为它有助于了解平台的可用性和可靠性。

# 单元测试 Lambda Python 代码

在 AWS 管理控制台中进行调试并不容易；在本地调试代码并稍后自动化该过程要更有建设性。

我们从之前的章节中知道，Lambda 事件源是 API Gateway 的`GET`请求。由于我们只关注数据的一个子集，因此完整的 JSON 有效负载也可以用几行 Python 代码模拟出来。

# 样本测试数据

在这里，我们有一个带有`setUp()`方法的测试用例，该方法在测试套件开始时运行一次，以及一个`tearDown()`方法，在测试结束时运行。

以下是在`serverless-microservice-data-api/test/test_dynamo_get.py`顶部的测试设置和拆卸的内容的子集：

```py
import unittest
import json

class TestIndexGetMethod(unittest.TestCase):
    def setUp(self):
        self.validJsonDataNoStartDate = json.loads('{"httpMethod": 
        "GET","path": "/path/to/resource/324","headers": ' \ 'null} ')
        self.validJsonDataStartDate = 
        json.loads('{"queryStringParameters": {"startDate":      
        "20171013"},' \ '"httpMethod": "GET","path": "/path/to/resource
        /324","headers": ' \ 'null} ')
        self.invalidJsonUserIdData =   
        json.loads('{"queryStringParameters": {"startDate": 
        "20171013"},' \ '"httpMethod": "GET","path": "/path/to/resource
        /324f","headers": ' \ 'null} ')
        self.invalidJsonData = "{ invalid JSON request!} "
    def tearDown(self):
        pass
```

我创建了四个不同的 JSON Python 字典：

+   `self.validJsonDataNoStartDate`: 没有`StartDate`过滤器的有效`GET`请求

+   `self.validJsonDataStartDate`: 具有`StartDate`过滤器的有效`GET`请求

+   `self.invalidJsonUserIdData`: 一个无效的`UserId`，不是一个数字

+   `self.invalidJsonData`: 无法解析的无效 JSON

# 单元测试

以下是可以在`serverless-microservice-data-api/test/test_dynamo_get.py`中找到的单元测试：

```py
    def test_validparameters_parseparameters_pass(self):
        parameters = lambda_query_dynamo.HttpUtils.parse_parameters(
                     self.validJsonDataStartDate)
        assert parameters['parsedParams']['startDate'] == u'20171013'
        assert parameters['parsedParams']['resource_id'] == u'324'     

    def test_emptybody_parsebody_nonebody(self):
        body = lambda_query_dynamo.HttpUtils.parse_body(
               self.validJsonDataStartDate)         
        assert body['body'] is None

    def test_invalidjson_getrecord_notfound404(self):
        result = lambda_query_dynamo.Controller.get_dynamodb_records(
                 self.invalidJsonData)
        assert result['statusCode'] == '404'

    def test_invaliduserid_getrecord_invalididerror(self):            
        result = lambda_query_dynamo.Controller.get_dynamodb_records(
                 self.invalidJsonUserIdData)
        assert result['statusCode'] == '404'
        assert json.loads(result['body'])['message'] == 
             "resource_id not a number" 
```

我使用了`test`的前缀，这样 Python 测试套件可以自动检测它们作为单元测试，并且我使用了三元单元测试命名约定来命名测试方法：方法名、测试状态和预期行为。测试方法如下：

+   `test_validparameters_parseparameters_pass()`: 检查参数是否被正确解析。

+   `test_emptybody_parsebody_nonebody()`: 在`GET`方法中我们没有使用 body，所以我们希望确保如果没有提供 body，它仍然可以正常工作。

+   `test_invalidjson_getrecord_notfound404()`: 检查 Lambda 对无效的 JSON 有效负载的反应。

+   `test_invaliduserid_getrecord_invalididerror()`: 检查 Lambda 对无效的非数字`userId`的反应。

前面的内容并不查询 DynamoDB 记录。如果我们想要这样做，我们应该让 DynamoDB 运行起来，使用新的 DynamoDB 本地（[`docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html`](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html)），或者我们可以模拟 DynamoDB 调用，这是我们接下来要看的。

# 模拟

有一个名为 Moto 的 Python AWS 模拟框架（[`docs.getmoto.org/en/latest/`](http://docs.getmoto.org/en/latest/)），但我更喜欢使用一个名为`mock`的通用框架，它在 Python 社区得到了更广泛的支持，并且从 Python 3.3 开始已经包含在 Python 标准库中。

以下模拟代码可以在`serverless-microservice-data-api/test/test_dynamo_get.py`底部找到：

```py
from unittest import mock

     mock.patch.object(lambda_query_dynamo.DynamoRepository,
                      "query_by_partition_key",
                       return_value=['item'])
     def test_validid_checkstatus_status200(self, 
         mock_query_by_partition_key):
        result = lambda_query_dynamo.Controller.get_dynamodb_records(
                 self.validJsonDataNoStartDate)
        assert result['statusCode'] == '200'

    @mock.patch.object(lambda_query_dynamo.DynamoRepository,
                       "query_by_partition_key",
                        return_value=['item'])
     def test_validid_getrecord_validparamcall(self, 
         mock_query_by_partition_key):         
lambda_query_dynamo.Controller.get_dynamodb_records(
self.validJsonDataNoStartDate)         mock_query_by_partition_key.assert_called_with(
     partition_key='EventId',                                                                      
     partition_value=u'324')

    @mock.patch.object(lambda_query_dynamo.DynamoRepository,
                       "query_by_partition_and_sort_key",
                        return_value=['item'])
    def test_validid_getrecorddate_validparamcall(self, 
        mock_query_by_partition_and_sort_key):
           lambda_query_dynamo.Controller.get_dynamodb_records(
               self.validJsonDataStartDate)
          mock_query_by_partition_and_sort_key.assert_called_with(partition_key='   
    EventId',                                                                      
    partition_value=u'324',                                                                 
    sort_key='EventDay',                                                                 
    sort_value=20171013)
```

从这段代码中得出的关键观察结果如下：

+   `@mock.patch.object()`是一个装饰器，用于对我们从`DynamoRepository()`类中模拟的`query_by_partition_key()`或`query_by_partition_and_sort_key()`方法。

+   `test_validid_checkstatus_status200()`: 我们模拟对`query_by_partition_key()`的调用。如果查询有效，我们会得到一个`'200'`状态码。

+   `test_validid_getrecords_validparamcall()`: 我们模拟对`query_by_partition_key()`的调用，并检查该方法是否使用了正确的参数进行调用。请注意，我们不需要检查较低级别的`boto3` `self.db_table.query()`方法是否有效。

+   `test_validid_getrecordsdate_validparamcall()`: 我们模拟对`query_by_partition_and_sort_key()`的调用，并检查该方法是否使用正确的参数进行了调用。

您不是在这里测试现有的第三方库或 Boto3，而是测试您的代码和与它们的集成。模拟允许您用模拟对象替换测试中的代码部分，并对方法或属性进行断言。

# 运行单元测试

现在我们有了所有的测试套件，而不是在 IDE（如 PyCharm）中运行它们，您可以使用以下 bash 命令从根文件夹运行测试：

```py
$ python3 -m unittest discover test 
```

`unittest`会自动检测所有测试文件必须是项目顶层目录可导入的模块或包。在这里，我们只想从以`test_`为前缀的测试文件夹中运行测试。

我在`serverless-microservice-data-api/bash/apigateway-lambda-dynamodb/unit-test-lambda.sh`下创建了一个 shell 脚本：

```py
#!/bin/sh (cd ../..; python3 -m unittest discover test) 
```

# 代码覆盖率

我们不会深入讨论，但代码覆盖率是软件工程中使用的另一个重要度量标准。代码覆盖率衡量了测试套件覆盖的代码程度。主要思想是，覆盖率百分比越高，测试覆盖的代码就越多，因此创建未检测到的错误的可能性就越小，服务应该按预期运行。这些报告可以帮助开发人员提出额外的测试或场景，以增加覆盖率百分比。

与测试覆盖率相关的 Python 包包括`coverage`、`nose`和较新的`nose2`，它们可以提供覆盖率报告。例如，您可以运行以下命令，使用`nose`或`nose2`获取 Lambda 代码的测试覆盖分析报告：

```py
$ nosetests test/test_dynamo_get.py --with-coverage --cover-package lambda_dynamo_read -v
$ nose2 --with-coverage 
```

当我们开始编写自己的测试时，我们可以选择使用一组额外的工具来进行测试。这些工具被称为代码覆盖工具。Codecov 和 Coveralls 就是这样的工具的例子。当我们想要分析通过 GitHub 等托管服务编写的代码时，这些工具非常有用，因为它们提供了完整的分析，以确定哪些行已经进行了测试。

# 在本地运行和调试 AWS Lambda 代码

有时，您希望使用本地 Lambda 模拟 API Gateway 负载，针对 AWS 中托管的真实远程 DynamoDB 进行调试。这样可以使用真实数据进行调试和构建单元测试。此外，我们将看到这些稍后可以用于集成测试。

# 批量加载数据到 DynamoDB

我们将首先讨论如何从名为`sample_data/dynamodb-sample-data.txt`的**逗号分隔值**（**CSV**）文件中批量加载数据到 DynamoDB。与为每个项目插入单个语句不同，这是一个更高效的过程，因为数据文件与 Python 代码是解耦的。

```py
EventId,EventDay,EventCount
324,20171010,2
324,20171012,10
324,20171013,10
324,20171014,6
324,20171016,6
324,20171017,2
300,20171011,1
300,20171013,3
300,20171014,30 
```

添加另一个名为`update_dynamo_event_counter()`的方法，该方法使用`DynamoRepository`类更新 DynamoDB 记录。

以下是`serverless-microservice-data-api/aws_dynamo/dynamo_insert_items_from_file.py` Python 脚本的内容：

```py
from boto3 import resource

class DynamoRepository:
    def __init__(self, target_dynamo_table, region='eu-west-1'):
        self.dynamodb = resource(service_name='dynamodb', region_name=region)
        self.target_dynamo_table = target_dynamo_table
        self.table = self.dynamodb.Table(self.target_dynamo_table)     

    def update_dynamo_event_counter(self, event_name, 
        event_datetime, event_count=1):
        response = self.table.update_item(
            Key={
                'EventId': str(event_name),
                'EventDay': int(event_datetime)
            },
            ExpressionAttributeValues={":eventCount": 
                int(event_count)},
            UpdateExpression="ADD EventCount :eventCount")
        return response 
```

在这里，我们有一个`DynamoRepository`类，在`__init__()`中实例化了与 DynamoDB 的连接，并且有一个`update_dynamo_event_counter()`方法，如果记录存在则更新 DynamoDB 记录，如果不存在则使用传入的参数添加新记录。这是一个原子操作。

以下是`serverless-microservice-data-api/aws_dynamo/dynamo_insert_items_from_file.py` Python 脚本的后半部分：

```py
 import csv
table_name = 'user-visits-sam'
input_data_path = '../sample_data/dynamodb-sample-data.txt'
dynamo_repo = DynamoRepository(table_name)
with open(input_data_path, 'r') as sample_file:
    csv_reader = csv.DictReader(sample_file)
    for row in csv_reader:
        response = dynamo_repo.update_dynamo_event_counter(row['EventId'],                                                            row['EventDay'],                                                            row['EventCount'])
        print(response) 
```

这段 Python 代码打开 CSV 文件，提取标题行，并解析每一行，同时将其写入名为`user-visits-sam`的 DynamoDB 表中。

现在我们已经将一些数据行加载到 DynamoDB 表中，我们将通过调试本地 Lambda 函数来查询表。

# 在本地运行 Lambda

这是一个完整的 API 网关请求示例，`serverless-microservice-data-api/sample_data/request-api-gateway-valid-date.json`，代理 Lambda 函数将作为事件接收。这些可以通过打印 Lambda 作为事件源传递给 CloudWatch 日志的真实 API 网关 JSON 事件来生成：

```py
{
  "body": "{\"test\":\"body\"}",
  "resource": "/{proxy+}",
  "requestContext": {
    "resourceId": "123456",
    "apiId": "1234567890",
    "resourcePath": "/{proxy+}",
    "httpMethod": "GET",
    "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef",
    "accountId": "123456789012",
    "identity": {
      "apiKey": null,
      "userArn": null,
      "cognitoAuthenticationType": null,
      "caller": null,
      "userAgent": "Custom User Agent String",
      "user": null,
      "cognitoIdentityPoolId": null,
      "cognitoIdentityId": null,
      "cognitoAuthenticationProvider": null,
      "sourceIp": "127.0.0.1",
      "accountId": null
    },
    "stage": "prod"
  },
  "queryStringParameters": {
    "foo": "bar"
  },
  "headers": {
    "Via": "1.1 08f323deadbeefa7af34d5feb414ce27.cloudfront.net 
            (CloudFront)",
    "Accept-Language": "en-US,en;q=0.8",
    "CloudFront-Is-Desktop-Viewer": "true",
    "CloudFront-Is-SmartTV-Viewer": "false",
    "CloudFront-Is-Mobile-Viewer": "false", 
    "X-Forwarded-For": "127.0.0.1, 127.0.0.2",
    "CloudFront-Viewer-Country": "US",
    "Accept": "text/html,application/xhtml+xml,application/xml;
               q=0.9,image/webp,*/*;q=0.8",
    "Upgrade-Insecure-Requests": "1",
    "X-Forwarded-Port": "443",
    "Host": "1234567890.execute-api.us-east-1.amazonaws.com",
    "X-Forwarded-Proto": "https",
    "X-Amz-Cf-Id": "cDehVQoZnx43VYQb9j2-nvCh-
                    9z396Uhbp027Y2JvkCPNLmGJHqlaA==",
    "CloudFront-Is-Tablet-Viewer": "false",
    "Cache-Control": "max-age=0",
    "User-Agent": "Custom User Agent String",     
    "CloudFront-Forwarded-Proto": "https",
    "Accept-Encoding": "gzip, deflate, sdch"
  },
  "pathParameters":{
    "proxy": "path/to/resource"
  },
  "httpMethod": "GET",
  "stageVariables": {
    "baz": "qux"
  },
  "path": "/path/to/resource/324"
} 
```

与依赖于另一个第三方框架进行本地调试（例如 SAM CLI）不同，您可以通过使用 JSON `Dict`事件直接调用 Lambda 函数来直接调试 Lambda 函数。这意味着您无需任何额外的库来运行，而且它是本机 Python。

`serverless-microservice-data-api/test/run_local_api_gateway_lambda_dynamo.py`的内容是使用 AWS 中的服务（例如 DynamoDB）本地调试 Lambda 函数的示例。

```py
import json

from lambda_dynamo_read import lambda_return_dynamo_records as lambda_query_dynamo

with open('../sample_data/request-api-gateway-valid-date.json', 'r') as sample_file:
     event = json.loads(sample_file.read())
print("lambda_query_dynamo\nUsing data: %s" % event)
print(sample_file.name.split('/')[-1]) response = lambda_query_dynamo.lambda_handler(event, None)
print('Response: %s\n' % json.dumps(response)) 
```

我们打开样本`GET`文件，将 JSON 解析为`Dict`，然后将其作为参数传递给`lambda_query_dynamo.lambda_handler()`。由于我们没有模拟 DynamoDB，它将查询`table_name = 'user-visits-sam'`Lambda 函数中指定的表。然后它将捕获输出响应，可能如下所示：

```py
Response: {"statusCode": "200", "body": "[{\"EventCount\": 3, \"EventDay\": 20171001, \"EventId\": \"324\"}, {\"EventCount\": 5, \"EventDay\": 20171002, \"EventId\": \"324\"}, {\"EventCount\": 4, \"EventDay\": 20171010, \"EventId\": \"324\"}, {\"EventCount\": 20, \"EventDay\": 20171012, \"EventId\": \"324\"}, {\"EventCount\": 10, \"EventDay\": 20171013, \"EventId\": \"324\"}, {\"EventCount\": 6, \"EventDay\": 20171014, \"EventId\": \"324\"}, {\"EventCount\": 6, \"EventDay\": 20171016, \"EventId\": \"324\"}, {\"EventCount\": 2, \"EventDay\": 20171017, \"EventId\": \"324\"}]", "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}} 
```

正文与我们在第三章中在浏览器中看到的内容相同，*部署您的无服务器堆栈*。因此，您可以直接使用真实数据调试不同的集成场景，并在使用真实数据的 Lambda 代码中构建更完整的测试套件。

# 使用真实测试数据进行集成测试

现在我们了解了真实测试数据，我们将看看如何测试已部署的 Lambda 函数。首先，您需要安装和设置 AWS CLI，并按照第一章末尾显示的方式配置 AWS 凭据：

```py
$ sudo pip3 sudo install awscli 
$ aws configure 
```

我们将重新部署在第三章中部署的无服务器微服务堆栈，*部署您的无服务器堆栈*，以便我们可以测试它。使用以下命令：

```py
$ cd ./serverless-microservice-data-api/bash/apigateway-lambda-dynamodb
$ ./build-package-deploy-lambda-dynamo-data-api.sh
```

这将重新构建 Lambda ZIP 包作为代码（如果有任何更改）。然后它将打包和部署代码和 SAM 配置。最后，它将创建 API 网关、Lambda 函数和 DynamoDB 表。

对于测试，我们将使用 AWS CLI，它可以调用所有 AWS 托管的服务。在这里，我们对`lambda` ([`docs.aws.amazon.com/cli/latest/reference/lambda/index.html`](https://docs.aws.amazon.com/cli/latest/reference/lambda/index.html))和`apigateway` ([`docs.aws.amazon.com/cli/latest/reference/apigateway/index.html`](https://docs.aws.amazon.com/cli/latest/reference/apigateway/index.html))服务感兴趣。

# 测试 Lambda 是否已正确部署

测试部署的 Lambda，您可以运行以下命令：

```py
$ aws lambda invoke --invocation-type Event \
 --function-name lambda-dynamo-data-api-sam  --region eu-west-1 \
 --payload file://../../sample_data/request-api-gateway-get-valid.json \ outputfile.tmp 
```

为了自动化，我们可以将以下代码放入一个 shell 脚本，`serverless-microservice-data-api/bash/apigateway-lambda-dynamodb/invoke-lambda.sh`：

```py
#!/bin/sh
. ./common-variables.sh
rm outputfile.tmp
status_code=$(aws lambda invoke --invocation-type RequestResponse \
    --function-name ${template}-sam --region ${region} \
    --payload file://../../sample_data/request-api-gateway-get-valid.json \
    outputfile.tmp --profile ${profile})
echo "$status_code"
if echo "$status_code" | grep -q "200";
then
    cat outputfile.tmp
    if grep -q error outputfile.tmp;
    then
        echo "\nerror in response"
        exit 1
    else
        echo "\npass"
        exit 0
    fi
else
    echo "\nerror status not 200"
    exit 1
fi 
```

我们调用 Lambda，但也使用`grep`命令检查`outputfile.tmp`文件中的响应。如果检测到错误，则返回退出代码`1`，否则返回`0`。这允许您在其他工具或 CI/CD 步骤中链接逻辑。

# 测试 API 网关是否已正确部署

我们还希望在部署后能够测试无服务器微服务 API 是否正常工作。我使用 Python 和 bash 混合使用，以使其更容易。

首先使用名为`serverless-microservice-data-api/bash/apigateway-lambda-dynamodb/get_apigateway_endpoint.py`的 Python 脚本查询 AWS API Gateway 以获取完整的端点，并在成功时返回代码`0`：

```py
import argparse
import logging

import boto3
logging.getLogger('botocore').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s %(name)-15s: %(lineno)d %(message)s',
                    level=logging.INFO) logger.setLevel(logging.INFO) 

def get_apigateway_names(endpoint_name):
    client = boto3.client(service_name='apigateway', 
                          region_name='eu-west-1')
    apis = client.get_rest_apis()
    for api in apis['items']:
        if api['name'] == endpoint_name:
            api_id = api['id']
            region = 'eu-west-1'
            stage = 'Prod'
            resource = 'visits/324'
            #return F"https://{api_id}.execute-api.
             {region}.amazonaws.com/{stage}/{resource}"
            return "https://%s.execute-api.%s.amazonaws.com/%s/%s" 
                % (api_id, region, stage, resource)
    return None

def main():
    endpoint_name = "lambda-dynamo-xray"

    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--endpointname", type=str, 
        required=False, help="Path to the endpoint_name")
    args = parser.parse_args()

    if (args.endpointname is not None): endpoint_name = 
        args.endpointname

    apigateway_endpoint = get_apigateway_names(endpoint_name)
    if apigateway_endpoint is not None:
        print(apigateway_endpoint)
        return 0
    else:
        return 1

if __name__ == '__main__':
    main()
```

然后我们使用一个 shell 脚本来调用 Python 脚本。Python 脚本返回 API 端点，该端点在 curl 中与样本`GET`请求一起使用。然后我们查看是否获得有效的状态码。

这是`serverless-microservice-data-api/bash/apigateway-lambda-dynamodb/curl-api-gateway.sh`的完整脚本：

```py
. ./common-variables.sh
endpoint="$(python get_apigateway_endpoint.py -e ${template})"
echo ${endpoint}
status_code=$(curl -i -H \"Accept: application/json\" -H \"Content-Type: application/json\" -X GET ${endpoint})
echo "$status_code"
if echo "$status_code" | grep -q "HTTP/1.1 200 OK";
then
    echo "pass"
    exit 0
else
    exit 1
fi 
```

以这种方式设置这些脚本使我们能够轻松地自动化这些集成测试。

**函数即服务**（**FaaS**）仍然是一个相对较新的领域。关于应该使用哪种类型的集成测试仍然有很多讨论。有一种观点是，我们应该在不同的 AWS 账户中进行全套测试，特别是那些会写入或更新数据存储的测试，比如`POST`或`PUT`请求。

如果您想这样做，我已经包括了`--profile`和`aws_account_id`。此外，使用 API Gateway，您可以使用一系列已经存在的围绕 HTTP 端点的测试套件，但是测试 Lambdas 与其他 AWS 服务的集成，比如在 S3 中创建触发 Lambda 的对象，需要更多的工作和思考。在我看来，无服务器集成测试仍然不够成熟，但我已经展示了如何通过使用 AWS CLI 直接调用 Lambda 函数以及使用 JSON 事件源负载调用 API Gateway 端点来实现它们。

接下来，我们将看看 SAM CLI 如何用于本地测试。

# AWS 无服务器应用程序模型 CLI

在本节中，我们将通过完全可用的示例演示 SAM Local 的不同功能。对于本地测试，您可以像我展示的那样使用 Python 和 bash，也可以使用 SAM CLI ([`github.com/awslabs/aws-sam-cli`](https://github.com/awslabs/aws-sam-cli))，在撰写本文时仍处于测试阶段。它使用 Docker，并且基于开源`docker-lambda` ([`github.com/lambci/docker-lambda`](https://github.com/lambci/docker-lambda)) Docker 镜像。如果您使用的是 Windows 10 Home，我建议您升级到 Pro 或 Enterprise，因为在 Home 版上更难使 Docker 工作。还有一些硬件要求，比如虚拟化，需要注意。我们需要执行以下步骤：

1.  安装 AWS CLI ([`docs.aws.amazon.com/cli/latest/userguide/installing.html`](https://docs.aws.amazon.com/cli/latest/userguide/installing.html))。

1.  安装 Docker CE ([`docs.docker.com/install/`](https://docs.docker.com/install/))。

1.  安装 AWS SAM CLI ([`docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html`](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html))。

1.  对于 Linux，您可以运行以下命令：

```py
$sudo pip install --user aws-sam-cli 
```

1.  对于 Windows，您可以使用 MSI 安装 AWS SAM CLI。

1.  创建一个新的 SAM Python 3.6 项目，`sam-app`，并`docker pull`镜像（这应该会自动发生，但我需要执行`pull`才能使其工作）：

```py
$ sam init --runtime python3.6
$ docker pull lambci/lambda-base:build
$ docker pull lambci/lambda:python3.6 
```

1.  调用以下函数：

```py
$ cd sam-app
$ sam local invoke "HelloWorldFunction" -e event.json --region eu-west-1 
```

您将获得以下内容：

```py
Duration: 8 ms Billed Duration: 100 ms Memory Size: 128 MB Max Memory Used: 19 MB
{"statusCode": 200, "body": "{\"message\": \"hello world\"}"} 
```

这可以用于添加自动化测试。

1.  启动本地 Lambda 端点：

```py
$ sam local start-lambda --region eu-west-1
# in new shell window
$ aws lambda invoke --function-name "HelloWorldFunction" \
 --endpoint-url "http://127.0.0.1:3001" --no-verify-ssl out.txt 
```

这将启动一个模拟 AWS Lambda 的 Docker 容器，并在本地启动一个 HTTP 服务器，您可以使用它来自动化测试 AWS CLI 或 Boto3 中的 Lambda 函数。

1.  启动 API 并使用以下进行测试：

```py
$ sam local start-api --region eu-west-1
# in new shell window
$ curl -i -H \"Accept: application/json\" -H \"Content-Type: application/json\" -X GET http://127.0.0.1:3000/hello 
```

这将在本地启动一个带有 HTTP 服务器的 Docker 容器，您可以使用它来自动化测试与`curl`、Postman 或您的 Web 浏览器一起使用的 API。

1.  生成示例事件的一种方法是从 Lambda 中打印出事件，并从 CloudWatch 日志中复制它（这是我的首选）。另一种方法是使用`sam local`，它可以生成一些示例事件。例如，您可以运行以下命令：

```py
$ sam local generate-event apigateway aws-proxy 
```

就我个人而言，我并没有广泛使用 SAM CLI，因为它非常新，需要安装 Docker，并且仍处于测试阶段。但它看起来很有前途，作为测试无服务器堆栈的另一个工具，它很有用，因为它可以在 Docker 容器中模拟 Lambda 并公开端点，我期望未来会添加更多功能。

也许不太有用的是，它还将一些现有命令的无服务器打包和部署命令包装为 CloudFormation 命令的别名。我认为这样做是为了将它们都放在一个地方。

1.  以下是 SAM CLI `package`和`deploy`命令的示例：

```py
$ sam package \
 --template-file $template.yaml \
 --output-template-file ../../package/$template-output.yaml \
 --s3-bucket
$bucket $ sam deploy \
 --template-file ../../package/$template-output.yaml \
 --stack-name $template \
 --capabilities CAPABILITY_IAM
```

使用 SAM 的 CloudFormation 进行`package`和`deploy`命令：

```py
$ aws cloudformation package \
 --template-file $template.yaml \
 --output-template-file ../../package/$template-output.yaml \
 --s3-bucket $bucket \
 --s3-prefix $prefix
$ aws cloudformation deploy \
 --template-file ../../package/$template-output.yaml \
 --stack-name $template \
 --capabilities CAPABILITY_IAM
```

# 加载和规模化的端到端测试

接下来，我们将看一下 Locust，这是一个用于性能和负载测试的 Python 工具。然后我们将讨论减少 API 延迟和改善 API 响应时间的策略，使用 Locust 将向我们展示性能改进。

# 对您的无服务器微服务进行负载测试

首先，您需要运行一个带有`./build-package-deploy-lambda-dynamo-data-api.sh`的无服务器微服务堆栈，并使用`python3 dynamo_insert_items_from_file.py` Python 脚本将数据加载到 DynamoDB 表中。

然后安装 Locust，如果它尚未与`requirements.txt`中的其他软件包一起安装：

```py
$ sudo pip3 install locustio 
```

Locust ([`docs.locust.io`](https://docs.locust.io))是一个易于使用的负载测试工具，具有 Web 指标和监控界面。它允许您使用 Python 代码定义用户行为，并可用于在多台机器上模拟数百万用户。

要使用 Locust，您首先需要创建一个 Locust Python 文件，在其中定义 Locust 任务。`HttpLocust`类添加了一个客户端属性，用于发出 HTTP 请求。`TaskSet`类定义了 Locust 用户将执行的一组任务。`@task`装饰器声明了`TaskSet`的任务：

```py
import random
from locust import HttpLocust, TaskSet, task

paths = ["/Prod/visits/324?startDate=20171014",
         "/Prod/visits/324",
         "/Prod/visits/320"]

class SimpleLocustTest(TaskSet):

    @task
    def get_something(self):
        index = random.randint(0, len(paths) - 1)
        self.client.get(paths[index])

class LocustTests(HttpLocust):
    task_set = SimpleLocustTest
```

要测试`GET`方法与不同的资源和参数，我们从路径列表中随机选择三个不同的路径，其中一个 ID 在 DynamoDB 中不存在。主要思想是，如果我们已经将相应的行从文件加载到 DynamoDB 中，我们可以轻松地扩展到模拟数百万个不同的查询。Locust 支持更复杂的行为，包括处理响应、模拟用户登录、排序和事件挂钩，但这个脚本是一个很好的开始。

要运行 Locust，我们需要获取 API Gateway ID，看起来像`abcdefgh12`，以创建用于负载测试的完整主机名。在这里，我编写了一个名为`serverless-microservice-data-api/bash/apigateway-lambda-dynamodbget_apigateway_id.py`的 Python 脚本，可以根据 API 名称执行此操作：

```py
import argparse
import logging

import boto3
logging.getLogger('botocore').setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s %(levelname)s %(name)-15s: %(lineno)d %(message)s',
                    level=logging.INFO)
logger.setLevel(logging.INFO)

def get_apigateway_id(endpoint_name):
    client = boto3.client(service_name='apigateway', 
             region_name='eu-west-1')
    apis = client.get_rest_apis()
    for api in apis['items']:
        if api['name'] == endpoint_name:
            return api['id']
    return None

def main():
    endpoint_name = "lambda-dynamo-xray"

    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--endpointname", type=str, 
                        required=False, help="Path to the endpoint_id")
    args = parser.parse_args()

    if (args.endpointname is not None): endpoint_name = args.endpointname

    apigateway_id = get_apigateway_id(endpoint_name)
    if apigateway_id is not None:
        print(apigateway_id)
        return 0
    else:
        return 1

if __name__ == '__main__':
    main() 
```

运行以下命令启动 Locust：

```py
$ . ./common-variables.sh
$ apiid="$(python3 get_apigateway_id.py -e ${template})"
$ locust -f ../../test/locust_test_api.py --host=https://${apiid}.execute-api.${region}.amazonaws.com 
```

或者，我还有这个`locust`运行命令，可以作为一个 shell 脚本运行，在`test`文件夹`serverless-microservice-data-api/bash/apigateway-lambda-dynamodb/run_locus.sh`下：

```py
#!/bin/sh
. ./common-variables.sh
apiid="$(python3 get_apigateway_id.py -e ${template})"
locust -f ../../test/locust_test_api.py --host=https://${apiid}.execute-api.${region}.amazonaws.com 
```

您现在应该在终端中看到 Locust 启动并执行以下步骤：

1.  在 Web 浏览器中导航到`http://localhost:8089/`，以访问 Locust Web 监控和测试界面。

1.  在开始新的 Locust 群中，输入以下内容：

+   **模拟的用户数量**为`10`

+   `5`用于 Hatch 速率（每秒生成的用户）

1.  在统计选项卡上让工具运行几分钟。

在统计选项卡中，您将得到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/4c3715e8-f782-4920-bab7-04b091154bb0.png)

在图表选项卡上，您应该会得到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/43fbaf5b-6abd-45ec-bd3f-4e1f816cdc5d.png)

在响应时间（毫秒）图表中，橙色线代表 95^(th)百分位数，绿色代表中位数响应时间。

以下是有关前面图表的一些观察：

+   最大请求时间为 2,172 毫秒，约为 2.1 秒，这非常慢——这与所谓的冷启动有关，这是首次启动 Lambda 的较慢方式。

+   大约一分钟后，失败的次数也会增加——这是因为 DynamoDB 在开始限制读取请求之前允许一些突发读取。如果您登录到 AWS 管理控制台并查看 DynamoDB 表指标，您将看到正在发生这种情况：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/4704d163-b694-4510-ba67-6a57890ee1a7.png)

# 减少 API 延迟的策略

有许多减少延迟的策略。我们将看两种，这两种都在 SAM 模板中设置：

+   **增加 Lambda RAM 大小**：目前设置为最小的 128 MB

+   **增加 DynamoDB 读取容量**：目前设置为最小值 1 个单位

我真的很喜欢 DynamoDB 的一点是，您可以更改每个表的容量，并且可以独立更改写入容量和读取容量。这对于我来说在读取密集型用例中非常有趣和划算，我可以将读取容量设置得比写入容量更高。甚至还有选项可以根据读/写利用率自动调整表的容量，或者完全基于需求，按照每次读/写请求付费。

我们将从 1 增加 DynamoDB 表的读取容量到 500 个读取单位（保持写入容量为 1 个单位）。费用原本是每月$0.66，但现在将增加到每月$55.24。

编辑`lambda-dynamo-data-api.yaml` SAM YAML 模板文件，并将`ReadCapacityUnits`从`1`增加到`500`：

```py
AWSTemplateFormatVersion: '2010-09-09'
Transform: 'AWS::Serverless-2016-10-31'
Description: >-
  This Lambda is invoked by API Gateway and queries DynamoDB.
Parameters:
    AccountId:
        Type: String

Resources:
  lambdadynamodataapi:
    Type: AWS::Serverless::Function
    Properties:
      Handler: lambda_return_dynamo_records.lambda_handler
      Runtime: python3.6
      CodeUri: ../../package/lambda-dynamo-data-api.zip
      FunctionName: lambda-dynamo-data-api-sam
      Description: >-
        This Lambda is invoked by API Gateway and queries DynamoDB.
      MemorySize: 128
      Timeout: 3
      Role: !Sub 'arn:aws:iam::${AccountId}:role/
                  lambda-dynamo-data-api'
      Environment:
        Variables:
          environment: dev
      Events:
        CatchAll:
          Type: Api
          Properties:
            Path: /visits/{resourceId}
           Method: GET
  DynamoDBTable:
    Type: AWS::DynamoDB::Table 
    Properties:
      TableName: user-visits-sam
      SSESpecification:
        SSEEnabled: True
      AttributeDefinitions:
        - AttributeName: EventId
          AttributeType: S
        - AttributeName: EventDay
          AttributeType: N
      KeySchema:
        - AttributeName: EventId
          KeyType: HASH
        - AttributeName: EventDay
          KeyType: RANGE
      ProvisionedThroughput:
        ReadCapacityUnits: 500
        WriteCapacityUnits: 1
```

运行`./build-package-deploy-lambda-dynamo-data-api.sh`来部署带有 DynamoDB 表更改的无服务器堆栈。

现在以 5 的孵化速率再次使用 10 个用户运行 Locust：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/c7010d83-294f-4e89-b8c5-a71631f1822e.png)

在图表选项卡上，您应该会得到类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/5820f3fb-b465-4722-8e28-596a7a4c6559.png)

以下是关于前述图表的一些观察：

+   没有故障

+   平均响应时间为 64 毫秒，这非常好

我们得到这些结果是因为增加了 DynamoDB 表的读取容量，也就是说，请求不再被限制。

现在增加 Lambda 函数中可用的 RAM：

1.  通过将 MemorySize: 128 更改为 MemorySize: 1536 来修改`lambda-dynamo-data-api.yaml` SAM YAML 文件。

1.  运行`./build-package-deploy-lambda-dynamo-data-api.sh`来部署带有 Lambda RAM 更改的无服务器堆栈。

以下是我们对前述更改所做的一些观察：

+   没有故障

+   平均响应时间为 60 毫秒，这稍微好一些，特别是考虑到这是 API Gateway 到 Lambda 到 DynamoDB 再返回的一个往返。

使用 10 的孵化速率和 100 个用户，我们得到以下结果：

+   没有故障

+   平均响应时间为 66 毫秒，负载测试开始时最大为 1,057 毫秒

使用 50 的孵化速率和 250 个用户，我们得到以下结果：

+   没有故障

+   平均响应时间为 81 毫秒，负载测试开始时最大为 1,153 毫秒。

您也可以测试更高数量的并发用户，比如 1,000 个，即使响应时间会因其他瓶颈而大大增加，但系统仍然可以正常工作。如果您想进一步扩展规模，我建议您考虑不同的架构。仅仅通过在配置文件中更改几个参数，就能如此轻松地扩展无服务器微服务，仍然令人印象深刻！

这让您对如何减少 API 的延迟有了很好的了解。

# 清理

使用`./delete-stack.sh`运行以下 shell 脚本来删除无服务器堆栈：

```py
#!/usr/bin/env bash
. ./common-variables.sh
aws cloudformation delete-stack --stack-name $template --region $region --profile $profile 
```

# 摘要

在本章中，我们探讨了许多类型的测试，包括使用模拟进行单元测试，使用 Lambda 和 API Gateway 进行集成测试，本地调试 Lambda，提供本地端点以及负载测试。这是我们将在本书的其余部分继续构建的内容。

在下一章中，我们将探讨无服务器的分布式数据管理模式和架构，您可以在组织中应用这些模式。


# 第五章：保护您的微服务

在本章中，我们将简要概述 AWS 中的安全性，以确保您的无服务器微服务是安全的。在创建我们的第一个微服务之前，我们首先需要了解 AWS 安全模型。我们将讨论一些重要的术语和整体 AWS 安全模型。然后，我们将讨论 IAM，用于访问任何 AWS 资源。最后，我们将讨论如何保护您的无服务器微服务。

在本章中，我们将涵盖以下主题：

+   AWS 安全概述

+   AWS 身份和访问管理（IAM）概述

+   保护您的无服务器微服务

# AWS 安全概述

在本节中，我们将概述 AWS 中的安全性。我们将看看为什么安全很重要，提供一些安全性的例子，讨论重要的安全术语类型，并谈论 AWS 共享责任模型。

# 为什么安全很重要？

以下几点讨论了安全的重要性：

+   **法律和标准的合规性**：例如，欧盟**通用数据保护条例**（**GDPR**）和美国颁布的**健康保险可移植性和责任法案**（**HIPAA**）负责监管所有个人数据保护和隐私的法律。

+   **数据完整性**：不安全的系统可能会被剥夺数据或篡改数据，这意味着您不能再信任数据。

+   **个人可识别信息**：隐私是当今的主要关注点。您应该当然地保护您的用户数据和资产。

+   **数据可用性**：例如，如果审计员要求您提供特定数据，您需要能够检索该数据。如果您的数据中心附近发生自然灾害，那些数据需要是可用和安全的。

让我们看看以下清单：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/ecf395c1-f69c-4c11-8097-56cff9358006.png)

在左侧，我们有各种配置不正确、缺少更新或未加密通信手段的系统。这实际上可能导致中间部分，例如系统被黑客入侵、勒索软件要求或对您的系统进行渗透。例如，可能会发动分布式拒绝服务攻击，这将使您的电子商务网站无法访问。

在右侧，您可以看到一些影响。可能会有诉讼成本、数据丢失或数据泄露、对您的组织的财务成本，以及声誉成本。

# AWS 中的安全术语类型

AWS 中的许多安全性实际上是配置和正确架构的重要性。因此，了解一些这些安全术语是很重要的。

+   **传输安全**：将其视为 HTTPS SSL。如果您考虑一个网络浏览器，您会在浏览器中看到一个挂锁，表示通信是安全的，例如当您访问任何在线银行系统时。

+   **静态安全**：这是加密在数据库或文件系统中的数据。只有拥有密钥的用户才能访问数据。

+   **身份验证**：这指的是确认用户或系统是否是其应该是的过程。

+   **授权**：一旦您经过身份验证，系统会检查正确的授权。这是为了检查权限和访问控制是否已经就位，以便您访问特定的 AWS 资源。

# AWS 身份和访问管理（IAM）概述

在本节中，我们将简要讨论 AWS IAM，特别是用于无服务器计算。IAM 是一个中心位置，您可以在那里管理用户和安全凭据，如密码、访问密钥和权限策略，以控制对 AWS 服务和资源的访问。我们将讨论最相关的 IAM 资源：策略、角色、组和用户。

IAM 策略是定义受影响操作的资源和条件的 JSON 文档。以下是一个 JSON 文档的示例，它将授予对 DynamoDB 表的读取访问权限，仅当请求来自特定 IP 范围时，表名为 `Books`：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/23e9e592-4c72-469c-879d-98779efa042c.png)

还有一个可视化编辑器，允许您创建这些组，或者您可以通过编辑 JSON 文档来手动创建。

# IAM 用户

IAM 用户是与 AWS 交互的人员或服务。他们通过密码或多因素身份验证（对于新用户）访问管理控制台，或者他们可能具有访问密钥，以便使用命令行界面或 SDK 进行编程访问。如下图所示，您可以将策略附加到用户，以授予他们对特定 IP 范围内 DynamoDB 的读取访问权限：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/54324278-3dcd-46d2-be1f-1add0e3d7f4f.png)

# IAM 组

IAM 组用于更好地模拟组织中的安全术语。您可以将它们视为活动目录组。例如，在您的组织中，您可能会有管理员、开发人员和测试人员。

要创建一个组，您可以使用 AWS 管理控制台、SDK 或 CLI，在 IAM 中添加组，然后附加策略。创建组后，您可以将其附加到用户，或者您可以创建一个新的组。

# IAM 角色

IAM 角色类似于用户，它们可以附加策略，但可以由需要访问的任何人附加到受信任的实体。通过这种方式，您可以委派对用户、应用程序或服务的访问权限，而无需给他们新的 AWS 密钥，因为他们可以通过这个受信任的实体使用临时安全令牌。例如，您可以授予第三方对 S3 存储桶的读取访问权限，而无需在您的 AWS 环境中共享任何密钥，纯粹使用角色：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/d4c71608-50fa-43c7-928b-833e844facca.png)

# 保护您的无服务器微服务

在本节中，我们将讨论构建第一个微服务所需的安全性。具体来说，我们将看一下围绕 Lambda 函数、API 网关和 DynamoDB 的安全性，然后我们将讨论在检测到可疑事件时可以使用的监控和警报方式。

# Lambda 安全

在 lambda 安全中，有两种类型的 IAM 角色：

+   调用 lambda：这意味着具有实际调用和运行 lambda 函数的权限。例如，这可以来自 API 网关或另一个服务。

+   授予 lambda 函数对特定 AWS 资源的读写访问权限：例如，您可以允许 Lambda 函数从 DynamoDB 表中读取。

此外，**密钥管理服务**（**KMS**）是 AWS 管理的密钥服务，允许您对数据进行加密和解密，例如在数据库或 NoSQL 数据存储中的数据。亚马逊虚拟私有云是另一个选项，Lambda 默认在安全的 VPC 中运行。但是，如果您需要访问资源，例如弹性碰撞集群或 RDS，这些资源位于私有 VPC 中，您可能希望在自己的私有 AWS VPC 中运行它。以下是使用 AWS Lambda 使用 AWS KMS 和 AWS VPC 的工作流表示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/19a2108f-ce03-45af-af20-5dc8ab3c2d18.png)

对于 API 网关安全性，有三种方式可以控制谁可以调用您的 API 方法。这被称为请求授权，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-msvc-py/img/2a977e79-748b-4e80-82c5-7765b11013bc.png)

以下是控制谁可以调用您的 API 的不同方法：

+   IAM 角色和策略：这提供对 API 网关的访问。API 网关将使用这些角色和策略来验证请求者的签名。

+   亚马逊 Cognito 用户池：这控制谁可以访问 API。在这种情况下，用户必须登录才能访问 API。

+   **API Gateway 自定义授权者**：这是一个请求，比如一个持有者令牌或 lambda 函数，用于验证并检查客户端是否被授权调用 API。

如果您从 API 自己的域之外的域接收请求，您必须启用跨域资源共享。此外，API Gateway 支持 SSL 证书和证书颁发机构。API Gateway 可能需要通过 IAM 角色授权调用或调用 AWS 内的特定资源，比如 Kinesis 流或调用 Lambda 函数。

# DynamoDB 安全

您可以使用 IAM 用户进行身份验证，也可以使用特定的 IAM 角色。一旦它们经过身份验证，授权就受到控制，并且 IAM 策略被分配给特定用户或角色。我建议的是，在为 DynamoDB 创建这些策略时，尽可能地限制它们，这意味着避免对所有表和 DynamoDB 进行读取和写入访问。最好为特定表使用特定名称。

# 监控和警报

监控系统中的任何可疑活动并检测任何性能问题非常重要。API Gateway、DynamoDB 和 Lambda 函数都支持 CloudTrail、CloudWatch 和 X-Ray 进行监控和警报。它们的讨论如下：

+   CloudTrail 允许您监控所有 API 和任何用户或系统对资源的访问。

+   CloudWatch 允许您收集和跟踪指标，监视日志文件，设置特定警报，并自动对 AWS 资源的更改做出反应。

+   X-Ray 是一项新服务，可以跟踪请求并生成服务地图。

这些免费系统的组合为您提供了对无服务器系统的非常好的洞察力。

# 摘要

阅读完本章后，您应该对 AWS 中的安全有更深入的了解，以及为什么对您的组织来说这是重要的。毕竟，没有人希望成为负责数据泄露的人。我们讨论了 IAM，您现在知道策略是确保对 AWS 资源受限访问的关键文档。我们还研究了一些保护您的无服务器微服务的安全概念；具体来说，我们了解了 lambda、API Gateway 和 DynamoDB。
