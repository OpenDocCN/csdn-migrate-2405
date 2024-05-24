# Docker AWS 教程（二）

> 原文：[`zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5`](https://zh.annas-archive.org/md5/13D3113D4BA58CEA008B572AB087A5F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：开始使用 AWS

在上一章中，我们讨论了部署容器应用程序到 AWS 的各种选项，现在是时候开始使用弹性容器服务（ECS）、Fargate、弹性 Kubernetes 服务（EKS）、弹性 Beanstalk 和 Docker Swarm 来实施实际解决方案了。在我们能够涵盖所有这些令人兴奋的材料之前，您需要建立一个 AWS 账户，了解如何为您的账户设置访问权限，并确保您对我们将在本书中使用的各种工具有牢固的掌握，以与 AWS 进行交互。

开始使用 AWS 非常容易——AWS 提供了一套免费的服务套件，使您能够在 12 个月内免费测试和尝试许多 AWS 服务，或者在某些情况下，无限期地免费使用。当然，会有一些限制，以确保您不能免费设置自己的比特币挖矿服务，但在大多数情况下，您可以利用这些免费套餐服务来测试大量的场景，包括我们将在本书中进行的几乎所有材料。因此，本章将从建立一个新的 AWS 账户开始，这将需要您拥有一张有效的信用卡，以防您真的跟进了那个伟大的新比特币挖矿企业。

一旦您建立了一个账户，下一步是为您的账户设置管理访问权限。默认情况下，所有 AWS 账户都是使用具有最高级别账户特权的根用户创建的，但 AWS 不建议将根账户用于日常管理。因此，我们将配置 AWS 身份访问和管理（IAM）服务，创建 IAM 用户和组，并学习如何使用多因素身份验证（MFA）实施增强安全性。

建立了对 AWS 账户的访问权限后，我们将专注于您可以用来与 AWS 进行交互的各种工具，包括提供基于 Web 的管理界面的 AWS 控制台，以及用于通过命令行与 AWS 进行交互的 AWS CLI 工具。

最后，我们将介绍一种名为 AWS CloudFormation 的管理服务和工具集，它提供了一种基础设施即代码的方法来定义您的 AWS 基础设施和服务。CloudFormation 允许您定义模板，使您能够通过单击按钮构建完整的环境，并且以可重复和一致的方式进行操作。在本书中，我们将广泛使用 CloudFormation，因为在实践中，大多数部署基于 Docker 的应用程序的组织都采用基础设施即代码工具，如 CloudFormation、Ansible 或 Terraform 来自动化其 Docker 应用程序和支持基础设施的部署。您将学习如何创建一个简单的 CloudFormation 模板，然后使用 AWS 控制台和 AWS CLI 部署该模板。

本章将涵盖以下主题：

+   设置 AWS 账户

+   以根账户登录

+   创建 IAM 用户、组和角色

+   创建一个 EC2 密钥对

+   安装 AWS CLI

+   在 AWS CLI 中配置凭据和配置文件

+   使用 AWS CLI 与 AWS 进行交互

+   介绍 AWS CloudFormation

+   定义一个简单的 AWS CloudFormation 模板

+   部署 AWS CloudFormation 堆栈

+   删除 AWS CloudFormation 堆栈

# 技术要求

本章的技术要求如下：

+   根据第一章《容器和 Docker 基础知识》中的说明安装先决条件软件

+   在本章中，需要一个有效的信用卡来创建免费的 AWS 账户

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch3`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch14)[.](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch3)

查看以下视频，了解代码的实际运行情况：

[`bit.ly/2N1nzJc`](http://bit.ly/2N1nzJc)

# 设置 AWS 账户

您 AWS 之旅的第一步是建立一个 AWS 账户，这是 AWS 的基础构建块，为您管理 AWS 服务和资源提供了安全和管理上下文。为了鼓励采用 AWS，并确保首次用户有机会免费尝试 AWS，AWS 提供了一个免费套餐，允许您免费访问一些 AWS 服务（在使用方面有一些限制）。您可以在[`aws.amazon.com/free/`](https://aws.amazon.com/free/)了解更多关于免费套餐和提供的服务。确保您对可以免费使用和不能免费使用有很好的理解，以避免不必要的账单冲击。

在本书中，我们将使用一些免费套餐服务，以下是每月使用限制：

| **服务** | **限制** |
| --- | --- |
| EC2 | 750 小时的 Linux t2.micro（单个 vCPU，1 GB 内存）实例 |
| 弹性块存储 | 30 GB 的块级存储（SSD 或传统旋转磁盘） |
| RDS | 750 小时的 db.t2.micro（单个 vCPU，1 GB 内存）MySQL 实例 |
| 弹性容器注册表 | 500 MB 的存储空间 |
| 弹性负载均衡 | 750 小时的经典或应用负载均衡器 |
| S3 | 5 GB 的 S3 存储空间 |
| Lambda | 1,000,000 次请求 |
| CloudWatch | 10 个自定义指标 |
| SNS | 1,000,000 次发布 |
| CodeBuild | 100 分钟的构建时间 |
| CodePipeline | 1 个活动管道 |
| X-Ray | 100,000 个跟踪 |
| 密钥管理服务 | 20,000 个请求 |
| Secrets Manager | 30 天免费试用期，然后每个秘密/月$0.40 |

正如您所看到的，我们将在本书中涵盖许多 AWS 服务，几乎所有这些服务都是免费的，假设您遵守前表中描述的使用限制。实际上，在本书中我们将使用的唯一一个不免费的服务是 AWS Fargate 服务，所以当您阅读 Fargate 章节时请记住这一点，并尽量减少使用，如果您担心成本。 

要注册免费套餐访问，请点击[`aws.amazon.com/free/`](https://aws.amazon.com/free/)上的**创建免费账户**按钮：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/de4a4e51-dad1-4756-ad13-ce2d6089757a.png)创建免费账户

您将被提示输入电子邮件地址、密码和 AWS 账户名称。重要的是要理解，您在这里输入的电子邮件地址和密码被称为您的 AWS 账户的根账户，这是对您的账户具有最高访问级别的账户。对于 AWS 账户名称，您可以输入任何您喜欢的名称，但它必须在所有其他 AWS 账户中是唯一的，所以至少您将无法使用我选择的账户名称，即`docker-in-aws`。这个账户名称在您登录时使用，比您的 AWS 账户号码更容易记住，后者是一个 12 位数字。

注册过程的其余部分是不言自明的，所以我不会在这里详细说明，但请理解，您将需要提供信用卡详细信息，并将对超出免费使用限制的任何费用负责。您还需要验证注册期间指定的电话号码，这涉及自动电话呼叫到您的号码，因此请确保您在注册期间输入一个有效的电话号码。

# 安装谷歌身份验证器

本节描述的步骤是完全可选的，但是作为安全最佳实践，您应该始终在根账户上启用多因素身份验证（MFA）。事实上，无论所需访问级别如何，您都应该为所有基于用户的 AWS 账户访问启用 MFA。在许多使用 AWS 的组织中，启用 MFA 越来越成为强制性要求，因此在涉及 MFA 时习惯于使用 AWS 是很重要的。因此，我们实际上将在本书中始终使用 MFA。

在您使用 MFA 之前，您需要有一个 MFA 设备，可以是硬件或虚拟 MFA 设备。虚拟 MFA 设备通常安装在您的智能手机上，作为应用程序的形式，完成了您所知道的东西（密码）和您所拥有的东西（您的手机）的多因素范式。

一个流行的 MFA 应用程序可用于 Android 和 iOS 的是谷歌身份验证器应用程序，您可以从谷歌 Play 或苹果应用商店下载。安装应用程序后，您可以继续登录到根账户并设置 MFA 访问。

# 以根账户登录

设置和激活您的账户后，您应该能够登录到 AWS 控制台，您可以在[`console.aws.amazon.com/console/home`](https://console.aws.amazon.com/console/home)访问。

使用根凭据登录后，您应立即启用 MFA 访问。这提供了额外的安全级别，确保如果您的用户名和密码被泄露，攻击者不能在没有您的 MFA 设备（在我们的示例中，这意味着您智能手机上的 Google Authenticator 应用程序）的情况下访问您的帐户。

要为您的根帐户启用 MFA，请选择指定您帐户名称的下拉菜单（在我的情况下，这是“docker-in-aws”），然后选择“我的安全凭据”：

！[](assets/bd93b230-35b0-4d24-b1dd-a148d744fe77.png)访问我的安全凭据

在下一个提示中，点击“继续到安全凭据”按钮，在“您的安全凭据”页面上展开“多因素身份验证（MFA）”选项，然后点击“激活 MFA”按钮：

！[](assets/b554b605-ddd9-4bce-a62c-1c6a6a7be323.png)您的安全凭据屏幕

在“管理 MFA 设备”屏幕上，点击“虚拟 MFA 设备”选项，然后连续点击两次“下一步”，此时您将看到一个 QR 码：

！[](assets/56ca8281-9403-47b8-82c7-5c2b96e94fe3.png)获取 QR 码

您可以使用智能手机上的 Google Authenticator 应用程序扫描此代码，方法是点击添加按钮，选择“扫描条形码”，然后在 AWS 控制台中扫描 QR 码：

！[](assets/6ab37fc0-9b86-4ee4-9c57-b186a02ddb6b.jpg)  ！[](assets/0a255dd8-9ba8-4e15-b55d-2d7e10bfc436.png)！[](assets/5c785b9d-3b72-40db-9f65-dcbb2a5b3343.png)注册 MFA 设备

一旦扫描完成，您需要在“管理 MFA 设备”屏幕上的“身份验证代码 1”输入中输入显示的六位代码。

代码旋转后，将代码的下一个值输入到“身份验证代码 2”输入中，然后点击“激活虚拟 MFA”按钮，以完成 MFA 设备的注册：

！[](assets/e399192a-aa4e-43d0-a977-2e8ba4107479.png)带有 MFA 设备的您的安全凭据

# 创建 IAM 用户、组和角色

在使用 MFA 保护根帐户后，您应立即在您的帐户中创建身份访问和管理（IAM）用户、组和角色以进行日常访问。 IAM 是日常管理和访问 AWS 帐户的推荐方法，您应仅限制根帐户访问计费或紧急情况。在继续之前，您需要知道您的 AWS 帐户 ID，您可以在上一个屏幕截图中看到，在您的 MFA 设备的序列号中（请注意，这将与显示的序列号不同）。记下这个帐户号，因为在配置各种 IAM 资源时将需要它。

# 创建 IAM 角色

创建 IAM 资源的标准做法是创建用户可以承担的*角色*，这将为用户在有限的时间内（通常最多 1 小时）授予提升的特权。最低限度，您需要默认创建一个 IAM 角色：

+   管理员：此角色授予对帐户的完全管理控制，但不包括计费信息

要创建管理员角色，请从 AWS 控制台中选择“服务”|“IAM”，从左侧菜单中选择“角色”，然后单击“创建角色”按钮。在“选择受信任的实体类型”屏幕中，选择“另一个 AWS 帐户”选项，并在“帐户 ID”字段中配置您的帐户 ID：

选择受信任的实体作为管理员角色

单击“下一步：权限”按钮后，选择“AdministratorAccess”策略，该策略授予角色管理访问权限：

将策略附加到 IAM 角色

最后，指定一个名为“admin”的角色名称，然后单击“创建角色”以完成管理员角色的创建：

创建 IAM 角色

这将创建管理员 IAM 角色。如果单击新创建的角色，请注意角色的角色 ARN（Amazon 资源名称），因为您以后会需要这个值：

管理员角色

# 创建管理员组

有了管理角色之后，下一步是将您的角色分配给用户或组。与其直接为用户分配权限，强烈建议改为将其分配给组，因为这提供了一种更可扩展的权限管理方式。鉴于我们已经创建了具有管理权限的角色，现在创建一个名为管理员的组是有意义的，该组将被授予*假定*您刚刚创建的 admin 角色的权限。请注意，我指的是假定一个角色，这类似于 Linux 和 Unix 系统，在那里您以普通用户身份登录，然后使用`sudo`命令临时假定根权限。

您将在本章后面学习如何假定一个角色，但现在您需要通过在 IAM 控制台的左侧菜单中选择**组**并单击**创建新组**按钮来创建管理员组。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/02d4df30-8fb3-4a62-af2f-7770c0acddb4.png)创建 IAM 组

您首先需要指定一个名为管理员的**组名称**，然后单击**下一步**两次以跳过**附加策略**屏幕，最后单击**创建组**以完成组的创建：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/bd6acf11-5675-4b42-aeec-0a51e1c66515.png)管理员组

这创建了一个没有附加权限的组，但是如果您单击该组并选择**权限**，现在您有创建内联策略的选项：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b3727916-33e9-467c-9529-620aba3b7bbe.png)创建内联策略

在上述截图中选择点击此处链接后，选择**自定义策略**选项并单击选择，这将允许您配置一个 IAM 策略文档，以授予假定您之前创建的`admin`角色的能力：

管理员组内联策略

该策略包括一个允许执行`sts:AssumeRole`操作的声明 - 这里的`sts`指的是安全令牌服务，这是您在假定角色时与之交互的服务（假定角色的操作会授予您与所假定角色相关联的临时会话凭证）。请注意，资源是您创建的 IAM 角色的 ARN，因此该策略允许任何属于**管理员**组的成员假定**admin**角色。单击**应用策略**按钮后，您将成功创建和配置**管理员**组。

# 创建一个用户组

我通常建议创建的另一个组是用户组，每个访问您的 AWS 账户的人类用户都应该属于该组，包括您的管理员（他们也将成为管理员组的成员）。用户组的核心功能是确保除了一小部分权限外，用户组的任何成员执行的所有操作都必须经过 MFA 身份验证，而不管通过其他组可能授予该用户的权限。这本质上是一个强制 MFA 策略，您可以在[`www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/`](https://www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/)上阅读更多相关信息，并且实施这种方法可以增加您为访问 AWS 账户设置的整体安全保护。请注意，该策略允许用户执行一小部分操作而无需 MFA，包括登录、更改用户密码，以及最重要的是允许用户注册 MFA 设备。这允许新用户使用临时密码登录，更改密码，并自行注册 MFA 设备，一旦用户注销并使用 MFA 重新登录，策略允许用户创建用于 API 和 CLI 访问的 AWS 访问密钥。

要实施用户组，我们首先需要创建一个托管 IAM 策略，与我们在前面的截图中采用的内联方法相比，这是一种更可扩展和可重用的机制，用于将策略分配给组和角色。要创建新的托管策略，请从右侧菜单中选择**策略**，然后单击**创建策略**按钮，这将打开**创建策略**屏幕。您需要创建的策略非常广泛，并且在 GitHub 的要点中发布，网址为[`bit.ly/2KfNfAz`](https://bit.ly/2KfNfAz)，该策略基于先前引用的博客文章中讨论的策略，添加了一些额外的安全增强功能。

请注意，要点包括在策略文件中包含一个名为`PASTE_ACCOUNT_NUMBER`的占位符，因此您需要将其替换为您的实际 AWS 账户 ID：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/f65c5220-257c-44e3-be1b-0aa1c9b60e26.png)创建一个 IAM 托管策略

点击**Review policy**按钮后，您需要为策略配置一个名称，我们将其称为`RequireMFAPolicy`，然后点击**Create policy**创建策略，您需要按照本章前面创建 Administrators 组时的相同说明创建一个 Users 组。

当您在创建 Users 组时到达**Attach Policy**屏幕时，您可以输入刚刚创建的 RequireMFAPolicy 托管策略的前几个字母，然后将其附加到组中。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/a9c05282-0d04-4a82-8e86-63463f523563.png)将 RequireMFAPolicy 附加到 Users 组

完成创建**Users**组的向导后，您现在应该在 IAM 控制台中拥有一个**Administrators**组和**Users**组。

# 创建 IAM 用户

您需要执行的最后一个 IAM 设置任务是创建一个 IAM 用户来管理您的帐户。正如本章前面讨论的那样，您不应该使用根凭证进行日常管理任务，而是创建一个管理 IAM 用户。

要创建用户，请从 IAM 控制台的右侧菜单中选择**Users**，然后点击**Add user**按钮。在**Add user**屏幕上，指定一个**User name**，并且只选择**AWS Management Console access**作为**Access type**，确保**Console password**设置为**Autogenerated password**，并且**Require password reset**选项已设置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6e4cf11a-4fb8-4226-adcc-a0f4d9cb667b.png)创建新用户

点击**Next: Permissions**按钮后，将用户添加到您之前创建的**Administrators**和**Users**组中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/f9dab5ca-1eb6-4942-a07a-d8acd12828aa.png)将用户添加到组中

现在，您可以点击**Next: review**和**Create user**按钮来创建用户。用户将被创建，因为您选择创建了自动生成的密码，您可以点击**Password**字段中的**Show**链接来显示用户的初始密码。请注意这个值，因为您将需要它来测试作为刚刚创建的 IAM 用户登录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/8b50427a-f35e-4772-a692-8e0664aebdf8.png)新创建的用户临时密码

# 作为 IAM 用户登录

现在您已经创建了 IAM 用户，您可以通过单击菜单中的帐户别名/ID 并选择**注销**来测试用户的首次登录体验。如果您现在单击**登录到控制台**按钮或浏览到[`console.aws.amazon.com/console/home`](https://console.aws.amazon.com/console/home)，选择**登录到其他帐户**选项，输入您的帐户别名或帐户 ID，然后单击**下一步**，然后输入刚刚创建的 IAM 用户的用户名和临时密码：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/75e79bbf-c290-4a2d-a106-6f13f32561bb.png)首次以 IAM 用户身份登录

然后会提示您输入新密码：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7deaf251-e404-41d0-961d-de7d00b8e18e.png)输入新密码

确认密码更改后，您将成功以新用户身份登录。

# 为 IAM 用户启用 MFA

在这一点上，您已经首次使用 IAM 用户登录，接下来需要执行的步骤是为新用户注册 MFA 设备。要做到这一点，选择**服务** | **IAM** 打开 IAM 控制台，从左侧菜单中选择**用户**，然后点击您的 IAM 用户。

在**安全凭证**选项卡中，单击**分配的 MFA 设备**字段旁边的铅笔图标：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/aebab6f6-7c8a-4cd4-9671-dccd26b7dc3e.png)IAM 用户安全凭证

管理 MFA 设备对话框将弹出，允许您注册新的 MFA 设备。这个过程与本章前面为根帐户设置 MFA 的过程相同，因此我不会重复说明这个过程，但是一旦您注册了 MFA 设备，重要的是您登出并重新登录到控制台以强制进行 MFA 身份验证。

如果您已经正确配置了一切，当您再次登录到控制台时，应该会提示您输入 MFA 代码：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/48de9696-0af0-40f0-bded-e298bd27a327.png)MFA 提示

# 假设 IAM 角色

一旦您完成了注册 MFA 设备并使用 MFA 登出并重新登录到 AWS 控制台，您现在满足了导致您之前创建的`RequireMFAPolicy`中的以下语句不被应用的要求：

```
{
    "Sid": "DenyEverythingExceptForBelowUnlessMFAd",
    "Effect": "Deny",
    "NotAction": [
        "iam:ListVirtualMFADevices",
        "iam:ListMFADevices",
        "iam:ListUsers",
        "iam:ListAccountAliases",
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ResyncMFADevice",
        "iam:ChangePassword",
        "iam:CreateLoginProfile",
        "iam:DeleteLoginProfile",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetLoginProfile",
        "iam:UpdateLoginProfile"
    ],
    "Resource": "*",
    "Condition": {
        "Null": {
            "aws:MultiFactorAuthAge": "true"
        }
    }
}
```

在上述代码中，重要的是要注意`Deny`的 IAM 效果是绝对的——一旦 IAM 遇到给定权限或一组权限的`Deny`，那么该权限就无法被允许。然而，`Condition`属性使这个广泛的`Deny`有条件——只有在特殊条件`aws:MultiFactorAuthAge`为 false 的情况下才会应用，这种情况发生在您没有使用 MFA 登录时。

假设 IAM 用户已通过 MFA 登录，并附加到具有承担**管理员**角色权限的**Administrators**组，那么`RequireMFAPolicy`中没有任何内容会拒绝此操作，因此您现在应该能够承担**管理员**角色。

要使用 AWS 控制台承担管理员角色，请点击下拉菜单，选择**切换角色**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7579bba8-fdb1-4462-a458-03ea1392ffe7.png)切换角色

点击**切换角色**按钮后，您将被提示输入帐户 ID 或名称，以及您想要在配置帐户中承担的角色：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b934817f-04fb-44ab-8a4b-ba8ad803e9a3.png)切换角色

您现在应该注意到 AWS 控制台的标题指示您必须承担管理员角色，现在您已经完全具有对 AWS 帐户的管理访问权限。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/582a79e0-cc9d-45da-ab8f-8e273dcb2a0a.png)承担管理员角色在本书的其余部分中，每当您需要在您的帐户中执行管理任务时，我将假定您已经承担了管理员角色，就像在之前的屏幕截图中演示的那样。

# 创建 EC2 密钥对

如果您打算在 AWS 帐户中运行任何 EC2 实例，那么需要完成的一个关键设置任务就是建立一个或多个 EC2 密钥对，对于 Linux EC2 实例，可以用来定义一个 SSH 密钥对，以授予对 EC2 实例的 SSH 访问。

当您创建 EC2 密钥对时，将自动生成一个 SSH 公钥/私钥对，其中 SSH 公钥将作为命名的 EC2 密钥对存储在 AWS 中，并相应的 SSH 私钥下载到您的本地客户端。如果随后创建任何 EC2 实例并在实例创建时引用命名的 EC2 密钥对，您将能够自动使用相关的 SSH 私钥访问您的 EC2 实例。

访问 Linux EC2 实例的 SSH 需要您使用与配置的 EC2 密钥对关联的 SSH 私钥，并且还需要适当的网络配置和安全组，以允许从您的 SSH 客户端所在的任何位置访问 EC2 实例的 SSH 端口。

要创建 EC2 密钥对，首先在 AWS 控制台中导航到**服务| EC2**，从左侧菜单中的**网络和安全**部分中选择**密钥对**，然后单击**创建密钥对**按钮：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/52541551-506e-42ce-9fdf-02cfa8b5a6f9.png)

在这里，您已配置了一个名为 admin 的 EC2 密钥对名称，并在单击“创建”按钮后，将创建一个新的 EC2 密钥对，并将 SSH 私钥下载到您的计算机：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b793d0f0-fcb8-4f02-9283-228dcf9a540b.png)

此时，您需要将 SSH 私钥移动到计算机上的适当位置，并按下面的示例修改私钥文件的默认权限：

```
> mv ~/Downloads/admin.pem ~/.ssh/admin.pem
> chmod 600 ~/.ssh/admin.pem
```

请注意，如果您不使用 chmod 命令修改权限，当您尝试使用 SSH 密钥时，将会出现以下错误：

```
> ssh -i ~/.ssh/admin.pem 192.0.2.1
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@ WARNING: UNPROTECTED PRIVATE KEY FILE! @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '/Users/jmenga/.ssh/admin.pem' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "/Users/jmenga/.ssh/admin.pem": bad permissions
```

# 使用 AWS CLI

到目前为止，在本章中，您只与 AWS 控制台进行了交互，该控制台可以从您的 Web 浏览器访问。虽然拥有 AWS 控制台访问权限非常有用，但在许多情况下，您可能更喜欢使用命令行工具，特别是在需要自动化关键操作和部署任务的情况下。

# 安装 AWS CLI

AWS CLI 是用 Python 编写的，因此您必须安装 Python 2 或 Python 3，以及 PIP Python 软件包管理器。

本书中使用的说明和示例假定您使用的是 MacOS 或 Linux 环境。

有关如何在 Windows 上设置 AWS CLI 的说明，请参阅[`docs.aws.amazon.com/cli/latest/userguide/awscli-install-windows.html`](https://docs.aws.amazon.com/cli/latest/userguide/awscli-install-windows.html)。

假设您已满足这些先决条件，您可以在终端中使用`pip`命令安装 AWS CLI，并使用`--upgrade`标志升级到最新的 AWS CLI 版本（如果已安装），并使用`--user`标志避免修改系统库：

```
> pip install awscli --upgrade --user
Collecting awscli
  Downloading https://files.pythonhosted.org/packages/69/18/d0c904221d14c45098da04de5e5b74a6effffb90c2b002bc2051fd59222e/awscli-1.15.45-py2.py3-none-any.whl (1.3MB)
    100% |████████████████████████████████| 1.3MB 1.2MB/s
...
...
Successfully installed awscli-1.15.45 botocore-1.10.45 colorama-0.3.9 pyasn1-0.4.3 python-dateutil-2.7.3
```

根据您的环境，如果您使用的是 Python 3，您可能需要用`pip3 install`命令替换`pip install`。

如果您现在尝试运行 AWS CLI 命令，该命令将失败，并指示您必须配置您的环境：

```
> aws ec2 describe-vpcs
You must specify a region. You can also configure your region by running "aws configure".
```

# 创建 AWS 访问密钥

如果您按照前面的代码建议运行`aws configure`命令，将提示您输入 AWS 访问密钥 ID：

```
> aws configure
AWS Access Key ID [None]:
```

要使用 AWS CLI 和 AWS SDK，您必须创建 AWS 访问密钥，这是由访问密钥 ID 和秘密访问密钥值组成的凭据。要创建访问密钥，请在 AWS 控制台中打开 IAM 仪表板，从左侧菜单中选择**用户**，然后单击您的用户名。在**安全凭据**选项卡下的**访问密钥**部分，单击**创建访问密钥**按钮，这将打开一个对话框，允许您查看访问密钥 ID 和秘密访问密钥值：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/fcc8616b-3a14-43ac-8b78-b7449ca7fc29.png)访问密钥凭证

记下访问密钥 ID 和秘密访问密钥值，因为您将需要这些值来配置您的本地环境。

# 配置 AWS CLI

回到您的终端，现在您可以完成`aws configure`设置过程：

```
> aws configure
AWS Access Key ID [None]: AKIAJXNI5XLCSBRQAZCA
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1
Default output format [None]:
```

如果您现在尝试运行之前尝试过的`aws ec2 describe-vpcs`命令，该命令仍然失败；但是，错误是不同的：

```
> aws ec2 describe-vpcs

An error occurred (UnauthorizedOperation) when calling the DescribeVpcs operation: You are not authorized to perform this operation.
```

现在的问题是，您未被授权执行此命令，因为您刚刚创建的访问密钥与您的用户帐户相关联，您必须假定管理员角色以获得管理特权。

# 配置 AWS CLI 以假定角色

此时，AWS CLI 正在以您的用户帐户的上下文中运行，您需要配置 CLI 以假定管理员角色以能够执行任何有用的操作。

当您运行`aws configure`命令时，AWS CLI 在名为`.aws`的文件夹中创建了两个重要文件，该文件夹位于您的主目录中：

```
> ls -l ~/.aws

total 16
-rw------- 1 jmenga staff 29  23 Jun 19:31 config
-rw------- 1 jmenga staff 116 23 Jun 19:31 credentials
```

`credentials`文件保存了一个或多个命名配置文件中的 AWS 凭据：

```
> cat ~/.aws/credentials
[default]
aws_access_key_id = AKIAJXNI5XLCSBRQAZCA
aws_secret_access_key = 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
```

在上述代码中，请注意`aws configure`命令创建了一个名为`default`的配置文件，并将访问密钥 ID 和秘密访问密钥值存储在该文件中。作为最佳实践，特别是如果您正在使用多个 AWS 账户，我建议避免使用默认配置文件，因为如果输入 AWS CLI 命令，AWS CLI 将默认使用此配置文件。您很快将学会如何使用命名配置文件来处理多个 AWS 账户，如果您有一个默认配置文件，很容易忘记指定要使用的配置文件，并在默认配置文件引用的账户中意外执行操作。我更喜欢根据您正在使用的账户的名称命名每个配置文件，例如，在这里，我已将凭据文件中的默认配置文件重命名为`docker-in-aws`，因为我将我的 AWS 账户命名为`docker-in-aws`：

```
[docker-in-aws]
aws_access_key_id = AKIAJXNI5XLCSBRQAZCA
aws_secret_access_key = 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
```

AWS CLI 创建的另一个文件是`~/.aws/config`文件，如下所示：

```
[default]
region = us-east-1
```

该文件包括命名的配置文件，并且因为您在运行`aws configure`命令时指定了默认区域，所以`default`配置文件中已经添加了`region`变量。配置文件支持许多变量，允许您执行更高级的任务，比如自动假定角色，因此这就是我们需要配置 CLI 以假定我们在本章前面创建的`admin`角色的地方。鉴于我们已经在`credentials`文件中重命名了`default`配置文件，以下代码演示了将`default`配置文件重命名为`docker-in-aws`并添加支持假定`admin`角色的操作：

```
[profile docker-in-aws]
source_profile = docker-in-aws
role_arn = arn:aws:iam::385605022855:role/admin
role_session_name=justin.menga
mfa_serial = arn:aws:iam::385605022855:mfa/justin.menga
region = us-east-1
```

请注意，在配置命名配置文件时，我们在配置文件名前面添加了`profile`关键字，这是必需的。我们还在配置文件中配置了许多变量：

+   `source_profile`：这是应该用于获取凭据的凭据配置文件。我们指定`docker-in-aws`，因为我们之前已将凭据文件中的配置文件重命名为`docker-in-aws`。

+   `role_arn`：这是要假定的 IAM 角色的 ARN。在这里，您指定了您在上一个截图中创建的`admin`角色的 ARN。

+   `role_session_name`：这是在承担配置的角色时创建的临时会话的名称。作为最佳实践，您应该指定您的 IAM 用户名，因为这有助于审计您使用角色执行的任何操作。当您使用承担的角色在 AWS 中执行操作时，您的身份实际上是`arn:aws:sts::<account-id>:assumed-role/<role-name>/<role-session-name>`，因此将用户名设置为角色会话名称可以确保可以轻松确定执行操作的用户。

+   `mfa_serial`：这是应该用于承担角色的 MFA 设备的 ARN。鉴于您的 IAM 用户属于用户组，对于所有操作，包括通过 AWS CLI 或 SDK 进行的任何 API 调用，都需要 MFA。通过配置此变量，AWS CLI 将在尝试承担配置的角色之前自动提示您输入 MFA 代码。您可以在 IAM 用户帐户的安全凭据选项卡中获取 MFA 设备的 ARN（请参阅分配的 MFA 设备字段，但它将始终遵循`arn:aws:iam::<account-id>:mfa/<user-id>`的命名约定）。

有关支持凭据和配置文件中的所有变量的完整描述，请参阅[`docs.aws.amazon.com/cli/latest/topic/config-vars.html`](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html)。

# 配置 AWS CLI 以使用命名配置文件

有了配置，您就不再有默认配置文件，因此运行 AWS CLI 将返回相同的输出。要使用命名配置文件，您有两个选项：

+   在 AWS CLI 命令中使用`--profile`标志指定配置文件名称。

+   在名为`AWS_PROFILE`的环境变量中指定配置文件名称。这是我首选的机制，我将假设您在本书中一直采用这种方法。

上面的代码演示了使用这两种方法：

```
> aws ec2 describe-vpcs --profile docker-in-aws
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga: ****
{
    "Vpcs": [
        {
            "VpcId": "vpc-f8233a80",
            "InstanceTenancy": "default",
            "CidrBlockAssociationSet": [
                {
                    "AssociationId": "vpc-cidr-assoc-32524958",
                    "CidrBlock": "172.31.0.0/16",
                    "CidrBlockState": {
                        "State": "associated"
                    }
                }
            ],
            "State": "available",
            "DhcpOptionsId": "dopt-a037f9d8",
            "CidrBlock": "172.31.0.0/16",
            "IsDefault": true
        }
    ]
}
> export AWS_PROFILE=docker-in-aws
> aws ec2 describe-vpcs --query Vpcs[].VpcId
[
    "vpc-f8233a80"
]
```

在上面的示例中，请注意当您首次运行`aws`命令时，会提示您输入 MFA 令牌，但是当您下次运行该命令时，将不会提示您。这是因为默认情况下，从承担角色获取的临时会话凭据在一个小时内有效，并且 AWS CLI 会缓存凭据，以便您在不必在每次执行命令时刷新凭据的情况下重用它们。当然，在一个小时后，由于临时会话凭据将会过期，您将再次被提示输入 MFA 令牌。

在前面的代码中，还有一个有趣的地方需要注意，就是在最后一个命令示例中使用了`--query`标志。这允许您指定一个 JMESPath 查询，这是一种用于查询 JSON 数据结构的查询语言。AWS CLI 默认输出 JSON，因此您可以使用查询从 AWS CLI 输出中提取特定信息。在本书中，我将经常使用这些查询的示例，您可以在[`jmespath.org/tutorial.html`](http://jmespath.org/tutorial.html)上阅读更多关于 JMESPath 查询语言的信息。

# AWS CloudFormation 简介

**AWS CloudFormation**是一项托管的 AWS 服务，允许您使用基础架构即代码来定义 AWS 服务和资源，并且是使用 AWS 控制台、CLI 或各种 SDK 部署 AWS 基础架构的替代方案。虽然需要一些学习曲线来掌握 CloudFormation，但一旦掌握了使用 CloudFormation 的基础知识，它就代表了一种非常强大的部署 AWS 基础架构的方法，特别是一旦开始部署复杂的环境。

在使用 CloudFormation 时，您可以在 CloudFormation 模板中定义一个或多个资源，这是一种将相关资源组合在一个地方的便捷机制。当您部署模板时，CloudFormation 将创建一个包含在模板中定义的物理资源的*堆栈*。CloudFormation 将部署每个资源，自动确定每个资源之间的任何依赖关系，并优化部署，以便在适用的情况下可以并行部署资源，或者在资源之间存在依赖关系时按正确的顺序部署资源。最好的消息是，所有这些强大的功能都是免费的 - 您只需要在通过 CloudFormation 部署堆栈时支付您消耗的资源。

需要注意的是，有许多第三方替代方案可以替代 CloudFormation - 例如，Terraform 非常受欢迎，传统的配置管理工具如 Ansible 和 Puppet 也包括部署 AWS 资源的支持。我个人最喜欢的是 CloudFormation，因为它得到了 AWS 的原生支持，对各种 AWS 服务和资源有很好的支持，并且与 AWS CLI 和 CodePipeline 等服务进行了原生集成（我们将在本书的第十三章“持续交付 ECS 应用程序”中利用这种集成）。

# 定义 CloudFormation 模板

使用 CloudFormation 的最简单方法是创建一个 CloudFormation 模板。该模板以 JSON 或 YAML 格式定义，我建议使用 YAML 格式，因为相比 JSON，YAML 更容易让人类操作。

[CloudFormation 用户指南](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)详细描述了[模板结构](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html)，但是出于本书的目的，我们只需要关注一个基本的模板结构，最好通过一个真实的例子来演示，您可以将其保存在计算机上一个方便的位置的名为`stack.yml`的文件中。

```
AWSTemplateFormatVersion: "2010-09-09"

Description: Cloud9 Management Station

Parameters:
 EC2InstanceType:
   Type: String
   Description: EC2 instance type
   Default: t2.micro
 SubnetId:
   Type: AWS::EC2::Subnet::Id
   Description: Target subnet for instance

Resources:
  ManagementStation:
    Type: AWS::Cloud9::EnvironmentEC2
    Properties:
      Name: !Sub ${AWS::StackName}-station
      Description:
        Fn::Sub: ${AWS::StackName} Station
      AutomaticStopTimeMinutes: 15
```

```
      InstanceType: !Ref EC2InstanceType
      SubnetId:
        Ref: SubnetId
```

在上述代码中，CloudFormation 定义了一个 Cloud9 管理站 - Cloud9 提供基于云的 IDE 和终端，在 EC2 实例上运行。让我们通过这个例子来讨论模板的结构和特性。

`AWSTemplateFormatVersion`属性是必需的，它指定了 CloudFormation 模板的格式版本，通常以日期形式表示。`Parameters`属性定义了一组输入参数，您可以将这些参数提供给您的模板，这是处理多个环境的好方法，因为您可能在每个环境之间有不同的输入值。例如，`EC2InstanceType`参数指定了管理站的 EC2 实例类型，而`SubnetId`参数指定了 EC2 实例应连接到的子网。这两个值在非生产环境和生产环境之间可能不同，因此将它们作为输入参数使得根据目标环境更容易更改。请注意，`SubnetId`参数指定了`AWS::EC2::Subnet::Id`类型，这意味着 CloudFormation 可以使用它来查找或验证输入值。有关支持的参数类型列表，请参见[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html)。您还可以看到`EC2InstanceType`参数为参数定义了默认值，如果没有为此参数提供输入，则将使用该默认值。

`Resources`属性定义了堆栈中的所有资源 - 这实际上是模板的主体部分，可能包含多达两百个资源。在上面的代码中，我们只定义了一个名为`ManagementStation`的资源，这将创建 Cloud9 EC2 环境，其`Type`值为`AWS::Cloud9::EnvironmentEC2`。所有资源必须指定一个`Type`属性，该属性定义了资源的类型，并确定了每种类型可用的各种配置属性。CloudFormation 用户指南包括一个定义了所有支持的资源类型的部分，截至最后一次统计，有 300 种不同类型的资源。

每个资源还包括一个 Properties 属性，其中包含资源可用的所有各种配置属性。在上面的代码中，您可以看到我们定义了五个不同的属性 - 可用的属性将根据资源类型而变化，并在 CloudFormation 用户指南中得到充分的文档记录。

+   `名称`：这指定了 Cloud9 EC2 环境的名称。属性的值可以是简单的标量值，比如字符串或数字，但是值也可以引用模板中的其他参数或资源。请注意，`Name`属性的值包括所谓的内置函数`Sub`，可以通过前面的感叹号(`!Sub`)来识别。`!Sub`语法实际上是`Fn::Sub`的简写，你可以在`Description`属性中看到一个例子。`Fn::Sub`内置函数允许您定义一个表达式，其中包括对堆栈中其他资源或参数的插值引用。例如，`Name`属性的值是`${AWS::StackName}-station`，其中`${AWS::StackName}`是一个称为[伪参数](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/pseudo-parameter-reference.html)的插值引用，它将被模板部署时的 CloudFormation 堆栈的名称替换。如果您的堆栈名称是`cloud9-management`，那么`${AWS::StackName}-station`的值在部署堆栈时将扩展为`cloud9-management-station`。

+   `Description`: 这为 Cloud9 EC2 环境提供了描述。这包括`Fn::Sub`内部函数的长格式示例，该函数要求您缩进一个新行，而简写的`!Sub`格式允许您在同一行上指定值。

+   `AutomaticStopTime`: 这定义了在停止 Cloud9 EC2 实例之前等待的空闲时间，单位为分钟。这可以节省成本，但只有在您使用 EC2 实例时才会运行（Cloud9 将自动启动您的实例，并从您之前停止的地方恢复会话）。在上面的代码中，该值是一个简单的标量值为 15。

+   `InstanceType`: 这是 EC2 实例的类型。这引用了`EC2InstanceType`参数，使用了 Ref 内部函数（`!Ref`是简写形式），允许您引用堆栈中的其他参数或资源。这意味着在部署堆栈时为此参数提供的任何值都将应用于`InstanceType`属性。

+   `SubnetId`: 这是 EC2 实例将部署的目标子网 ID。此属性引用了 SubnetID 参数，使用了`Ref`内部函数的长格式，这要求您在缩进的新行上表达此引用。

# 部署 CloudFormation 堆栈

现在您已经定义了一个 CloudFormation 模板，可以以 CloudFormation 堆栈的形式部署模板中的资源。

您可以通过选择**服务** | **CloudFormation**在 AWS 控制台上部署堆栈，这将打开 CloudFormation 仪表板。在继续之前，请确保您已经在您的帐户中扮演了管理员角色，并且还选择了美国东部北弗吉尼亚（us-east-1）作为地区：

在本书的所有示例中，我们将使用美国东部北弗吉尼亚（us-east-1）地区。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6aec5bab-afe5-4795-ac18-1c6681e28289.png)CloudFormation 仪表板

如果单击**创建新堆栈**按钮，将提示您选择模板，您可以选择示例模板、上传模板或指定 S3 模板 URL。因为我们在名为`stack.yml`的文件中定义了我们的堆栈，所以选择上传模板的选项，并单击**选择文件**按钮选择计算机上的文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/38367206-84db-4a54-8043-fe8aa6613cef.png)选择 CloudFormation 模板

上传模板后，CloudFormation 服务将解析模板并要求您为堆栈指定名称，并为堆栈中的任何参数提供值：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/65e6ca0f-052d-4840-96b2-503e43d49863.png)指定模板详细信息

在上述截图中，默认情况下为`EC2InstanceType`参数设置了值`t2.micro`，因为您在模板中将其设置为默认值。由于您将`AWS::EC2::Subnet::Id`指定为`SubnetId`参数的类型，**创建堆栈**向导会自动查找您帐户和区域中的所有子网，并在下拉菜单中呈现它们。在这里，我选择了位于**us-east-1a**可用区的每个新 AWS 帐户中创建的默认 VPC 中的子网。

您可以通过在 AWS 控制台中选择**服务**|**VPC**|**子网**，或者通过运行带有 JMESPath 查询的`aws ec2 describe-subnets` AWS CLI 命令来确定每个子网属于哪个可用区：

```
> aws ec2 describe-subnets --query 'Subnets[].[SubnetId,AvailabilityZone,CidrBlock]' \
    --output table
-----------------------------------------------------
| DescribeSubnets                                   |
+-----------------+--------------+------------------+
| subnet-a5d3ecee | us-east-1a   | 172.31.16.0/20   |
| subnet-c2abdded | us-east-1d   | 172.31.80.0/20   |
| subnet-aae11aa5 | us-east-1f   | 172.31.48.0/20   |
| subnet-fd3a43c2 | us-east-1e   | 172.31.64.0/20   |
| subnet-324e246f | us-east-1b   | 172.31.32.0/20   |
| subnet-d281a2b6 | us-east-1c   | 172.31.0.0/20    |
+-----------------+--------------+------------------+
```

此时，您可以单击**下一步**，然后在**创建堆栈**向导中单击**创建**，以开始部署新堆栈。在 CloudFormation 仪表板中，您将看到创建了一个名为**cloud9-management**的新堆栈，最初状态为`CREATE_IN_PROGRESS`。通过 CloudFormation 部署 Cloud9 环境的一个有趣行为是，通过`AWS::Cloud9::Environment`资源会自动创建一个单独的子 CloudFormation 堆栈，这在部署其他类型的 CloudFormation 资源时是不太常见的。部署完成后，堆栈的状态将变为`CREATE_COMPLETE`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/de0f7e1f-35bc-47aa-8df0-7bebfa06bb1f.png)部署 CloudFormation 堆栈

在上述截图中，您可以单击**事件**选项卡以显示与堆栈部署相关的事件。这将显示每个资源部署的进度，并指示是否存在任何失败。

现在您已成功部署了第一个 CloudFormation 堆栈，您应该可以使用全新的 Cloud9 IDE 环境。如果您在 AWS 控制台菜单栏中选择**服务**|**Cloud9**，您应该会看到一个名为`cloud9-management-station`的单个环境：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/bf94b2a5-6146-44ae-a0ed-3de38549d0ea.png)Cloud9 环境

如果单击**打开 IDE**按钮，这将打开一个包含安装了 AWS CLI 的集成终端的新 IDE 会话。请注意，会话具有创建 Cloud9 环境的用户关联的所有权限 - 在本例中，这是假定的**admin**角色，因此您可以从终端执行任何管理任务。Cloud9 环境也在您的 VPC 中运行，因此，如果您部署其他资源（如 EC2 实例），即使您的其他资源部署在没有互联网连接的私有子网中，您也可以从此环境本地管理它们。

确保您了解创建具有完全管理特权的 Cloud9 环境的影响。尽管这非常方便，但它确实代表了一个潜在的安全后门，可能被用来破坏您的环境和帐户。Cloud9 还允许您与其他用户共享您的 IDE，这可能允许其他用户冒充您并执行您被允许执行的任何操作。 ![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/47bf21c4-dc4c-45a7-800a-25ed9098cff3.png)Cloud9 IDE

# 更新 CloudFormation 堆栈

创建 CloudFormation 堆栈后，您可能希望对堆栈进行更改，例如添加其他资源或更改现有资源的配置。 CloudFormation 定义了与堆栈相关的三个关键生命周期事件 - CREATE，UPDATE 和 DELETE - 这些事件可以应用于堆栈中的单个资源，也可以应用于整个堆栈。

要更新堆栈，只需对 CloudFormation 模板进行任何必要的更改，并提交修改后的模板 - CloudFormation 服务将计算每个资源所需的更改，这可能导致创建新资源，更新或替换现有资源，或删除现有资源。 CloudFormation 还将首先进行任何新更改，仅当这些更改成功时，它才会清理应该被移除的任何资源。这提供了在 CloudFormation 堆栈更新失败的情况下恢复的更高机会，在这种情况下，CloudFormation 将尝试回滚更改以将堆栈恢复到其原始状态。

要测试更新您的 CloudFormation 堆栈，让我们对`stack.yml`模板进行小的更改：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: Cloud9 Management Station

Parameters:
  EC2InstanceType:
    Type: String
    Description: EC2 instance type
    Default: t2.micro
  SubnetId:
    Type: AWS::EC2::Subnet::Id
    Description: Target subnet for instance

```

```
Resources:
  ManagementStation:
    Type: AWS::Cloud9::EnvironmentEC2
    Properties:
      Name: !Sub ${AWS::StackName}-station
      Description:
        Fn::Sub: ${AWS::StackName} Station
 AutomaticStopTimeMinutes: 20
      InstanceType: !Ref EC2InstanceType
      SubnetId:
        Ref: SubnetId
```

应用此更改，我们将使用 AWS CLI 而不是使用 AWS 控制台，AWS CLI 支持通过`aws cloudformation deploy`命令部署 CloudFormation 模板。我们将在本书的其余部分大量使用此命令，现在是介绍该命令的好时机：

```
> export AWS_PROFILE=docker-in-aws
> aws cloudformation deploy --stack-name cloud9-management --template-file stack.yml \
--parameter-overrides SubnetId=subnet-a5d3ecee
Enter MFA code for arn:aws:iam::385605022855:mfa/justin.menga: ****

Waiting for changeset to be created..
Waiting for stack create/update to complete

Failed to create/update the stack. Run the following command
to fetch the list of events leading up to the failure
aws cloudformation describe-stack-events --stack-name cloud9-management
```

在上述代码中，我们首先确保配置了正确的配置文件，然后运行`aws cloudformation deploy`命令，使用`--stack-name`标志指定堆栈名称和`--template-file`标志指定模板文件。`--parameter-overrides`标志允许您以`<parameter>=<value>`格式提供输入参数值-请注意，在像这样的更新场景中，如果您不指定任何参数覆盖，将使用先前提供的参数值（在本例中创建堆栈时）。

请注意，更新实际上失败了，如果您通过 CloudFormation 控制台查看堆栈事件，您可以找出堆栈更新失败的原因。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/74b208ac-b2b6-4b7d-8dd4-d59eaaa6da1c.png)CloudFormation 堆栈更新失败

在上述屏幕截图中，您可以看到堆栈更新失败，因为更改需要 CloudFormation 创建并替换现有资源（在本例中为 Cloud9 环境）为新资源。由于 CloudFormation 始终在销毁任何已被替换的旧资源之前尝试创建新资源，因为资源配置了名称，CloudFormation 无法使用相同名称创建新资源，导致失败。这突显了 CloudFormation 的一个重要注意事项-在定义资源的静态名称时要非常小心-如果 CloudFormation 需要在像这样的更新场景中替换资源，更新将失败，因为通常资源名称必须是唯一的。

有关 CloudFormation 何时选择替换资源（如果正在更新资源），请参考[Amazon Web Services 资源类型参考](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html)文档中为每种资源类型定义的资源属性。

您可以看到，CloudFormation 在失败后会自动回滚更改，撤消导致失败的任何更改。堆栈的状态最终会更改为`UPDATE_ROLLBACK_COMPLETE`，表示发生了失败和回滚。

解决堆栈失败的一个修复方法是在堆栈中的`ManagementStation`资源上删除`Name`属性 - 在这种情况下，CloudFormation 将确保生成一个唯一的名称（通常基于 CloudFormation 堆栈名称并附加一些随机的字母数字字符），这意味着每次更新资源以便需要替换时，CloudFormation 将简单地生成一个新的唯一名称并避免我们遇到的失败场景。

# 删除 CloudFormation 堆栈

现在您了解了如何创建和更新堆栈，让我们讨论如何删除堆栈。您可以通过 CloudFormation 仪表板非常轻松地删除堆栈，只需选择堆栈，选择**操作**，然后点击**删除堆栈**：

删除 CloudFormation 堆栈

点击**是，删除**以确认删除堆栈后，CloudFormation 将继续删除堆栈中定义的每个资源。完成后，堆栈将从 CloudFormation 仪表板中消失，尽管您可以更改位于**创建堆栈**按钮下方的**筛选器**下拉菜单，以点击**已删除**以查看以前删除的堆栈。

有人可能会认为删除堆栈太容易了。如果您担心意外删除堆栈，您可以在前面的截图中选择**更改终止保护**选项以启用终止保护，这将防止堆栈被意外删除。

# 摘要

在本章中，您学习了如何通过创建免费账户和建立账户的根用户来开始使用 AWS。您学会了如何使用多因素身份验证来保护根访问权限，然后创建了一些 IAM 资源，这些资源是管理您的账户所必需的。您首先创建了一个名为**admin**的管理 IAM 角色，然后创建了一个管理员组，将其分配为允许假定您的管理 IAM 角色的单一权限。假定角色的这种方法是管理 AWS 的推荐和最佳实践方法，并支持更复杂的多账户拓扑结构，在这种结构中，您可以将所有 IAM 用户托管在一个账户中，并在其他账户中假定管理角色。

然后，您创建了一个用户组，并分配了一个托管策略，该策略强制要求属于该组的任何用户进行多因素身份验证（MFA）。MFA 现在应被视为任何使用 AWS 的组织的强制性安全要求，简单地将用户分配到强制执行 MFA 要求的用户组是一种非常简单和可扩展的机制来实现这一点。创建用户并将其分配到管理员和用户组后，您学会了首次用户设置其访问所需的步骤，其中包括使用一次性密码登录，建立新密码，然后设置 MFA 设备。一旦用户使用 MFA 登录，用户就能执行分配给他们的任何权限 - 例如，您在本章中创建的用户被分配到了管理员组，因此能够承担管理员 IAM 角色，您可以在 AWS 控制台中使用内置的 Switch Role 功能执行此操作。

随着您的 IAM 设置完成并能够通过控制台承担管理员角色，我们接下来将注意力转向命令行，安装 AWS CLI，通过控制台生成访问密钥，然后在本地`~/.aws`文件夹中配置您的访问密钥凭据，该文件夹由 AWS CLI 用于存储凭据和配置文件。您学会了如何在`~/.aws/configuration`文件中配置命名配置文件，该文件会自动承担管理员角色，并在 CLI 检测到需要新的临时会话凭据时提示输入 MFA 代码。您还创建了一个 EC2 密钥对，以便您可以使用 SSH 访问 EC2 实例。

最后，您了解了 AWS CloudFormation，并学会了如何定义 CloudFormation 模板并部署 CloudFormation 堆栈，这是基于您的 CloudFormation 模板定义的资源集合。您学会了 CloudFormation 模板的基本结构，如何使用 AWS 控制台创建堆栈，以及如何使用 AWS CLI 部署堆栈。

在下一章中，您将介绍弹性容器服务，您将充分利用您的新 AWS 账户，并学习如何创建 ECS 集群并将 Docker 应用程序部署到 ECS。

# 问题

1.  真/假：建立免费的 AWS 账户需要一个有效的信用卡。

1.  正确/错误：您应该始终使用根帐户执行管理操作。

1.  正确/错误：您应该直接为 IAM 用户和/或组分配 IAM 权限。

1.  您将使用哪个 IAM 托管策略来分配管理权限？

1.  您运行什么命令来安装 AWS CLI？

1.  正确/错误：当您配置 AWS CLI 时，您必须在本地存储您的 IAM 用户名和密码。

1.  您在哪里存储 AWS CLI 的凭据？

1.  您设置了一个需要 MFA 才能执行管理操作的 IAM 用户。IAM 用户设置了他们的 AWS CLI，但在尝试运行 AWS CLI 命令时抱怨未经授权的错误。命名配置文件包括`source_profile`，`role_arn`和`role_session_name`参数，并且您确认这些已正确配置。您将如何解决这个问题？

1.  正确/错误：CloudFormation 模板可以使用 JSON 或 YAML 编写。

1.  正确/错误：您可以使用`!Ref`关键字来引用 CloudFormation 模板中的另一个资源或参数。

1.  您在 CloudFormation 模板中定义了一个资源，其中包括一个可选的`Name`属性，您将其配置为`my-resource`。您成功从模板创建了一个新堆栈，然后对文档中规定将需要替换整个资源的资源进行了更改。您能成功部署这个更改吗？

# 进一步阅读

您可以查看以下链接，了解本章涵盖的主题的更多信息：

+   设置免费层帐户：[`aws.amazon.com/free`](https://aws.amazon.com/free)

+   IAM 最佳实践：[`docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

+   您的 AWS 帐户 ID 和别名：[`docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/console_account-alias.html)

+   改进 AWS Force MFA 策略：[`www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/`](https://www.trek10.com/blog/improving-the-aws-force-mfa-policy-for-IAM-users/)

+   安装 AWS CLI：[`docs.aws.amazon.com/cli/latest/userguide/installing.html`](https://docs.aws.amazon.com/cli/latest/userguide/installing.html)

+   AWS CLI 参考：[`docs.aws.amazon.com/cli/latest/reference/`](https://docs.aws.amazon.com/cli/latest/reference/)

+   AWS CLI 配置变量：[`docs.aws.amazon.com/cli/latest/topic/config-vars.html`](https://docs.aws.amazon.com/cli/latest/topic/config-vars.html)

+   AWS shell：[`github.com/awslabs/aws-shell`](https://github.com/awslabs/aws-shell)

+   AWS CloudFormation 用户指南：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)

+   AWS CloudFormation 模板解剖：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html)

+   AWS CloudFormation 资源类型参考：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html)

+   AWS CloudFormation 内部函数：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference.html)

+   AWS CloudFormation 伪参数：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/pseudo-parameter-reference.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/pseudo-parameter-reference.html)


# 第四章：ECS 简介

弹性容器服务（ECS）是一项流行的 AWS 托管服务，为您的应用程序提供容器编排，并与各种 AWS 服务和工具集成。

在本章中，您将学习 ECS 的关键概念；ECS 的架构方式，并了解 ECS 的各个组件，包括弹性容器注册表（ECR），ECS 集群，ECS 容器实例，ECS 任务定义，ECS 任务和 ECS 服务。本章的重点将是使用 AWS 控制台创建您的第一个 ECS 集群，定义 ECS 任务定义，并配置 ECS 服务以部署您的第一个容器应用程序到 ECS。您将更仔细地了解 ECS 集群是如何由 ECS 容器实例形成的，并检查 ECS 容器实例的内部，以进一步了解 ECS 如何与您的基础架构连接以及如何部署和管理容器。最后，您将介绍 ECS 命令行界面（CLI），这是一个有用的工具，可以快速搭建 ECS 集群，任务定义和服务，它使用流行的 Docker Compose 格式来定义您的容器和服务。

将涵盖以下主题：

+   ECS 架构

+   创建 ECS 集群

+   理解 ECS 容器实例

+   创建 ECS 任务定义

+   创建 ECS 服务

+   部署 ECS 服务

+   运行 ECS 任务

+   使用 ECS CLI

# 技术要求

以下是完成本章所需的技术要求：

+   Docker Engine 18.06 或更高版本

+   Docker Compose 1.22 或更高版本

+   jq

+   对 AWS 账户的管理员访问权限

+   根据第三章的说明配置本地 AWS 配置文件

+   在第二章中配置的示例应用程序的工作 Docker 工作流程（请参阅[`github.com/docker-in-aws/docker-in-aws/tree/master/ch2`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch2)）。

以下 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch4`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch4)。

查看以下视频以查看代码实际操作：

[`bit.ly/2MTG1n3`](http://bit.ly/2MTG1n3)

# ECS 架构

ECS 是 AWS 托管服务，为您提供了构建在 AWS 中部署和操作容器应用程序的核心构建块。

在 2017 年 12 月之前，弹性容器服务被称为 EC2 容器服务。

ECS 允许您：

+   构建和发布您的 Docker 镜像到私有仓库

+   创建描述容器镜像、配置和运行应用程序所需资源的定义。

+   使用您自己的 EC2 基础设施或使用 AWS 托管基础设施启动和运行您的容器

+   管理和监视您的容器

+   编排滚动部署新版本或修订您的容器应用程序

为了提供这些功能，ECS 包括以下图表中说明的一些组件，并在下表中描述：

| 组件 | 描述 |
| --- | --- |
| 弹性容器注册表（ECR） | 提供安全的私有 Docker 镜像仓库，您可以在其中发布和拉取您的 Docker 镜像。我们将在第五章中深入研究 ECR，*使用 ECR 发布 Docker 镜像*。 |
| ECS 集群 | 运行您的容器应用程序的 ECS 容器实例的集合。 |
| ECS 容器实例 | 运行 Docker 引擎和 ECS 代理的 EC2 实例，该代理与 AWS ECS 服务通信，并允许 ECS 管理容器应用程序的生命周期。每个 ECS 容器实例都加入到单个 ECS 集群中。 |
| ECS 代理 | 以 Docker 容器的形式运行的软件组件，与 AWS ECS 服务通信。代理负责代表 ECS 管理 Docker 引擎，从注册表中拉取 Docker 镜像，启动和停止 ECS 任务，并向 ECS 发布指标。 |
| ECS 任务定义 | 定义组成您的应用程序的一个或多个容器和相关资源。每个容器定义包括指定容器镜像、应分配给容器的 CPU 和内存量、运行时环境变量等许多配置选项的信息。 |
| ECS 任务 | ECS 任务是 ECS 任务定义的运行时表现，代表在给定 ECS 集群上运行的任务定义中定义的容器。ECS 任务可以作为短暂的临时任务运行，也可以作为长期任务运行，这些任务是 ECS 服务的构建块。 |
| ECS 服务 | ECS 服务定义了在给定的 ECS 集群上运行的一个或多个长期运行的 ECS 任务实例，并代表您通常会考虑为您的应用程序或微服务实例。ECS 服务定义了一个 ECS 任务定义，针对一个 ECS 集群，并且还包括一个期望的计数，它定义了与服务关联的基于 ECS 任务定义的实例或 ECS 任务的数量。您的 ECS 服务可以与 AWS 弹性负载均衡服务集成，这允许您为您的 ECS 服务提供高可用的、负载均衡的服务端点，并且还支持新版本应用程序的滚动部署。 |
| AWS ECS | 管理 ECS 架构中的所有组件。提供管理 ECS 代理的服务端点，与其他 AWS 服务集成，并允许客户管理其 ECR 存储库、ECS 任务定义和 ECS 集群。 |

随着我们在本章中的进展，参考以下图表以获得各种 ECS 组件之间关系的视觉概述。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/25c1eaac-981b-4035-b59d-dda3353e1607.png)ECS 架构

# 创建 ECS 集群

为了帮助您了解 ECS 的基础知识，我们将通过 AWS 控制台逐步进行一系列配置任务。

我们首先将创建一个 ECS 集群，这是一组将运行您的容器应用程序的 ECS 容器实例，并且通常与 EC2 自动扩展组密切相关，如下图所示。

可以通过以下步骤执行创建 ECS 集群的操作：

本章中的所有 AWS 控制台配置示例都基于您已登录到 AWS 控制台并假定了适当的管理角色，如在第三章“开始使用 AWS”中所述。撰写本章时，本节中描述的任务特定于 us-east-1（北弗吉尼亚）地区，因此在继续之前，请确保您已在 AWS 控制台中选择了该地区。

1.  从主 AWS 控制台中，在计算部分中选择“服务”|“弹性容器服务”。

1.  如果您以前没有在您的 AWS 账户和地区中使用或配置过 ECS，您将看到一个欢迎屏幕，并且可以通过单击“开始”按钮来调用一个入门配置向导。

1.  在撰写本文时，入门向导只允许您使用 Fargate 部署类型开始。我们将在后面的章节中了解有关 Fargate 的信息，因此请滚动到屏幕底部，然后单击**取消**。

1.  您将返回到 ECS 控制台，现在可以通过单击**创建集群**按钮开始创建 ECS 集群。

1.  在**选择集群模板**屏幕上，选择**EC2 Linux + Networking**模板，该模板将通过启动基于特殊的 ECS 优化 Amazon 机器映像（AMI）的 EC2 实例来设置网络资源和支持 Linux 的 Docker 的 EC2 自动扩展组，我们稍后将了解更多信息。完成后，单击**下一步**继续。

1.  在**配置集群**屏幕上，配置一个名为**test-cluster**的集群名称，确保**EC2 实例类型**设置为**t2.micro**以符合免费使用条件，并将**密钥对**设置为您在早期章节中创建的 EC2 密钥对。请注意，将创建新的 VPC 和子网，以及允许来自互联网（`0.0.0.0/0`）的入站 Web 访问（TCP 端口`80`）的安全组。完成后，单击**创建**开始创建集群：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/06292307-6855-4e25-869b-12901590f2ef.png)配置 ECS 集群

1.  此时，将显示启动状态屏幕，并将创建一些必要的资源来支持您的 ECS 集群。完成集群创建后，单击**查看集群**按钮继续。

现在，您将转到刚刚创建的`test-cluster`的详细信息屏幕。恭喜 - 您已成功部署了第一个 ECS 集群！

集群详细信息屏幕为您提供有关 ECS 集群的配置和操作数据 - 例如，如果您单击**ECS 实例**选项卡，则会显示集群中每个 ECS 容器实例的列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b41be353-c25f-4219-a6c6-d5792812649d.png)ECS 集群详细信息

您可以看到向导创建了一个单个容器实例，该实例正在从部署到显示的可用区的 EC2 实例上运行。请注意，您还可以查看有关 ECS 容器实例的其他信息，例如 ECS 代理版本和状态、运行任务、CPU/内存使用情况，以及 Docker Engine 的版本。

ECS 集群没有比这更多的东西——它本质上是一组 ECS 容器实例，这些实例又是运行 Docker 引擎以及提供 CPU、内存和网络资源来运行容器的 EC2 实例。

# 理解 ECS 容器实例

使用 AWS 控制台提供的向导创建 ECS 集群非常容易，但是显然，在幕后进行了很多工作来使您的 ECS 集群正常运行。本入门章节范围之外的所有创建资源的讨论都是不在讨论范围内的，但是在这个阶段，集中关注 ECS 容器实例并对其进行进一步详细检查是有用的，因为它们共同构成了 ECS 集群的核心。

# 加入 ECS 集群

当 ECS 创建集群向导启动实例并创建我们的 ECS 集群时，您可能会想知道 ECS 容器实例如何加入 ECS 集群。这个问题的答案非常简单，可以通过单击新创建集群中 ECS 容器实例的 EC2 实例 ID 链接来轻松理解。

此链接将带您转到 EC2 仪表板，其中选择了与容器实例关联的 EC2 实例，如下一个屏幕截图所示。请注意，我已经突出显示了一些元素，我们在讨论 ECS 容器实例时将会回顾到它们：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/54684032-be1c-458f-9a0f-54cd1fd2f890.png)EC2 实例详情

如果您右键单击实例并选择**实例设置** | **查看/更改用户数据**（参见上一个屏幕截图），您将看到实例的用户数据，这是在实例创建时运行的脚本，可用于帮助初始化您的 EC2 实例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/f1a75df1-7ad8-457a-96e4-701b6a1d0a5d.png)加入 ECS 集群的 EC2 实例用户数据脚本

通过入门向导配置的用户数据脚本显示在上一个屏幕截图中，正如您所看到的，这是一个非常简单的 bash 脚本，它将`ECS_CLUSTER=test-cluster`文本写入名为`/etc/ecs/ecs.config`的文件中。在这个例子中，回想一下，`test-cluster`是您为 ECS 集群配置的名称，因此在引用的 ECS 代理配置文件中的这一行配置告诉运行在 ECS 容器实例上的代理尝试注册到名为`test-cluster`的 ECS 集群。

`/etc/ecs/ecs.config`文件包含许多其他配置选项，我们将在第六章中进一步详细讨论*构建自定义 ECS 容器实例*。

# 授予加入 ECS 集群的访问权限

在上一个屏幕截图中，请注意连接到 ECS 集群不需要凭据—您可能会原谅认为 ECS 只允许任何 EC2 实例加入 ECS 集群，但当然这并不安全。

EC2 实例包括一个名为 IAM 实例配置文件的功能，它将 IAM 角色附加到定义实例可以执行的各种 AWS 服务操作的 EC2 实例上。在您的 EC2 实例的 EC2 仪表板中，您可以看到一个名为**ecsInstanceRole**的角色已分配给您的实例，如果您点击此角色，您将被带到 IAM 仪表板，显示该角色的**摘要**页面。

在**权限**选项卡中，您可以看到一个名为`AmazonEC2ContainerServiceforEC2Role`的 AWS 托管策略附加到该角色，如果您展开该策略，您可以看到与该策略相关的各种 IAM 权限，如下面的屏幕截图所示：

EC2 实例角色 IAM 策略

请注意，该策略允许`ecs:RegisterContainerInstance`操作，这是 ECS 容器实例加入 ECS 集群所需的 ECS 权限，并且该策略还授予了`ecs:CreateCluster`权限，这意味着尝试注册到当前不存在的 ECS 集群的 ECS 容器实例将自动创建一个新的集群。

还有一件需要注意的事情是，该策略适用于所有资源，由`"Resource": "*"`属性指定，这意味着分配了具有此策略的角色的任何 EC2 实例都能够加入您帐户和区域中的任何 ECS 集群。再次强调，这可能看起来不太安全，但请记住，这是一个旨在简化授予 ECS 容器实例所需权限的策略，在后面的章节中，我们将讨论如何创建自定义 IAM 角色和策略，以限制特定 ECS 容器实例可以加入哪些 ECS 集群。

# 管理 ECS 容器实例

通常，ECS 容器实例应该是自管理的，需要很少的直接管理，但是总会有一些时候你需要排查你的 ECS 容器实例，因此学习如何连接到你的 ECS 容器实例并了解 ECS 容器实例内部发生了什么是很有用的。

# 连接到 ECS 容器实例

ECS 容器实例是常规的 Linux 主机，因此您可能期望，连接到您的实例只是意味着能够与实例建立安全外壳（SSH）会话：

1.  如果您在 EC2 仪表板中导航回到您的实例，我们首先需要配置附加到您的实例的安全组，以允许入站 SSH 访问。您可以通过点击安全组，选择入站选项卡，然后点击**编辑按钮**来修改安全组的入站规则来实现这一点。

1.  在**编辑入站规则**对话框中，点击**添加规则**按钮，并使用以下设置添加新规则：

+   协议：TCP

+   端口范围：22

+   来源：我的 IP

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/47275b79-2f2b-40c2-9a8b-df1c4a977c87.png)为 SSH 访问添加安全组规则

1.  点击**保存**后，您将允许来自您的公共 IP 地址的入站 SSH 访问到 ECS 容器实例。如果您在浏览器中返回到您的 EC2 实例，现在您可以复制公共 IP 地址并 SSH 到您的实例。

以下示例演示了如何建立与实例的 SSH 连接，使用`-i`标志引用与实例关联的 EC2 密钥对的私钥。您还需要使用用户名`ec2-user`登录，这是 Amazon Linux 中包含的默认非 root 用户：

```
> ssh -i ~/.ssh/admin.pem ec2-user@34.201.120.79
The authenticity of host '34.201.120.79 (34.201.120.79)' can't be established.
ECDSA key fingerprint is SHA256:c/MniTAq931tJj8bCVtRUP9gixM/ZXZSqDuMENqpod0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '34.201.120.79' (ECDSA) to the list of known hosts.

   __| __| __|
   _| ( \__ \ Amazon ECS-Optimized Amazon Linux AMI 2017.09.g
 ____|\___|____/

For documentation visit, http://aws.amazon.com/documentation/ecs
5 package(s) needed for security, out of 7 available
Run "sudo yum update" to apply all updates.
```

首先要注意的是登录横幅指示此实例基于 Amazon ECS-Optimized Amazon Linux AMI，这是创建 ECS 容器实例时默认和推荐的 Amazon Machine Image（AMI）。AWS 定期维护此 AMI，并使用与 ECS 推荐使用的 Docker 和 ECS 代理版本定期更新，因此这是迄今为止最简单的用于 ECS 容器实例的平台，我强烈建议使用此 AMI 作为 ECS 容器实例的基础。

您可以在此处了解有关此 AMI 的更多信息：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html)。它包括每个 ECS 支持的区域的当前 AMI 映像 ID 列表。

在第六章中，*构建自定义 ECS 容器实例*，您将学习如何自定义和增强 Amazon ECS 优化的 Amazon Linux AMI。

# 检查本地 Docker 环境

正如您可能期望的那样，您的 ECS 容器实例将运行一个活动的 Docker 引擎，您可以通过运行`docker info`命令来收集有关其信息：

```
> docker info
Containers: 1
 Running: 1
 Paused: 0
 Stopped: 0
Images: 2
Server Version: 17.09.1-ce
Storage Driver: devicemapper
 Pool Name: docker-docker--pool
 Pool Blocksize: 524.3kB
 Base Device Size: 10.74GB
 Backing Filesystem: ext4
...
...
```

在这里，您可以看到实例正在运行 Docker 版本 17.09.1-ce，使用设备映射器存储驱动程序，并且当前只有一个容器正在运行。

现在让我们通过执行`docker container ps`命令来查看运行的容器：

```
> docker ps
CONTAINER ID   IMAGE                            COMMAND    CREATED          STATUS          NAMES
a1b1a89b5e9e   amazon/amazon-ecs-agent:latest   "/agent"   36 minutes ago   Up 36 minutes   ecs-agent
```

您可以看到 ECS 代理实际上作为一个名为`ecs-agent`的容器运行，这应该始终在您的 ECS 容器实例上运行，以便您的 ECS 容器实例由 ECS 管理。

# 检查 ECS 代理

如前所示，ECS 代理作为 Docker 容器运行，我们可以使用`docker container inspect`命令来收集有关此容器如何工作的一些见解。在先前的示例中，我们引用了 ECS 代理容器的名称，然后使用 Go 模板表达式以及`--format`标志来过滤命令输出，显示 ECS 代理容器到 ECS 容器实例主机的各种绑定挂载或卷映射。

在许多命令示例中，我正在将输出传输到`jq`实用程序，这是一个用于在命令行解析 JSON 输出的实用程序。 `jq`不是 Amazon Linux AMI 默认包含的，因此您需要通过运行`sudo yum install jq`命令来安装`jq`。

```
> docker container inspect ecs-agent --format '{{json .HostConfig.Binds}}' | jq
[
  "/var/run:/var/run",
  "/var/log/ecs:/log",
  "/var/lib/ecs/data:/data",
  "/etc/ecs:/etc/ecs",
  "/var/cache/ecs:/var/cache/ecs",
  "/cgroup:/sys/fs/cgroup",
  "/proc:/host/proc:ro",
  "/var/lib/ecs/dhclient:/var/lib/dhclient",
  "/lib64:/lib64:ro",
  "/sbin:/sbin:ro"
]
```

运行 docker container inspect 命令

请注意，将`/var/run`文件夹从主机映射到代理，这将允许 ECS 代理访问位于`/var/run/docker.sock`的 Docker 引擎套接字，从而允许 ECS 代理管理 Docker 引擎。您还可以看到 ECS 代理日志将写入 Docker 引擎主机文件系统上的`/var/log/ecs`。

# 验证 ECS 代理

ECS 代理包括一个本地 Web 服务器，可用于内省当前的 ECS 代理状态。

以下示例演示了使用`curl`命令内省 ECS 代理：

```
> curl -s localhost:51678 | jq
{
  "AvailableCommands": [
    "/v1/metadata",
    "/v1/tasks",
    "/license"
  ]
}
> curl -s localhost:51678/v1/metadata | jq
{
  "Cluster": "test-cluster",
  "ContainerInstanceArn": "arn:aws:ecs:us-east-1:385605022855:container-instance/f67cbfbd-1497-47c0-b56c-a910c923ba70",
  "Version": "Amazon ECS Agent - v1.16.2 (998c9b5)"
}
```

审查 ECS 代理

请注意，ECS 代理监听端口 51678，并提供三个可以查询的端点：

+   `/v1/metadata`：描述容器实例加入的集群、容器实例的 Amazon 资源名称（ARN）和 ECS 代理版本

+   `/v1/tasks`：返回当前正在运行的任务列表。目前我们还没有将任何 ECS 服务或任务部署到我们的集群，因此此列表为空

+   `/license`：提供适用于 ECS 代理软件的各种软件许可证

`/v1/metadata`端点特别有用，因为您可以使用此端点来确定 ECS 代理是否成功加入了给定的 ECS 集群。我们将在第六章中使用这一点，构建自定义 ECS 容器实例来执行实例创建的健康检查，以确保我们的实例已成功加入了正确的 ECS 集群。

# ECS 容器实例日志

每个 ECS 容器实例都包括可帮助排除故障的日志文件。

您将处理的主要日志包括以下内容：

+   Docker 引擎日志：位于`/var/log/docker`

+   ECS 代理日志：位于`/var/log/ecs`

请注意，有两种类型的 ECS 代理日志：

+   初始化日志：位于`/var/log/ecs/ecs-init.log`，这些日志提供与`ecs-init`服务相关的输出，这是一个 Upstart 服务，确保 ECS 代理在容器实例启动时运行。

+   代理日志：位于`/var/log/ecs/ecs-agent.log.*`，这些日志提供与 ECS 代理操作相关的输出。这些日志是您检查任何与 ECS 代理相关问题的最常见日志。

# 创建 ECS 任务定义

现在您已经设置了 ECS 集群并了解了 ECS 容器实例如何注册到集群，现在是时候配置 ECS 任务定义了，该定义定义了您要为应用程序部署的容器的配置。ECS 任务定义可以定义一个或多个容器，以及其他元素，例如容器可能需要读取或写入的卷。

为了简化问题，我们将创建一个非常基本的任务定义，该任务将运行官方的 Nginx Docker 镜像，该镜像发布在[`hub.docker.com/_/nginx/`](https://hub.docker.com/_/nginx/)。Nginx 是一个流行的 Web 服务器，默认情况下将提供欢迎页面，现在这足以代表一个简单的 Web 应用程序。

现在，让我们通过执行以下步骤为我们的简单 Web 应用程序创建一个 ECS 任务定义：

1.  在 ECS 控制台上导航到**服务** | **弹性容器服务**。您可以通过从左侧菜单中选择**任务定义**并单击**创建新任务定义**按钮来创建一个新的任务定义。

1.  在**选择启动类型兼容性**屏幕上，选择**EC2 启动类型**，这将配置任务定义在基于您拥有和管理的基础设施上启动 ECS 集群。

1.  在**配置任务和容器定义**屏幕上，配置**任务定义名称**为**simple-web**，然后向下滚动并单击**添加容器**以添加新的容器定义。

1.  在**添加容器**屏幕上，配置以下设置，完成后单击**添加按钮**以创建容器定义。此容器定义将在 ECS 容器主机上将端口 80 映射到容器中的端口`80`，允许从外部世界访问 Nginx Web 服务器：

+   **容器名称**：nginx

+   **镜像**：nginx

+   **内存限制**：`250` MB 硬限制

+   **端口映射**：主机端口`80`，容器端口`80`，协议 tcp：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/0b9e9538-9656-4d04-a83d-a988536410bf.png)创建容器定义

1.  通过单击**配置任务和容器定义**页面底部的**创建**按钮完成任务定义的创建。

# 创建 ECS 服务

我们已经创建了一个 ECS 集群，并配置了一个 ECS 任务定义，其中包括一个运行 Nginx 的单个容器，具有适当的端口映射配置，以将 Nginx Web 服务器暴露给外部世界。

现在我们需要定义一个 ECS 服务，这将配置 ECS 以部署一个或多个实例到我们的 ECS 集群。ECS 服务将给定的 ECS 任务定义部署到给定的 ECS 集群，允许您配置要运行多少个实例（ECS 任务）的引用 ECS 任务定义，并控制更高级的功能，如负载均衡器集成和应用程序的滚动更新。

要创建一个新的 ECS 服务，请完成以下步骤：

1.  在 ECS 控制台上，从左侧选择集群，然后单击您在本章前面创建的**test-cluster**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/ee85b80b-d440-4a73-bbd4-fa331767d863.png)选择要创建 ECS 服务的 ECS 集群

1.  在集群详细信息页面，选择**服务**选项卡，然后点击**创建**来创建一个新服务。

1.  在配置服务屏幕上，配置以下设置，完成后点击**下一步**按钮。请注意，我们在本章前面创建的任务定义和 ECS 集群都有所提及：

+   **启动类型**：EC2

+   **任务定义**：simple-web:1

+   **集群**：test-cluster

+   **服务名称**：simple-web

+   **任务数量**：1

1.  ECS 服务配置设置的其余部分是可选的。继续点击**下一步**，直到到达**审阅**屏幕，在那里您可以审阅您的设置并点击**创建服务**来完成 ECS 服务的创建。

1.  **启动状态**屏幕现在将出现，一旦您的服务已创建，点击**查看服务**按钮。

1.  服务详细信息屏幕现在将出现在您的新 ECS 服务中，您应该看到一个处于运行状态的单个 ECS 任务，这意味着与 simple-web ECS 任务定义相关联的 Nginx 容器已成功启动：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7ff62653-1a1e-4dc7-9f44-848fcebca51c.png)完成新 ECS 服务的创建

此时，您现在应该能够浏览到您新部署的 Nginx Web 服务器，您可以通过浏览到您之前作为 ECS 集群的一部分创建的 ECS 容器实例的公共 IP 地址来验证。如果一切正常，您应该会看到默认的**欢迎使用 nginx**页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7863bcb9-dbb8-42c2-8481-c43e191fa316.png)浏览到 Nginx Web 服务器

# 部署 ECS 服务

现在您已成功创建了一个 ECS 服务，让我们来看看 ECS 如何管理容器应用的新部署。重要的是要理解，ECS 任务定义是不可变的—也就是说，一旦创建了任务定义，就不能修改任务定义，而是需要创建一个全新的任务定义或创建当前任务定义的*修订版*，您可以将其视为给定任务定义的新版本。

ECS 将 ECS 任务定义的逻辑名称定义为*family*，ECS 任务定义的给定修订版以*family*:*revision*的形式表示—例如，`my-task-definition:3`指的是*my-task-definition*家族的第 3 个修订版。

这意味着为了部署一个容器应用的新版本，您需要执行一些步骤：

1.  创建一个新的 ECS 任务定义修订，其中包含已更改为应用程序新版本的配置设置。这通常只是您为应用程序构建的 Docker 镜像关联的图像标签，但是任何配置更改，比如分配的内存或 CPU 资源的更改，都将导致创建 ECS 任务定义的新修订。

1.  更新您的 ECS 服务以使用 ECS 任务定义的新修订版。每当以这种方式更新 ECS 服务时，ECS 将自动执行应用程序的滚动更新，试图优雅地用基于新 ECS 任务定义修订的新容器替换组成 ECS 服务的每个运行容器。

为了演示这种行为，现在让我们修改本章前面创建的 ECS 任务定义，并通过以下步骤更新 ECS 服务：

1.  在 ECS 控制台中，从左侧选择任务定义，然后点击您之前创建的 simple-web 任务定义。

1.  注意，当前任务定义修订只有一个存在——在任务定义名称后的冒号后面标明修订号。例如，simple-web:1 指的是 simple-web 任务定义的修订 1。选择当前任务定义修订，然后点击创建新修订以基于现有任务定义修订创建新的修订。

1.  创建新的任务定义修订屏幕显示出来，这与您之前配置的创建新任务定义屏幕非常相似。滚动到容器定义部分，点击 Nginx 容器以修改 Nginx 容器定义。

1.  我们将对任务定义进行的更改是修改端口映射，从当前端口 80 的静态主机映射到主机上的动态端口映射。这可以通过简单地将主机端口设置为空来实现，在这种情况下，Docker 引擎将从基础 ECS 容器实例上的临时端口范围中分配动态端口。对于我们使用的 Amazon Linux AMI，此端口范围介于`32768`和`60999`之间。动态端口映射的好处是我们可以在同一主机上运行多个容器实例 - 如果静态端口映射已经存在，只能启动一个容器实例，因为随后的容器实例将尝试绑定到已使用的端口`80`。完成配置更改后，点击**更新**按钮继续。

1.  在**创建新的任务定义版本**屏幕的底部点击**创建**按钮，完成新版本的创建。

要获取 Docker 使用的临时端口范围，您可以检查`/proc/sys/net/ipv4/ip_local_port_range`文件的内容。如果您的操作系统上没有此文件，Docker 将使用`49153`到`65535`的端口范围。

此时，已从您的 ECS 任务定义创建了一个新版本（版本 2）。现在，您需要通过完成以下步骤来更新您的 ECS 服务以使用新的任务定义版本。

1.  在 ECS 控制台中，从左侧选择**集群**，选择您的测试集群。在服务选项卡上，选择您的 ECS 服务旁边的复选框，然后点击**更新**按钮。

1.  在配置服务屏幕上的任务定义下拉菜单中，您应该能够选择您刚刚创建的任务定义的新版本（simple-web:2）。完成后，继续点击**下一步**按钮，直到到达审阅屏幕，在这时您可以点击**更新服务**按钮完成配置更改：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/2aa14d89-5a38-4204-b619-236a6a61a153.png)修改 ECS 服务任务定义

1.  与您创建 ECS 服务时之前看到的类似，启动状态屏幕将显示。如果您点击**查看服务**按钮，您将进入 ECS 服务详细信息屏幕，如果选择部署选项卡，您应该看到正在部署的任务定义的新版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6fe12f0d-5fdd-48bd-8677-ed4aa6755052.png)ECS 服务部署

请注意，有两个部署——活动部署显示现有的 ECS 服务部署，并指示当前有一个正在运行的容器。主要部署显示基于新修订的新 ECS 服务部署，并指示期望计数为 1，但请注意运行计数尚未为 1。

如果您定期刷新部署状态，您将能够观察到新任务定义修订版部署时的各种状态变化：

部署更改将会相当快速地进行，所以如果您没有看到任何这些更改，您可以随时更新 ECS 服务，以使用 ECS 任务定义的第一个修订版本来强制进行新的部署。

1.  主要部署应该指示挂起计数为 1，这意味着新版本的容器即将启动。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/7686c6f8-bd4d-4904-bf65-0fd0382085d4.png)新部署待转换

1.  主要部署接下来将转换为运行计数为 1，这意味着新版本的容器正在与现有容器一起运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/74aa02ea-9b46-46cb-8854-3b7b1a8ffecd.png)新部署运行转换

1.  在这一点上，现有容器现在可以停止，所以您应该看到活动部署的运行计数下降到零：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/619fe851-38df-4e92-bde6-6371ee013880.png)旧部署停止转换

1.  活动部署从部署选项卡中消失，滚动部署已完成：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/3750bf97-f2c1-4d44-a110-f3952a961157.png)滚动部署完成

在这一点上，我们已成功执行了 ECS 服务的滚动更新，值得指出的是，新的动态端口映射配置意味着您的 Nginx Web 服务器不再在端口 80 上对外界进行监听，而是在 ECS 容器实例动态选择的端口上进行监听。

您可以通过尝试浏览到您的 Nginx Web 服务器的公共 IP 地址来验证这一点——这应该会导致连接失败，因为 Web 服务器不再在端口 80 上运行。如果您选择**Tasks**选项卡，找到**simple-web** ECS 服务，您可以点击任务，找出我们的 Web 服务器现在正在监听的端口。

在扩展 Nginx 容器后，您可以看到在这种情况下，ECS 容器实例主机上的端口`32775`映射到 Nginx 容器上的端口`80`，但由于 ECS 容器实例分配的安全组仅允许在端口`80`上进行入站访问，因此您无法从互联网访问该端口。

为了使动态端口映射有用，您需要将您的 ECS 服务与应用程序负载均衡器相关联，负载均衡器将自动检测每个 ECS 服务实例的动态端口映射，并将传入的请求负载均衡到负载均衡器上定义的静态端口到每个 ECS 服务实例。您将在后面的章节中了解更多相关内容。![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c27fd937-e1b2-4a91-8300-c174222ad400.png)ECS 服务动态端口映射

# 运行 ECS 任务

我们已经看到了如何将长时间运行的应用程序部署为 ECS 服务，但是如何使用 ECS 运行临时任务或短暂的容器呢？答案当然是创建一个 ECS 任务，通常用于运行临时任务，例如运行部署脚本，执行数据库迁移，或者执行定期批处理。

尽管 ECS 服务本质上是长时间运行的 ECS 任务，但 ECS 确实会对您自己创建的 ECS 任务与 ECS 服务进行不同的处理，如下表所述：

| 场景/特性 | ECS 服务行为 | ECS 任务行为 |
| --- | --- | --- |
| 容器停止或失败 | ECS 将始终尝试维护给定 ECS 服务的期望计数，并将尝试重新启动容器，如果活动计数由于容器停止或失败而低于期望计数。 | ECS 任务是一次性执行，要么成功，要么失败。ECS 永远不会尝试重新运行失败的 ECS 任务。 |
| 任务定义配置 | 您无法覆盖给定 ECS 服务的任何 ECS 任务定义配置。 | ECS 任务允许您覆盖环境变量和命令行设置，允许您利用单个 ECS 任务定义来运行各种不同类型的 ECS 任务。 |
| 负载均衡器集成 | ECS 服务具有与 AWS 弹性负载均衡服务的完全集成。 | ECS 任务不与任何负载均衡服务集成。 |

ECS 服务与 ECS 任务

让我们现在看看如何使用 AWS 控制台运行 ECS 任务。您将创建一个非常简单的 ECS 任务，该任务将在 ECS 任务定义中定义的 Nginx 镜像中运行`sleep 300`命令。

这将导致任务在执行之前休眠五分钟，模拟短暂的临时任务：

1.  在 ECS 控制台上，选择左侧的**集群**，然后单击名为**test-cluster**的集群。

1.  选择**任务**选项卡，单击**运行新任务**按钮以创建新的 ECS 任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c57d3acc-a14a-4571-b3a6-158461398793.png)运行 ECS 任务

1.  在**运行任务**屏幕上，首先选择**EC2**作为**启动类型**，并确保**任务定义**和**集群**设置正确配置。如果您展开**高级选项**部分，注意您可以为**nginx**容器指定容器覆盖。请注意，要配置命令覆盖，您必须以逗号分隔的格式提供要运行的命令及其任何参数，例如，要执行`sleep 300`命令，您必须配置**sleep,300**的命令覆盖。配置完成后，单击**运行任务**以执行新的 ECS 任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/689373b4-dae0-49a9-9677-97bf10311b1a.png)配置 ECS 任务

此时，您将返回到 ECS 集群的任务选项卡，您应该看到一个状态为**挂起**的新任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/e25ba3d1-4de3-4d2d-a607-16d019c3b943.png)ECS 任务处于挂起状态

新任务应该很快转换为**运行**状态，如果我们让任务运行，它最终会在五分钟后退出。

现在让我们利用这个机会观察 ECS 任务在停止时的行为。如果您选择所有任务并单击**停止**按钮，系统将提示您确认是否要停止每个任务。确认要停止每个任务后，**任务**窗格应立即显示没有活动任务，然后单击刷新按钮几次后，您应该看到一个任务重新启动。这个任务是由 ECS 自动启动的，以保持 simple-web 服务的期望计数为 1。

# 使用 ECS CLI

在本章中，我们专注于使用 AWS 控制台来开始使用 ECS。AWS 编写和维护的另一个工具称为 ECS CLI，它允许您从命令行创建 ECS 集群并部署 ECS 任务和服务。

ECS CLI 与 AWS CLI 在许多方面不同，但主要区别包括：

+   ECS CLI 专注于与 ECS 交互，并且仅支持与为 ECS 提供支持资源的其他 AWS 服务进行交互，例如 AWS CloudFormation 和 EC2 服务。

+   ECS CLI 操作比 AWS CLI 操作更粗粒度。例如，ECS CLI 将编排创建 ECS 集群及其所有支持资源，就像您在本章前面使用的 ECS 集群向导的行为一样，而 AWS CLI 则专注于执行单个特定任务的更细粒度操作。

+   ECS CLI 是用 Golang 编写的，而 AWS CLI 是用 Python 编写的。这确实引入了一些行为差异——例如，ECS CLI 不支持启用了 MFA（多因素认证）的 AWS 配置文件的使用，这意味着您需要使用不需要 MFA 的 AWS 凭据和角色。

ECS CLI 的一个特别有用的功能是它支持 Docker Compose 文件的第 1 版和第 2 版，这意味着您可以使用 Docker Compose 来提供对多容器环境的通用描述。ECS CLI 还允许您使用基于 YAML 的配置文件来定义您的基础设施，因此可以被视为一个简单而功能强大的基础设施即代码工具。

一般来说，ECS CLI 对于快速搭建沙盒/开发环境以进行快速原型设计或测试非常有用。对于部署正式的非生产和生产环境，您应该使用诸如 Ansible、AWS CloudFormation 或 Terraform 等工具和服务，这些工具和服务提供了对您运行生产级环境所需的所有 AWS 资源的更广泛支持。

ECS CLI 包括完整的文档，您可以在 [`docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_CLI.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_CLI.html) 找到。您还可以查看 ECS CLI 源代码并在 [`github.com/aws/amazon-ecs-cli`](https://github.com/aws/amazon-ecs-cli) 上提出问题。

# 删除测试集群

此时，您应该按照 ECS 仪表板中的以下步骤删除本章中创建的测试集群：

1.  从集群中选择测试集群

1.  选择并更新 simple-web ECS 服务，使其期望计数为 0

1.  等待直到 simple-web ECS 任务计数下降到 0

1.  选择测试集群，然后单击删除集群按钮

# 摘要

在本章中，您了解了 ECS 架构，并了解了构成 ECS 的核心组件。您了解到 ECS 集群是一组 ECS 容器实例，这些实例在 EC2 自动扩展组实例上运行 Docker 引擎。AWS 为您提供了预构建的 ECS 优化 AMI，使得使用 ECS 能够快速启动和运行。每个 ECS 容器实例包括一个作为系统容器运行并与 ECS 通信的 ECS 代理，提供启动、停止和部署容器所需的管理和控制平面。

接下来，您创建了一个 ECS 任务定义，该定义定义了一个或多个容器和卷定义的集合，包括容器映像、环境变量和 CPU/内存资源分配等信息。有了您的 ECS 集群和 ECS 任务定义，您随后能够创建和配置一个 ECS 服务，引用 ECS 任务定义来定义 ECS 服务的容器配置，并将一个或多个实例的 ECS 服务定位到您的 ECS 集群。

ECS 支持滚动部署以更新容器应用程序，您可以通过简单地创建 ECS 任务定义的新版本，然后将定义与 ECS 服务关联来成功部署新的应用程序更改。

最后，您学会了如何使用 ECS CLI 简化创建 ECS 集群和服务，使用 Docker Compose 作为通用机制来定义任务定义和 ECS 服务。

在下一章中，您将更仔细地了解弹性容器注册表（ECR）服务，您将学习如何创建自己的私有 ECR 存储库，并将您的 Docker 映像发布到这些存储库。

# 问题

1.  列出三个在使用 ECS 运行长时间运行的 Docker 容器所需的 ECS 组件

1.  真/假：ECS 代理作为 upstart 服务运行

1.  在使用 ECS CLI 时，您使用什么配置文件格式来定义基础架构？

1.  真/假：您可以将两个实例的 ECS 任务部署到单个实例 ECS 集群并进行静态端口映射

1.  真/假：ECS CLI 被认为是将 Docker 环境部署到生产环境的最佳工具

1.  使用 ECS 运行每晚运行 15 分钟的批处理作业时，您将配置什么？

1.  真/假：ECS 任务定义是可变的，可以修改

1.  真/假：您可以通过运行`curl localhost:51678`命令来检查给定 Docker Engine 上代理的当前状态

# 更多信息

您可以查看以下链接以获取有关本章涵盖的主题的更多信息：

+   ECS 开发人员指南：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/Welcome.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/Welcome.html)

+   Amazon ECS-Optimized AMI：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-optimized_AMI.html)

+   ECS 容器实例所需的权限：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/instance_IAM_role.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/instance_IAM_role.html)

+   ECS 代理文档：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_agent.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_agent.html)

+   使用 ECS CLI：[`docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_CLI.html`](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ECS_CLI.html)

+   ECS 代理 GitHub 存储库：[`github.com/aws/amazon-ecs-agent`](https://github.com/aws/amazon-ecs-agent)

+   ECS init GitHub 存储库：[`github.com/aws/amazon-ecs-init`](https://github.com/aws/amazon-ecs-init)

+   ECS CLI GitHub 存储库：[`github.com/aws/amazon-ecs-cli`](https://github.com/aws/amazon-ecs-cli)


# 第五章：使用 ECR 发布 Docker 镜像

Docker 注册表是 Docker 和容器生态系统的关键组件，提供了一种通用机制来公开和分发您的容器应用程序，无论是公开还是私有。

ECR 提供了一个完全托管的私有 Docker 注册表，具有与上一章介绍的 ECS 组件和其他 AWS 服务紧密集成的特性。ECR 具有高度可扩展性，安全性，并提供工具来与用于构建和发布 Docker 镜像的本机 Docker 客户端集成。

在本章中，您将学习如何创建 ECR 存储库来存储您的 Docker 镜像，使用各种机制，包括 AWS 控制台，AWS CLI 和 CloudFormation。一旦您建立了第一个 ECR 存储库，您将学习如何使用 ECR 进行身份验证，拉取存储在您的存储库中的 Docker 镜像，并使用 Docker 客户端构建和发布 Docker 镜像到 ECR。最后，您将学习如何处理更高级的 ECR 使用和管理场景，包括配置跨帐户访问以允许在其他 AWS 帐户中运行的 Docker 客户端访问您的 ECR 存储库，并配置生命周期策略，以确保孤立的 Docker 镜像定期清理，减少管理工作量和成本。

将涵盖以下主题：

+   了解 ECR

+   创建 ECR 存储库

+   登录到 ECR

+   将 Docker 镜像发布到 ECR

+   从 ECR 拉取 Docker 镜像

+   配置生命周期策略

# 技术要求

以下列出了完成本章所需的技术要求：

+   Docker 18.06 或更高版本

+   Docker Compose 1.22 或更高版本

+   GNU Make 3.82 或更高版本

+   jq

+   AWS CLI 1.15.71 或更高版本

+   对 AWS 帐户的管理员访问权限

+   本地 AWS 配置文件按第三章中的说明配置

+   在第二章中配置的示例应用程序的工作 Docker 工作流程（请参阅[`github.com/docker-in-aws/docker-in-aws/tree/master/ch2`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch2)）。

此 GitHub URL 包含本章中使用的代码示例：[`github.com/docker-in-aws/docker-in-aws/tree/master/ch5`](https://github.com/docker-in-aws/docker-in-aws/tree/master/ch5)。

查看以下视频以查看代码的实际操作：

[`bit.ly/2PKMLSP`](http://bit.ly/2PKMLSP)

# 了解 ECR

在开始创建和配置 ECR 存储库之前，重要的是要简要介绍 ECR 的核心概念。

ECR 是由 AWS 提供的完全托管的私有 Docker 注册表，并与 ECS 和其他 AWS 服务紧密集成。ECR 包括许多组件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4472aae0-f99e-482d-a642-fad5cc753bfa.png)ECR 架构

ECR 的核心组件包括：

+   **仓库**: 仓库存储给定 Docker 镜像的所有版本。每个仓库都配置有名称和 URI，该 URI 对于您的 AWS 帐户和区域是唯一的。

+   **权限**: 每个仓库都包括权限，允许您授予各种 ECR 操作的访问权限，例如推送或拉取 Docker 镜像。

+   **生命周期策略**: 每个仓库都可以配置一个可选的生命周期策略，用于清理已被新版本取代的孤立的 Docker 镜像，或者删除您可能不再使用的旧 Docker 镜像。

+   **认证服务**: ECR 包括一个认证服务，其中包括一个令牌服务，可用于以临时认证令牌交换您的 IAM 凭据以进行身份验证，与 Docker 客户端身份验证过程兼容。

考虑 ECR 的消费者也很重要。如前图所示，这些包括：

+   **与您的仓库在同一本地 AWS 帐户中的 Docker 客户端**: 这通常包括在 ECS 集群中运行的 ECS 容器实例。

+   **不同 AWS 帐户中的 Docker 客户端**: 这是较大组织的常见情况，通常包括在远程帐户中运行的 ECS 集群中的 ECS 容器实例。

+   **AWS 服务使用的 Docker 客户端**: 一些 AWS 服务可以利用您在 ECR 中发布的自己的 Docker 镜像，例如 AWS CodeBuild 服务。

在撰写本书时，ECR 仅作为私有注册表提供 - 这意味着如果您想公开发布您的 Docker 镜像，那么至少在发布您的公共 Docker 镜像方面，ECR 不是正确的解决方案。

# 创建 ECR 仓库

现在您已经对 ECR 有了基本概述，让我们开始创建您的第一个 ECR 存储库。回想一下，在早期的章节中，您已经介绍了本书的示例**todobackend**应用程序，并在本地环境中构建了一个 Docker 镜像。为了能够在基于此镜像的 ECS 集群上运行容器，您需要将此镜像发布到 ECS 容器实例可以访问的 Docker 注册表中，而 ECR 正是这个问题的完美解决方案。

为**todobackend**应用程序创建 ECR 存储库，我们将专注于三种流行的方法来创建和配置您的存储库：

+   使用 AWS 控制台创建 ECR 存储库

+   使用 AWS CLI 创建 ECR 存储库

+   使用 AWS CloudFormation 创建 ECR 存储库

# 使用 AWS 控制台创建 ECR 存储库

通过执行以下步骤，可以在 AWS 控制台上创建 ECR 存储库：

1.  从主 AWS 控制台中，选择**服务** | **弹性容器服务**，在计算部分中选择**存储库**，然后单击“开始”按钮。

1.  您将被提示配置存储库的名称。一个标准的约定是以`<organization>/<application>`格式命名您的存储库，这将导致一个完全合格的存储库 URI 为`<registry>/<organization>/<application>`。在下面的示例中，我将存储库命名为`docker-in-aws/todobackend`，但您可以根据自己的喜好命名您的镜像。完成后，点击“下一步”继续：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b8a39b1e-b38f-4f4b-91d7-162b33f6f0ea.png)配置存储库名称

1.  您的 ECR 存储库现在将被创建，并提供如何登录到 ECR 并发布您的 Docker 镜像的说明。

# 使用 AWS CLI 创建 ECR 存储库

通过运行`aws ecr create-repository`命令可以创建 ECR 存储库，但是考虑到您已经通过 AWS 控制台创建了存储库，让我们看看如何检查 ECR 存储库是否已经存在以及如何使用 AWS CLI 删除存储库。

查看您的 AWS 帐户和本地区域中的 ECR 存储库列表，您可以使用`aws ecr list-repositories`命令，而要删除 ECR 存储库，您可以使用`aws ecr delete-repository`命令，如下所示：

```
> aws ecr list-repositories
{
    "repositories": [
        {
            "repositoryArn": "arn:aws:ecr:us-east-1:385605022855:repository/docker-in-aws/todobackend",
            "registryId": "385605022855",
            "repositoryName": "docker-in-aws/todobackend",
            "repositoryUri": "385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend",
            "createdAt": 1517692382.0
        }
    ]
}
> aws ecr delete-repository --repository-name docker-in-aws/todobackend
{
    "repository": {
        "repositoryArn": "arn:aws:ecr:us-east-1:385605022855:repository/docker-in-aws/todobackend",
        "registryId": "385605022855",
        "repositoryName": "docker-in-aws/todobackend",
        "repositoryUri": "385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend",
        "createdAt": 1517692382.0
    }
}
```

使用 AWS CLI 描述和删除 ECR 存储库

现在，您已经使用 AWS 控制台删除了之前创建的仓库，您可以按照这里演示的方法重新创建它：

```
> aws ecr create-repository --repository-name docker-in-aws/todobackend
{
    "repository": {
        "repositoryArn": "arn:aws:ecr:us-east-1:385605022855:repository/docker-in-aws/todobackend",
        "registryId": "385605022855",
        "repositoryName": "docker-in-aws/todobackend",
        "repositoryUri": "385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend",
        "createdAt": 1517693074.0
    }
}
```

使用 AWS CLI 创建 ECR 仓库

# 使用 AWS CloudFormation 创建 ECR 仓库

AWS CloudFormation 支持通过`AWS::ECR::Repository`资源类型创建 ECR 仓库，在撰写本文时，这允许您管理 ECR 资源策略和生命周期策略，我们将在本章后面介绍。

作为一个经验法则，鉴于 ECR 仓库作为 Docker 镜像分发机制的关键性质，我通常建议将您的帐户和区域中的各种 ECR 仓库定义在一个单独的共享 CloudFormation 堆栈中，专门用于创建和管理 ECR 仓库。

遵循这个建议，并为将来的章节，让我们创建一个名为**todobackend-aws**的仓库，您可以用来存储您将在本书中创建和管理的各种基础架构配置。我会让您在 GitHub 上创建相应的仓库，之后您可以将您的 GitHub 仓库配置为远程仓库：

```
> mkdir todobackend-aws
> touch todobackend-aws/ecr.yml > cd todobackend-aws
> git init Initialized empty Git repository in /Users/jmenga/Source/docker-in-aws/todobackend-aws/.git/
> git remote add origin https://github.com/jmenga/todobackend-aws.git
> tree .
.
└── ecr.yml
```

现在，您可以配置一个名为`ecr.yml`的 CloudFormation 模板文件，该文件定义了一个名为`todobackend`的单个 ECR 仓库：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: ECR Repositories

Resources:
  TodobackendRepository:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: docker-in-aws/todobackend
```

使用 AWS CloudFormation 定义 ECR 仓库

正如您在前面的示例中所看到的，使用 CloudFormation 定义 ECR 仓库非常简单，只需要定义`RepositoryName`属性，这个属性定义了仓库的名称，正如您所期望的那样。

假设您已经删除了之前的 todobackend ECR 仓库，就像之前演示的那样，现在您可以使用`aws cloudformation deploy`命令使用 CloudFormation 创建 todobackend 仓库：

```
> aws cloudformation deploy --template-file ecr.yml --stack-name ecr-repositories
Waiting for changeset to be created..
Waiting for stack create/update to complete
Successfully created/updated stack - ecr-repositories
```

使用 AWS CloudFormation 创建 ECR 仓库

一旦堆栈成功部署，您可以在 CloudFormation 控制台中查看堆栈，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/355c6511-887a-4c48-a0d6-d563459b8ed9.png)ECR 仓库 CloudFormation 堆栈

如果您现在返回 ECS 控制台，并从左侧菜单中选择**资源**，您应该会看到一个名为`docker-in-aws/todobackend`的单个 ECR 仓库，就像在您的 CloudFormation 堆栈中定义的那样。如果您点击该仓库，您将进入仓库详细页面，该页面为您提供了仓库 URI、仓库中发布的镜像列表、ECR 权限和生命周期策略设置。

# 登录到 ECR

创建 Docker 镜像的存储库后，下一步是构建并将您的镜像发布到 ECR。在此之前，您必须对 ECR 进行身份验证，因为在撰写本文时，ECR 是一个不支持公共访问的私有服务。

登录到 ECR 的说明和命令显示在 ECR 存储库向导的一部分中，但是您可以随时通过选择适当的存储库并单击**查看推送命令**按钮来查看这些说明，该按钮将显示登录、构建和发布 Docker 镜像到存储库所需的各种命令。

显示的第一个命令是`aws ecr get-login`命令，它将生成一个包含临时身份验证令牌的`docker login`表达式，有效期为 12 小时（请注意，出于节省空间的考虑，命令输出已被截断）：

```
> aws ecr get-login --no-include-email
docker login -u AWS -p eyJwYXl2ovSUVQUkJkbGJ5cjQ1YXJkcnNLV29ubVV6TTIxNTk3N1RYNklKdllvanZ1SFJaeUNBYk84NTJ2V2RaVzJUYlk9Iiw
idmVyc2lvbiI6IjIiLCJ0eXBlIjoiREFUQV9LRVkiLCJleHBpcmF0aW9uIjoxNTE4MTIyNTI5fQ== https://385605022855.dkr.ecr.us-east-1.amazonaws.com
```

为 ECR 生成登录命令

对于 Docker 版本 17.06 及更高版本，`--no-include-email`标志是必需的，因为从此版本开始，`-e` Docker CLI 电子邮件标志已被弃用。

尽管您可以复制并粘贴前面示例中生成的命令输出，但更快的方法是使用 bash 命令替换自动执行`aws ecr get-login`命令的输出，方法是用`$(...)`将命令括起来：

```
> $(aws ecr get-login --no-include-email)
Login Succeeded
```

登录到 ECR

# 将 Docker 镜像发布到 ECR

在早期的章节中，您学习了如何使用 todobackend 示例应用程序在本地构建和标记 Docker 镜像。

现在，您可以将此工作流程扩展到将 Docker 镜像发布到 ECR，这需要您执行以下任务：

+   确保您已登录到 ECR

+   使用您的 ECR 存储库的 URI 构建和标记您的 Docker 镜像

+   将您的 Docker 镜像推送到 ECR

# 使用 Docker CLI 发布 Docker 镜像

您已经看到如何登录 ECR，并且构建和标记您的 Docker 镜像与本地使用情况大致相同，只是在标记图像时需要指定 ECR 存储库的 URI。

以下示例演示了构建`todobackend`镜像，使用您的新 ECR 存储库的 URI 标记图像（用于您的存储库的实际 URI），并使用`docker images`命令验证图像名称：

```
> cd ../todobackend
> docker build -t 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend .
Sending build context to Docker daemon 129.5kB
Step 1/25 : FROM alpine AS build
 ---> 3fd9065eaf02
Step 2/25 : LABEL application=todobackend
 ---> Using cache
 ---> f955808a07fd
...
...
...
Step 25/25 : USER app
 ---> Running in 4cf3fcab97c9
Removing intermediate container 4cf3fcab97c9
---> 2b2d8d17367c
Successfully built 2b2d8d17367c
Successfully tagged 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest
> docker images
REPOSITORY                                                             TAG    IMAGE ID     SIZE 
385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend latest 2b2d8d17367c 99.4MB
```

为 ECR 标记图像

构建并标记了您的镜像后，您可以将您的镜像推送到 ECR。

请注意，要将图像发布到 ECR，您需要各种 ECR 权限。因为您在您的帐户中使用管理员角色，所以您自动拥有所有所需的权限。我们将在本章后面更详细地讨论 ECR 权限。

因为您已经登录到 ECR，所以只需使用`docker push`命令并引用您的 Docker 图像的名称即可：

```
> docker push 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend]
1cdf73b07ed7: Pushed
0dfffc4aa16e: Pushed
baaced0ec8f8: Pushed
e3b27097ac3f: Pushed
3a29354c4bcc: Pushed
a031167f960b: Pushed
cd7100a72410: Pushed
latest: digest: sha256:322c8b378dd90b3a1a6dc8553baf03b4eb13ebafcc926d9d87c010f08e0339fa size: 1787
```

将图像推送到 ECR

如果您现在在 ECS 控制台中导航到 todobackend 存储库，您应该会看到您新发布的图像以默认的`latest`标签出现，如下图所示。请注意，当您比较图像的构建大小（在我的示例中为 99 MB）与存储在 ECR 中的图像大小（在我的示例中为 34 MB）时，您会发现 ECR 以压缩格式存储图像，从而降低了存储成本。

在使用 ECR 时，AWS 会对数据存储和数据传输（即拉取 Docker 图像）收费。有关更多详细信息，请参见[`aws.amazon.com/ecr/pricing/`](https://aws.amazon.com/ecr/pricing/)！[](assets/9cb36e30-9f49-412d-833c-93abf0e56183.png)查看 ECR 图像

# 使用 Docker Compose 发布 Docker 图像

在之前的章节中，您已经学会了如何使用 Docker Compose 来帮助简化测试和构建 Docker 图像所需的 CLI 命令数量。目前，Docker Compose 只能在本地构建 Docker 图像，但当然您现在希望能够发布您的 Docker 图像并利用您的 Docker Compose 工作流程。

Docker Compose 包括一个名为`image`的服务配置属性，通常用于指定要运行的容器的图像：

```
version: '2.4'

services:
  web:
    image: nginx
```

示例 Docker Compose 文件

尽管这是 Docker Compose 的一个非常常见的使用模式，但如果您结合`build`和`image`属性，还存在另一种配置和行为集，如在 todobackend 存储库的`docker-compose.yml`文件中所示：

```
version: '2.4'

volumes:
  public:
    driver: local

services:
  test:
    build:
      context: .
      dockerfile: Dockerfile
      target: test
  release:
 image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      DJANGO_SETTINGS_MODULE: todobackend.settings_release
      MYSQL_HOST: db
      MYSQL_USER: todo
      MYSQL_PASSWORD: password
  app:
    image: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:${APP_VERSION}
    extends:
  ...
  ...
```

Todobackend Docker Compose 文件

在上面的示例中，为`release`和`app`服务同时指定了`image`和`build`属性。当这两个属性一起使用时，Docker 仍将从引用的 Dockerfile 构建图像，但会使用`image`属性指定的值对图像进行标记。

您可以通过创建新服务并定义包含附加标签的图像属性来应用多个标签。

请注意，对于`app`服务，我们引用环境变量`APP_VERSION`，这意味着要使用在 todobackend 存储库根目录的 Makefile 中定义的当前应用程序版本标记图像：

```
.PHONY: test release clean version

export APP_VERSION ?= $(shell git rev-parse --short HEAD)

version:
  @ echo '{"Version": "$(APP_VERSION)"}'
```

在上面的示例中，用您自己 AWS 账户生成的适当 URI 替换存储库 URI。

为了演示当您结合`image`和`build`属性时的标记行为，首先删除本章前面创建的 Docker 图像，如下所示：

```
> docker rmi 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend
Untagged: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest
Untagged: 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend@sha256:322c8b378dd90b3a1a6dc8553baf03b4eb13ebafcc926d9d87c010f08e0339fa
Deleted: sha256:2b2d8d17367c32993b0aa68f407e89bf4a3496a1da9aeb7c00a8e49f89bf5134
Deleted: sha256:523126379df325e1bcdccdf633aa10bc45e43bdb5ce4412aec282e98dbe076fb
Deleted: sha256:54521ab8917e466fbf9e12a5e15ac5e8715da5332f3655e8cc51f5ad3987a034
Deleted: sha256:03d95618180182e7ae08c16b4687a7d191f3f56d909b868db9e889f0653add46
Deleted: sha256:eb56d3747a17d5b7d738c879412e39ac2739403bbf992267385f86fce2f5ed0d
Deleted: sha256:9908bfa1f773905e0540d70e65d6a0991fa1f89a5729fa83e92c2a8b45f7bd29
Deleted: sha256:d9268f192cb01d0e05a1f78ad6c41bc702b11559d547c0865b4293908d99a311
Deleted: sha256:c6e4f60120cdf713253b24bba97a0c2a80d41a0126eb18f4ea5269034dbdc7e1
Deleted: sha256:0b780adf8501c8a0dbf33f49425385506885f9e8d4295f9bc63c3f895faed6d1
```

删除 Docker 图像

如果您现在运行`docker-compose build release`命令，一旦命令完成，Docker Compose 将构建一个新的图像，并标记为您的 ECR 存储库 URI：

```
> docker-compose build release WARNING: The APP_VERSION variable is not set. Defaulting to a blank string.
Building release
Step 1/25 : FROM alpine AS build
 ---> 3fd9065eaf02
Step 2/25 : LABEL application=todobackend
 ---> Using cache
 ---> f955808a07fd
...
...
Step 25/25 : USER app
 ---> Using cache
 ---> f507b981227f

Successfully built f507b981227f
Successfully tagged 385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest
> docker images
```

```
REPOSITORY                                                               TAG                 IMAGE ID            CREATED             SIZE
385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend   latest              f507b981227f        4 days ago          99.4MB
```

使用 Docker Compose 构建带标签的图像

当您的图像构建并正确标记后，您现在可以执行`docker-compose push`命令，该命令可用于推送在 Docker Compose 文件中定义了`build`和`image`属性的服务：

```
> docker-compose push release
Pushing release (385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest)...
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend]
9ae8d6169643: Layer already exists
cdbc5d8be7d1: Pushed
08a1fb32c580: Layer already exists
2e3946df4029: Pushed
3a29354c4bcc: Layer already exists
a031167f960b: Layer already exists
cd7100a72410: Layer already exists
latest: digest: sha256:a1b029d347a2fabd3f58d177dcbbcd88066dc54ccdc15adad46c12ceac450378 size: 1787
```

使用 Docker Compose 发布图像

在上面的示例中，与名为`release`的服务关联的图像被推送，因为这是您使用 Docker 图像 URI 配置的服务。

# 自动化发布工作流程

在之前的章节中，您学习了如何使用 Docker、Docker Compose 和 Make 自动化测试和构建 todobackend 应用程序的 Docker 图像。

现在，您可以增强此工作流程以执行以下附加操作：

+   登录和注销 ECR

+   发布到 ECR

为了实现这一点，您将在 todobackend 存储库的 Makefile 中创建新的任务。

# 自动化登录和注销

以下示例演示了添加名为`login`和`logout`的两个新任务，这些任务将使用 Docker 客户端执行这些操作：

```
.PHONY: test release clean version login logout

export APP_VERSION ?= $(shell git rev-parse --short HEAD)

version:
  @ echo '{"Version": "$(APP_VERSION)"}'

login:
 $$(aws ecr get-login --no-include-email)

logout:
 docker logout https://385605022855.dkr.ecr.us-east-1.amazonaws.com test:
    docker-compose build --pull release
    docker-compose build
    docker-compose run test

release:
    docker-compose up --abort-on-container-exit migrate
    docker-compose run app python3 manage.py collectstatic --no-input
    docker-compose up --abort-on-container-exit acceptance
    @ echo App running at http://$$(docker-compose port app 8000 | sed s/0.0.0.0/localhost/g)

clean:
    docker-compose down -v
    docker images -q -f dangling=true -f label=application=todobackend | xargs -I ARGS docker rmi -f ARGS
```

登录和注销 ECR

请注意，`login`任务使用双美元符号($$)，这是必需的，因为 Make 使用单美元符号来定义 Make 变量。当您指定双美元符号时，Make 将向 shell 传递单美元符号，这将确保执行 bash 命令替换。

在使用`logout`任务注销时，请注意您需要指定 Docker 注册表，否则 Docker 客户端会假定默认的公共 Docker Hub 注册表。

有了这些任务，您现在可以轻松地使用`make logout`和`make login`命令注销和登录 ECR：

```
> make logout docker logout https://385605022855.dkr.ecr.us-east-1.amazonaws.com
Removing login credentials for 385605022855.dkr.ecr.us-east-1.amazonaws.com
 > make login
$(aws ecr get-login --no-include-email)
WARNING! Using --password via the CLI is insecure. Use --password-stdin.
Login Succeeded
```

运行 make logout 和 make login

# 自动化发布 Docker 图像

要自动化发布工作流，您可以在 Makefile 中添加一个名为`publish`的新任务，该任务简单地调用标记为`release`和`app`服务的`docker-compose push`命令：

```
.PHONY: test release clean login logout publish

export APP_VERSION ?= $(shell git rev-parse --short HEAD)

version:
  @ echo '{"Version": "$(APP_VERSION)"}'

...
...

release:
    docker-compose up --abort-on-container-exit migrate
    docker-compose run app python3 manage.py collectstatic --no-input
    docker-compose up --abort-on-container-exit acceptance
    @ echo App running at http://$$(docker-compose port app 8000 | sed s/0.0.0.0/localhost/g)

publish:
 docker-compose push release app
clean:
    docker-compose down -v
    docker images -q -f dangling=true -f label=application=todobackend | xargs -I ARGS docker rmi -f ARGS
```

自动发布到 ECR

有了这个配置，您的 Docker 镜像现在将被标记为提交哈希和最新标记，然后您只需运行`make publish`命令即可将其发布到 ECR。

现在让我们提交您的更改并运行完整的 Make 工作流来测试、构建和发布您的 Docker 镜像，如下例所示。请注意，一个带有提交哈希`97e4abf`标记的镜像被发布到了 ECR：

```
> git commit -a -m "Add publish tasks"
[master 97e4abf] Add publish tasks
 2 files changed, 12 insertions(+), 1 deletion(-)

> make login
$(aws ecr get-login --no-include-email)
Login Succeeded

> make test && make release
docker-compose build --pull release
Building release
...
...
todobackend_db_1 is up-to-date
Creating todobackend_app_1 ... done
App running at http://localhost:32774
$ make publish
docker-compose push release app
Pushing release (385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:latest)...
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend]
53ca7006d9e4: Layer already exists
ca208f4ebc53: Layer already exists
1702a4329d94: Layer already exists
e2aca0d7f367: Layer already exists
c3e0af9081a5: Layer already exists
20ae2e176794: Layer already exists
cd7100a72410: Layer already exists
latest: digest: sha256:d64e1771440208bde0cabe454f213d682a6ad31e38f14f9ad792fabc51008888 size: 1787
Pushing app (385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend:97e4abf)...
The push refers to repository [385605022855.dkr.ecr.us-east-1.amazonaws.com/docker-in-aws/todobackend]
53ca7006d9e4: Layer already exists
ca208f4ebc53: Layer already exists
1702a4329d94: Layer already exists
e2aca0d7f367: Layer already exists
c3e0af9081a5: Layer already exists
20ae2e176794: Layer already exists
cd7100a72410: Layer already exists
97e4abf: digest: sha256:d64e1771440208bde0cabe454f213d682a6ad31e38f14f9ad792fabc51008888 size: 1787

> make clean
docker-compose down -v
Stopping todobackend_app_1 ... done
Stopping todobackend_db_1 ... done
...
...

> make logout
docker logout https://385605022855.dkr.ecr.us-east-1.amazonaws.com
Removing login credentials for 385605022855.dkr.ecr.us-east-1.amazonaws.com

```

运行更新后的 Make 工作流

# 从 ECR 中拉取 Docker 镜像

现在您已经学会了如何将 Docker 镜像发布到 ECR，让我们专注于在各种场景下运行的 Docker 客户端如何从 ECR 拉取您的 Docker 镜像。回想一下本章开头对 ECR 的介绍，客户端访问 ECR 存在各种场景，我们现在将重点关注这些场景，以 ECS 容器实例作为您的 Docker 客户端：

+   在与您的 ECR 存储库相同的账户中运行的 ECS 容器实例

+   运行在不同账户中的 ECS 容器实例访问您的 ECR 存储库

+   需要访问您的 ECR 存储库的 AWS 服务

# 来自相同账户的 ECS 容器实例对 ECR 的访问

当您的 ECS 容器实例在与您的 ECR 存储库相同的账户中运行时，推荐的方法是使用与运行为 ECS 容器实例的 EC2 实例应用的 IAM 实例角色相关联的 IAM 策略，以使在 ECS 容器实例内运行的 ECS 代理能够从 ECR 中拉取 Docker 镜像。您已经在上一章中看到了这种方法的实际操作，AWS 提供的 ECS 集群向导附加了一个名为`AmazonEC2ContainerServiceforEC2Role`的托管策略到集群中 ECS 容器实例的 IAM 实例角色，并注意到此策略中包含的以下 ECR 权限：

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:CreateCluster",
        "ecs:DeregisterContainerInstance",
        "ecs:DiscoverPollEndpoint",
        "ecs:Poll",
        "ecs:RegisterContainerInstance",
        "ecs:StartTelemetrySession",
        "ecs:Submit*",
        "ecr:GetAuthorizationToken",
 "ecr:BatchCheckLayerAvailability",
 "ecr:GetDownloadUrlForLayer",
 "ecr:BatchGetImage",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

AmazonEC2ContainerServiceforEC2Role 策略

在上面的例子中，您可以看到授予了四个 ECR 权限，这些权限共同允许 ECS 代理登录到 ECR 并拉取 Docker 镜像：

+   `ecr:GetAuthorizationToken`：允许检索有效期为 12 小时的身份验证令牌，可用于使用 Docker CLI 登录到 ECR。

+   `ecr:BatchCheckLayerAvailability`: 检查给定存储库中多个镜像层的可用性。

+   `ecr:GetDownloadUrlForLayer`: 为 Docker 镜像中的给定层检索预签名的 S3 下载 URL。

+   `ecr:BatchGetImage`: 重新获取给定存储库中 Docker 镜像的详细信息。

这些权限足以登录到 ECR 并拉取镜像，但请注意前面示例中的`Resource`属性允许访问您帐户中的所有存储库。

根据您组织的安全要求，对所有存储库的广泛访问可能是可以接受的，也可能不可以接受 - 如果不可以接受，则需要创建自定义 IAM 策略，限制对特定存储库的访问，就像这里演示的那样：

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": [
        "arn:aws:ecr:us-east-1:385605022855:repository/docker-in-aws/todobackend"
      ]
    }
  ]
}
```

授予特定存储库的 ECR 登录和拉取权限

在前面的示例中，请注意`ecr:GetAuthorizationToken`权限仍然适用于所有资源，因为您没有登录到特定的 ECR 存储库，而是登录到给定区域中您帐户的 ECR 注册表。然而，用于拉取 Docker 镜像的其他权限可以应用于单个存储库，您可以看到这些权限仅允许对您的 ECR 存储库的 ARN 进行操作。

请注意，如果您还想要在前面的示例中授予对 ECR 存储库的推送访问权限，则需要额外的 ECR 权限：

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:PutImage",         
        "ecr:InitiateLayerUpload",         
        "ecr:UploadLayerPart",         
        "ecr:CompleteLayerUpload"
      ],
      "Resource": [
        "arn:aws:ecr:us-east-1:385605022855:repository/docker-in-aws/todobackend"
      ]
    }
  ]
}
```

授予特定存储库的 ECR 推送权限

# 来自不同帐户的 ECS 容器实例访问 ECR

在较大的组织中，资源和用户通常分布在多个帐户中，一个常见的模式是拥有一个中央构建帐户，应用程序构件（如 Docker 镜像）在其中进行集中存储。

下图说明了这种情况，您可能有几个帐户运行 ECS 容器实例，这些实例需要拉取存储在您中央存储库中的 Docker 镜像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/5cf82ce0-1580-4267-aa6d-c6bf66054e75.png)需要访问中央 ECR 存储库的多个帐户

当您需要授予其他帐户对您的 ECR 存储库的访问权限时，需要执行两项配置任务：

1.  在托管存储库的帐户中配置 ECR *资源策略*，允许您定义适用于单个 ECR 存储库（这是*资源*）的策略，并定义*谁*可以访问存储库（例如，AWS 帐户）以及*他们*可以执行的*操作*（例如，登录，推送和/或拉取映像）。定义*谁*可以访问给定存储库的能力是允许通过资源策略启用和控制跨帐户访问的关键。例如，在前面的图中，存储库配置为允许来自帐户`333333444444`和`555555666666`的访问。

1.  远程帐户中的管理员需要以 IAM 策略的形式分配权限，以从您的 ECR 存储库中提取映像。这是一种委托访问的形式，即托管 ECR 存储库的帐户信任远程帐户的访问，只要通过 IAM 策略明确授予了访问权限。例如，在前面的图中，ECS 容器实例分配了一个 IAM 策略，允许它们访问帐户`111111222222`中的 myorg/app-a 存储库。

# 使用 AWS 控制台配置 ECR 资源策略

您可以通过打开适当的 ECR 存储库，在**权限**选项卡中选择**添加**来配置 ECS 控制台中的 ECR 资源策略，并单击**添加**以添加新的权限集：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/4dc40247-49ee-463d-ab22-2800808bfd0d.png)配置 ECR 资源策略

在上图中，请注意您可以通过主体设置将 AWS 帐户 ID 配置为主体，然后通过选择**仅拉取操作**选项轻松允许拉取访问。通过此配置，您允许与远程帐户关联的任何实体从此存储库中拉取 Docker 映像。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/c0f530e0-0975-491a-8e31-390eedb7a484.png)配置 ECR 资源策略

请注意，如果您尝试保存前图和上图中显示的配置，您将收到错误，因为我使用了无效的帐户。假设您使用了有效的帐户 ID 并保存了策略，则将为配置生成以下策略文档：

```
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "RemoteAccountAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::*<remote-account-id>*:root"
            },
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability"
            ]
        }
    ]
}
```

示例 ECR 存储库策略文档

# 使用 AWS CLI 配置 ECR 资源策略

您可以使用`aws ecr set-repository-policy`命令通过 AWS CLI 配置 ECR 资源策略，如下所示：

```
> aws ecr set-repository-policy --repository-name docker-in-aws/todobackend --policy-text '{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "RemoteAccountAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::*<remote-account-id>*:root"
            },
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability"
            ]
        }
    ]
}'
```

通过 AWS CLI 配置 ECR 资源策略

如前面的示例所示，您必须使用`--repository-name`标志指定存储库名称，并使用`--policy-text`标志配置存储库策略为 JSON 格式的文档。

# 使用 AWS CloudFormation 配置 ECR 资源策略

在使用 AWS CloudFormation 定义 ECR 存储库时，您可以配置`AWS::ECR::Repository`资源的`RepositoryPolicyText`属性，以定义 ECR 资源策略：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: ECR Repositories

Resources:
  TodobackendRepository:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: docker-in-aws/todobackend
      RepositoryPolicyText:
 Version: "2008-10-17"
 Statement:
 - Sid: RemoteAccountAccess
 Effect: Allow
 Principal:
 AWS: arn:aws:iam::*<remote-account-id>*:root
 Action:
 - ecr:GetDownloadUrlForLayer
 - ecr:BatchGetImage
 - ecr:BatchCheckLayerAvailability
```

使用 AWS CloudFormation 配置 ECR 资源策略

在前面的示例中，策略文本以 YAML 格式表达了您在之前示例中配置的 JSON 策略，并且您可以通过运行`aws cloudformation deploy`命令将更改部署到您的堆栈。

# 配置远程帐户中的 IAM 策略

通过控制台、CLI 或 CloudFormation 配置好 ECR 资源策略后，您可以继续在您的 ECR 资源策略中指定的远程帐户中创建 IAM 策略。这些策略的配置方式与您在本地帐户中配置 IAM 策略的方式完全相同，如果需要，您可以引用远程 ECR 存储库的 ARN，以便仅授予对该存储库的访问权限。

# AWS 服务访问 ECR

我们将讨论的最后一个场景是 AWS 服务访问您的 ECR 镜像的能力。一个例子是 AWS CodeBuild 服务，它使用基于容器的构建代理执行自动化持续集成任务。CodeBuild 允许您定义自己的自定义构建代理，一个常见的做法是将这些构建代理的镜像发布到 ECR 中。这意味着 AWS CodeBuild 服务现在需要访问 ECR，您可以使用 ECR 资源策略来实现这一点。

以下示例扩展了前面的示例，将 AWS CodeBuild 服务添加到资源策略中：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: ECR Repositories

Resources:
  TodobackendRepository:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: docker-in-aws/todobackend
      RepositoryPolicyText:
        Version: "2008-10-17"
        Statement:
          - Sid: RemoteAccountAccess
            Effect: Allow
            Principal:
              AWS: arn:aws:iam::*<remote-account-id>*:root              Service: codebuild.amazonaws.com
            Action:
              - ecr:GetDownloadUrlForLayer
              - ecr:BatchGetImage
              - ecr:BatchCheckLayerAvailability
```

配置 AWS 服务访问 ECR 存储库

在前面的示例中，请注意您可以在`Principal`属性中使用`Service`属性来标识将应用该策略语句的 AWS 服务。在后面的章节中，当您创建自己的自定义 CodeBuild 镜像并发布到 ECR 时，您将看到这一示例的实际操作。

# 配置生命周期策略

如果您在本章中跟随操作，您将已经多次将 todobackend 图像发布到您的 ECR 存储库，并且很可能已经在您的 ECR 存储库中创建了所谓的*孤立图像*。在早期的章节中，我们讨论了在本地 Docker 引擎中创建的孤立图像，并将其定义为其标记已被新图像取代的图像，从而使旧图像无名，并因此“孤立”。

如果您浏览到您的 ECR 存储库并在 ECS 控制台中选择图像选项卡，您可能会注意到您有一些不再具有标记的图像，这是因为您推送了几个带有`latest`标记的图像，这些图像已经取代了现在孤立的图像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/6396f20d-d78c-4511-ab1e-c3a676b92950.png)孤立的 ECR 图像

在前面的图中，请注意您的 ECR 中的存储使用量现在已经增加了三倍，即使您只有一个当前的`latest`图像，这意味着您可能也要支付三倍的存储成本。当然，您可以手动删除这些图像，但这很容易出错，而且通常会成为一个被遗忘和忽视的任务。

幸运的是，ECR 支持一种称为*生命周期策略*的功能，允许您定义包含在策略中的一组规则，管理您的 Docker 图像的生命周期。您应该始终应用于您创建的每个存储库的生命周期策略的标准用例是定期删除孤立的图像，因此现在让我们看看如何创建和应用这样的策略。

# 使用 AWS 控制台配置生命周期策略

在配置生命周期策略时，因为这些策略可能实际删除您的 Docker 图像，最好始终使用 AWS 控制台来测试您的策略，因为 ECS 控制台包括一个功能，允许您模拟如果应用生命周期策略会发生什么。

使用 AWS 控制台配置生命周期策略，选择 ECR 存储库中的**生命周期规则的干运行**选项卡，然后单击**添加**按钮以创建新的干运行规则。这允许您在不实际删除 ECR 存储库中的任何图像的情况下测试生命周期策略规则。一旦您满意您的规则安全地行为并符合预期，您可以将它们转换为实际的生命周期策略，这些策略将应用于您的存储库：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/b3d8f9fb-8e73-4b0a-9fca-b5e329a297df.png)ECR 干运行规则

您现在可以在“添加规则”屏幕中使用以下参数定义规则：

+   **规则优先级**：确定在策略中定义多个规则时的规则评估顺序。

+   **规则描述**：规则的可读描述。

+   **图像状态**：定义规则适用于哪种类型的图像。请注意，您只能有一个指定**未标记**图像的规则。

+   **匹配条件**：定义规则应何时应用的条件。例如，您可以配置条件以匹配自上次推送到 ECR 存储库以来超过七天的未标记图像。

+   **规则操作**：定义应对匹配规则的图像执行的操作。目前，仅支持**过期**操作，将删除匹配的图像。

单击保存按钮后，新规则将添加到**生命周期规则的模拟运行**选项卡。如果您现在单击**保存并执行模拟运行**按钮，将显示符合规则条件的任何图像，其中应包括先前显示的孤立图像。

现在，取决于您是否有未标记的图像以及它们与您最后推送到存储库的时间相比有多久，您可能会或可能不会看到与您的模拟运行规则匹配的图像。无论实际结果如何，关键在于确保与规则匹配的任何图像都是您期望的，并且您确信模拟运行规则不会意外删除您期望发布和可用的有效图像。

如果您对模拟运行规则满意，接下来可以单击**应用为生命周期策略**按钮，首先会显示对新规则的确认对话框，一旦应用，如果您导航到**生命周期策略**选项卡，您应该会看到您的生命周期策略：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-aws/img/5b82b40f-e3f7-4792-aece-cc70583abb0a.png)ECR 生命周期策略

要确认您的生命周期策略是否起作用，您可以单击任何策略规则，然后从“操作”下拉菜单中选择**查看历史记录**，这将显示 ECR 执行的与策略规则相关的任何操作。

# 使用 AWS CLI 配置生命周期策略

AWS CLI 支持与通过 AWS 控制台配置 ECR 生命周期策略类似的工作流程，概述如下：

+   `aws ecr start-lifecycle-policy-preview --repository-name <*name*> --lifecycle-policy-text <*json*>`：对存储库启动生命周期策略的模拟运行

+   `aws ecr get-lifecycle-policy-preview --repository-name <*name*>`：获取试运行的状态

+   `aws ecr put-lifecycle-policy --repository-name <*name*> --lifecycle-policy-text <*json*>`：将生命周期策略应用于存储库

+   `aws ecr get-lifecycle-policy --repository-name <*name*>`：显示应用于存储库的当前生命周期策略

+   `aws ecr delete-lifecycle-policy --repository-name <*name*>`：删除应用于存储库的当前生命周期策略

在使用 CLI 时，您需要以 JSON 格式指定生命周期策略，您可以通过单击前面截图中的“查看 JSON”操作来查看示例。

# 使用 AWS CloudFormation 配置生命周期策略

在使用 AWS CloudFormation 定义 ECR 存储库时，您可以配置之前创建的`AWS::ECR::Repository`资源的`LifecyclePolicy`属性，以定义 ECR 生命周期策略：

```
AWSTemplateFormatVersion: "2010-09-09"

Description: ECR Repositories

Resources:
  TodobackendRepository:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: docker-in-aws/todobackend
      LifecyclePolicy:
 LifecyclePolicyText: |
 {
 "rules": [
 {
 "rulePriority": 10,
 "description": "Untagged images",
 "selection": {
 "tagStatus": "untagged",
 "countType": "sinceImagePushed",
 "countUnit": "days",
 "countNumber": 7
 },
 "action": {
```

```
 "type": "expire"
 }
 }
 ]
 }
```

使用 AWS CloudFormation 配置 ECR 生命周期策略

前面示例中的策略文本表示您在之前示例中配置的 JSON 策略作为 JSON 字符串 - 请注意使用管道（`|`）YAML 运算符，它允许您输入多行文本以提高可读性。

有了这个配置，您可以通过运行`aws cloudformation deploy`命令将更改应用到您的堆栈。

# 总结

在本章中，您学习了如何创建和管理 ECR 存储库，您可以使用它来安全和私密地存储您的 Docker 镜像。创建了第一个 ECR 存储库后，您学会了如何使用 AWS CLI 和 Docker 客户端进行 ECR 身份验证，然后成功地给 ECR 打上标签并发布了您的 Docker 镜像。

发布了您的 Docker 镜像后，您还了解了 Docker 客户端可能需要访问存储库的各种情况，包括来自与您的 ECR 存储库相同账户的 ECS 容器实例访问、来自与您的 ECR 存储库不同账户的 ECS 容器实例访问（即跨账户访问），以及最后授予对 AWS 服务（如 CodeBuild）的访问权限。您创建了 ECR 资源策略，这在配置跨账户访问和授予对 AWS 服务的访问权限时是必需的，并且您了解到，尽管在定义远程账户为受信任的中央账户中创建了 ECR 资源策略，但您仍然需要在每个远程账户中创建明确授予对中央账户存储库访问权限的 IAM 策略。

最后，您创建了 ECR 生命周期策略规则，允许您自动定期删除未标记（孤立）的 Docker 镜像，从而有助于减少存储成本。在下一章中，您将学习如何使用一种流行的开源工具 Packer 构建和发布自己的自定义 ECS 容器实例 Amazon Machine Images（AMIs）。

# 问题

1.  您执行哪个命令以获取 ECR 的身份验证令牌？

1.  真/假：ECR 允许您公开发布和分发 Docker 镜像

1.  如果您注意到存储库中有很多未标记的图像，您应该配置哪个 ECR 功能？

1.  真/假：ECR 以压缩格式存储 Docker 镜像

1.  真/假：配置从相同帐户的 ECS 容器实例访问 ECR 需要 ECR 资源策略

1.  真/假：配置从远程帐户的 ECS 容器实例访问 ECR 需要 ECR 资源策略

1.  真/假：配置从 AWS CodeBuild 访问 ECR 需要 ECR 资源策略

1.  真/假：配置从相同帐户的 ECS 容器实例访问 ECR 需要 IAM 策略

1.  真/假：配置从远程帐户的 ECS 容器实例访问 ECR 需要 IAM 策略

# 进一步阅读

您可以查看以下链接以获取有关本章涵盖的主题的更多信息：

+   ECR 用户指南：[`docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html`](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html)

+   ECR 存储库 CloudFormation 资源：[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecr-repository.html)

+   基于身份和基于资源的策略：[`docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html)

+   ECR 存储库的资源级权限：[`docs.aws.amazon.com/AmazonECR/latest/userguide/ecr-supported-iam-actions-resources.html`](https://docs.aws.amazon.com/AmazonECR/latest/userguide/ecr-supported-iam-actions-resources.html)

+   ECR 的生命周期策略：[`docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html`](https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html)

+   AWS ECR CLI 参考：[`docs.aws.amazon.com/cli/latest/reference/ecr/index.html#cli-aws-ecr`](https://docs.aws.amazon.com/cli/latest/reference/ecr/index.html#cli-aws-ecr)
