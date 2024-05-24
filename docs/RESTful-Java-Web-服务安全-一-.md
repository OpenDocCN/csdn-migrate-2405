# RESTful Java Web 服务安全（一）

> 原文：[`zh.annas-archive.org/md5/28DD94223A475A77126C29F9DB046845`](https://zh.annas-archive.org/md5/28DD94223A475A77126C29F9DB046845)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

使用 Web 服务在计算机系统开发中的固有优势与需要对其进行安全管理的原因是相同的。今天，我们可以说没有一家公司能够完全孤立地工作，而不需要与他人互动、共享和消费信息。此外，这也是任何公司最重要的资产。因此，这些要求在代码行之间也是共同的。本书提供了适用解决方案的真实场景，引导您一路前行，以便您可以轻松学习解决可能出现的最常见需求的解决方案和实施。

RESTful Web 服务相对于基于 SOAP 的服务提供了几个优势。例如，在处理数据类型时，根据您用于创建它们的编程语言或库，使用空值（""）而不是 NULL 时可能会出现不一致。此外，当使用不同版本的库来创建/消费 Web 服务时，可能会在映射复杂对象和文件传输的兼容性问题上遇到困难。在某些情况下，即使从.NET 应用程序中使用 Java 创建的 Web 服务，最终也会在两者之间创建一个在 Java 中实现的服务。这种情况在 RESTful Web 服务中不会发生，因为在这种情况下，功能是通过 HTTP 方法调用公开的。

为了保护信息，安全领域有许多功能可以帮助实现这一目标。例如，了解一些问题，比如身份验证和授权如何协助实现所选机制的实施，其中主要目标是使我们的应用程序更安全，更可靠，是至关重要的。选择每种不同的方式来保护应用程序都与您想要解决的问题相关；为此，我们展示了每种方式的使用场景。

我们经常看到大型组织花费时间和精力来创建自己的实现来处理安全性，而不是使用已经解决了我们需要的标准。通过我们想要与您分享的知识，我们希望避免这种重新发明轮子的过程。

# 本书涵盖的内容

第一章，“设置环境”，帮助我们创建我们的第一个功能应用程序，类似于“Hello World”示例，但具有更多功能，并且非常接近现实世界。本章的主要目的是让我们熟悉我们将要使用的工具。

第二章，“保护 Web 服务的重要性”，介绍了 Java 平台中所有可能的身份验证模型。为了让您更好地理解，我们将一步一步地深入探讨如何利用每个可用的身份验证模型。我们将向您展示信息是如何暴露的，以及如何被第三方拦截，并且我们将使用 Wireshark 进行演示，这是一个非常好的工具来解释它。

最后，在本章中，我们将回顾身份验证和授权之间的区别。这两个概念都非常重要，在安全术语的背景下绝对不可能被忽视。

第三章，“使用 RESTEasy 进行安全管理”，展示了 RESTEasy 如何提供处理安全性的机制，从一个相当基本的模型（粗粒度）开始，到一个更精细的模型（细粒度），在这个模型中，您可以进行更彻底的控制，包括管理不仅配置文件，还有编程文件。

第四章，“RESTEasy Skeleton Key”，帮助我们研究 OAuth 实现以及令牌承载者实现和单点登录。所有这些都是为了限制资源共享的方式。与往常一样，您将亲自动手编写代码并进行真实示例。我们想向您展示，通过这些技术在应用程序之间共享资源和信息已经成为最有用和强大的技术之一，使客户或用户只需使用其凭据一次即可访问多个服务，限制第三方应用程序对您的信息或数据的访问，并通过令牌承载者实施访问控制。您将学会应用这些技术和概念，以构建安全灵活的应用程序。

第五章，“数字签名和消息加密”，帮助我们理解使用简单示例的数字签名的好处；您将注意到消息接收者如何验证发送者的身份。此外，我们将模拟外部代理在传输过程中修改数据，并查看数字签名如何帮助我们检测到它，以避免使用损坏的数据。

最后，我们将解释 SMIME 用于主体加密的工作原理，并通过一个示例来加密请求和响应，以便更好地理解。

# 你需要为这本书做什么

为了在本书中实施和测试所有示例，我们将使用许多免费工具，例如以下工具：

+   Eclipse IDE（或任何其他 Java IDE）

+   JBoss AS 7

+   Maven

+   Wireshark

+   SoapUI

# 这本书适合谁

这本书适用于开发人员、软件分析师、架构师或从事软件开发和 RESTful Web 服务的人员。这本书需要一些关于 Java 或其他语言中面向对象编程概念的先前知识。

不需要先前的安全模型知识，因为我们在本书中解释了理论并在实际示例中应用。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们将修改`web.xml`文件。”

代码块设置如下：

```java
private boolean isUserAllowed(final String username, final String password, final Set<String> rolesSet) {
    boolean isAllowed = false;
    if (rolesSet.contains(ADMIN)) {
      isAllowed = true;
    }
    return isAllowed;
  }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```java
final List<String> authorizationList = headersMap.get(AUTHORIZATION_PROPERTY);

```

任何命令行输入或输出都将以以下方式编写：

```java
mvn clean install

```

**新术语**和**重要**单词以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“从弹出窗口中，选择**SSL 设置**选项卡。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：设置环境

我们诚挚地欢迎您来到我们旅程的第一章。让我们给您一个关于您将在这里实现的想法。阅读完本章后，您将拥有设置开发环境以处理 RESTful Web 服务所需的基本和激动人心的知识。然后，您将熟悉与其相关的一个非常基本的项目的开发。此外，在最后，您将非常清楚地了解如何使用 RESTful Web 服务创建应用程序以及如何实现这一点。本章将为您提供使用这种类型的 Web 服务的信息，以一种非常简单和全面的方式。

在本章中，我们将涵盖以下主题：

+   安装开发环境

+   创建我们的第一个 RESTful Web 服务应用程序

+   测试 RESTful Web 服务

# 下载工具

首先，我们必须获取我们的工作工具，以便投入编码。这里指定的工具在全世界范围内使用，但您可以自由选择您的工具。记住，“工具不会使艺术家”。无论您使用 Windows、MAC OS X 还是 Linux；每个操作系统都有可用的工具。

让我们简要解释一下每个工具的用途。我们将使用 Eclipse 作为我们的 IDE 来开发示例，JBoss AS 7.1.1.Final 作为我们的应用服务器，Maven 来自动化构建过程，并使用 SoapUI 作为测试我们将创建的 Web 服务功能的工具。此外，我们建议您安装最新版本的 JDK，即 JDK 1.7.x。为了帮助，我们已经获取并包含了一些链接，您需要使用这些链接来获取实现第一个示例所需的软件。每个链接都会为您提供有关每个工具的更多信息，如果您还不了解它们，这可能会对您有所帮助。

## 下载链接

必须下载以下工具：

+   Eclipse IDE for Java EE Developers 4.3（[`www.eclipse.org/downloads/`](http://www.eclipse.org/downloads/)）

+   JBoss AS 7.1.1 Final（[`www.jboss.org/jbossas/downloads/`](http://www.jboss.org/jbossas/downloads/)）

+   Apache Maven 3.1.1 或更高版本（[`maven.apache.org/download.cgi`](http://maven.apache.org/download.cgi)）

+   SoapUI 4.6 或更高版本（[`www.soapui.org/`](http://www.soapui.org/)）

+   JDK 1.7.x（[`www.oracle.com/technetwork/java/javase/downloads/jdk7-downloads-1880260.html`](http://www.oracle.com/technetwork/java/javase/downloads/jdk7-downloads-1880260.html)）

# 创建基本项目

为了使构建我们的示例项目的过程更容易，我们将使用 Maven。这个神奇的软件将在眨眼之间创建一个基本项目，我们的项目可以很容易地编译和打包，而不依赖于特定的 IDE。

Maven 使用原型来创建特定类型的项目。原型是预先创建的项目模板；它们允许我们创建各种应用程序，从 Java 桌面应用程序到多模块项目，其中 EAR 可以包含多个工件，如 JAR 和 WAR。它的主要目标是通过提供演示 Maven 许多功能的示例项目，尽快让用户上手运行。如果您想了解更多关于 Maven 的信息，可以访问[`maven.apache.org/`](http://maven.apache.org/)。

然而，我们在这里描述的信息足以继续前进。我们将使用原型来创建一个基本项目；如果我们想更具体，我们将使用原型来创建一个带有 Java 的 Web 应用程序。为此，我们将在终端中输入以下命令行：

```java
mvn archetype:generate

```

当我们在终端中执行这个命令行时，我们将获得 Maven 仓库中所有可用的原型。因此，让我们寻找我们需要的原型，以便创建我们的 Web 应用程序；它的名称是`webapp-javaee6`，属于`org.codehaus.mojo.archetypes`组。此外，我们可以使用一个代表其 ID 的数字进行搜索；这个数字是`557`，如下面的屏幕截图所示。我们建议您按名称搜索，因为数字可能会改变，因为以后可能会添加其他原型：

![创建基本项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_01.jpg)

将会出现几个问题；我们必须为每个问题提供相应的信息。Maven 将使用这些信息来创建我们之前选择的原型，如下面的屏幕截图所示：

![创建基本项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_02.jpg)

您可能已经注意到，每个问题都要求您定义一个属性，每个属性的解释如下：

+   `groupId`：此属性表示公司的域名倒序；这样我们就可以识别出代码的所有者是哪家公司

+   `artifactId`：此属性表示项目的名称

+   `version`：此属性表示项目的版本

+   `package`：此属性表示要添加类的基本包名称

类名和包名共同构成了类的全名。这个全名允许以独特的方式识别类名。有时，当有几个具有相同名称的类时，包名有助于识别它属于哪个库。

下一步是将项目放入 Eclipse 的工作空间；为此，我们必须通过**文件** | **导入** | **Maven** | **现有的 Maven 项目**来将我们的项目导入 Eclipse。

我们应该在 IDE 中看到项目，如下面的屏幕截图所示：

![创建基本项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_03.jpg)

在继续之前，让我们解决`pom.xml`文件中出现的问题。

下面代码中显示的错误与来自 Eclipse 和 Maven 集成的错误有关。为了解决这个问题，我们必须在`<build>`标签之后添加`<pluginManagement>`标签。

`pom.xml`文件应该如下所示：

```java
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.packtpub</groupId>
  <artifactId>resteasy-examples</artifactId>
  <version>1.0-SNAPSHOT</version>
  <packaging>war</packaging>

  . . .

  <build>
 <pluginManagement>
      <plugins>
        <plugin>
          . . .
        </plugin>
      </plugins>
 </pluginManagement>
  </build>

</project>
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。此外，我们强烈建议从 GitHub 上获取可在[`github.com/restful-java-web-services-security`](https://github.com/restful-java-web-services-security)上获得的源代码。

这将修复错误，现在我们只需要更新项目中 Maven 的配置，如下面的屏幕截图所示：

![创建基本项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_04.jpg)

刷新项目后，错误应该消失，因为当我们更新 Maven 的配置时，实际上是在更新我们项目的依赖项，比如缺少的库。通过这样做，我们将把它们包含在我们的项目中，错误将消失。

在`src/main/webapp`路径下，让我们创建`WEB-INF`文件夹。

现在，在`WEB-INF`文件夹中，我们将创建一个名为`web.xml`的新文件，内容如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.0" 

  xsi:schemaLocation="http://java.sun.com/xml/ns/javaee 
  http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">
</web-app>
```

当您保护您的应用程序时，这个文件非常有用；这一次，我们将在没有任何配置的情况下创建它。目前，`/WEB-INF`文件夹和`web.xml`文件只定义了 Web 应用程序的结构。

# 第一个功能示例

现在我们的开发环境已经设置好了，是时候动手写第一个 RESTful web 服务了。由于我们使用的是 JBoss，让我们使用 JAX-RS 的 RESTEasy 实现。我们将开发一个非常简单的示例；假设您想要实现一个保存和搜索人员信息的服务。

首先，我们创建一个简单的`Person`领域类，它使用 JAXB 注解。JAXB 在 XML 和 Java 之间进行对象的编组/解组。在这个例子中，我们将把这些实例存储在内存缓存中，而不是数据库中。在 JEE 中，这通常表示关系数据库中的一个表，每个实体实例对应该表中的一行，如下面的代码所示：

```java
package com.packtpub.resteasy.entities;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "person")
@XmlAccessorType(XmlAccessType.FIELD)
public class Person {

  @XmlAttribute
  protected int id;

  @XmlElement
  protected String name;

  @XmlElement
  protected String lastname;

  public int getId() {
    return id;
  }

  public void setId(int id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getLastname() {
    return lastname;
  }

  public void setLastname(String lastname) {
    this.lastname = lastname;
  }

}
```

接下来，我们在`com.packtpub.resteasy.services`包中创建一个名为`PersonService`的新类。这个类将有两个方法；一个用于注册新的人员，另一个用于按 ID 搜索人员。这个类将使用内存映射缓存来存储人员。

该服务将有以下实现：

```java
package com.packtpub.resteasy.services;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import com.packtpub.resteasy.entities.Person;

@Path("/person")
public class PersonService {
  private Map<Integer, Person> dataInMemory;
  public PersonService() {
    dataInMemory = new HashMap<Integer, Person>();
  }

  @POST
  @Consumes("application/xml")
  public Response savePerson(Person person) {
    int id = dataInMemory.size() + 1;
    person.setId(id);
    dataInMemory.put(id, person);
    return Response.created(URI.create("/person/" + id)).build();
  }

  @GET
  @Path("{id}")
  @Produces("application/xml")
  public Person findById(@PathParam("id") int id) {
    Person person = dataInMemory.get(id);
    if (person == null) {
      throw new WebApplicationException(Response.Status.NOT_FOUND);
    }
    return person;
  }
}
```

`@Path`注解定义了 URL 中的路径，该路径将在此类中编写的功能中可用。用`@Post`注解的方法表示应该进行 HTTP POST 请求。此外，它用`@Consumes`注解，并使用`application`/`xml`值；这意味着 POST 请求将以 XML 格式的字符串执行，其中包含要保存的人员的信息。另一方面，要通过 ID 查找一个人，你必须进行 HTTP GET 请求。URL 必须以与方法上的`@Path`注解指示的方式指示 ID。`@Produces`注解表示我们将以 XML 格式获得响应。最后，请注意，参数 ID，如`@Path`注解中所示，被用作方法的参数，使用`@PathParam`注解。

最后，我们编写一个类，它将扩展`Application`类，并将我们刚刚创建的服务设置为单例。这样，信息在每个请求中不会丢失，我们将把它保存在内存中，如下所示：

```java
package com.packtpub.resteasy.services;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationPath("/services")
public class MyRestEasyApplication extends Application {

  private Set<Object> services;

  public MyRestEasyApplication() {
    services = new HashSet<Object>();
    services.add(new PersonService());
  }

  @Override
  public Set<Object> getSingletons() {
    return services;
  }
}
```

请注意，由于我们使用 JAXB 映射了我们的实体，我们的方法在 XML 格式中消耗和产生信息。

为了在 JBoss 中部署我们的应用程序，我们应该在`pom.xml`文件中添加一个依赖项。这个依赖项必须引用 JBoss 插件。我们必须更改`pom.xml`中生成的构件名称。默认值是`artifactId`文件，后跟版本；例如，`resteasy-examples-1.0-snapshot.war`。我们将设置它，所以我们将只使用`artifactId`文件；在这种情况下，`resteasy-examples.war`。所有这些配置必须包含、修改和实现在`pom.xml`中，如下面的 XML 代码所示：

```java
  <build>
 <finalName>${artifactId}</finalName>
    <pluginManagement>
      <plugins>
        <plugin>
          <groupId>org.jboss.as.plugins</groupId>
          <artifactId>jboss-as-maven-plugin</artifactId>
          <version>7.5.Final</version>
          <configuration>
            <jbossHome>/pathtojboss/jboss-as-7.1.1.Final</jbossHome>
          </configuration>
        </plugin>
        ...
        </plugin>
      </plugins>
    </pluginManagement>
  </build>
```

您应该更改`jbossHome`属性的值为您的 JBoss 安装路径。之后，我们将使用命令终端；前往项目目录，并输入`mvn jboss-as:run`。如果在执行命令后对代码进行任何更改，则应使用以下命令以查看更改：

```java
mvn jboss-as:redeploy

```

Run 和 redeploy 是这个插件的目标。如果您想了解有关此插件的更多目标，请访问[`docs.jboss.org/jbossas/7/plugins/maven/latest/`](https://docs.jboss.org/jbossas/7/plugins/maven/latest/)。这将再次编译所有项目类；然后将其打包以创建`.war`文件。最后，修改将部署到服务器上。如果一切正常，我们应该在终端看到一条消息，说明部署已成功完成，如下面的截图所示：

![第一个功能示例](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_05.jpg)

本章的源代码可在 GitHub 的以下位置找到：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter01`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter01)

## 测试示例 Web 服务

此时，我们将测试我们刚刚创建的功能。我们将使用 SoapUI 作为我们的测试工具；确保您使用最新版本，或者至少是 4.6.x 或更高版本，因为这个版本提供了更多功能来测试 RESTful Web 服务。让我们从执行以下步骤开始：

1.  从主菜单开始，让我们通过导航到**文件** | **新建 REST 项目**来创建一个新的 REST 项目，如下面的屏幕截图所示：![测试示例 Web 服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_06.jpg)

1.  设置我们服务的 URI，如下所示：![测试示例 Web 服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_07.jpg)

1.  之后，让我们使用工作区的`POST`方法创建一个新的人。在**媒体类型**字段中，选择**application/xml**，并使用包含信息的 XML 字符串进行请求，如下文所示：

```java
<person><name>Rene</name><lastname>Enriquez</lastname></person>
```

1.  当我们点击**播放**按钮时，我们应该得到一个答案，其中显示了创建的资源 URI（超链接"`http://localhost:8080/resteasy-examples/services/person/1`"），如下面的屏幕截图所示：![测试示例 Web 服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_08.jpg)

1.  如果我们在 SoapUI 的**资源**文本框中更改 URI 并使用`GET`方法，它将显示我们刚刚输入的数据，如下面的屏幕截图所示：![测试示例 Web 服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_01_09.jpg)

恭喜！我们已经开发了我们的第一个功能性的 RESTful Web 服务，具有两个功能。第一个是将人们的信息保存在内存中，第二个是通过 ID 检索人们的信息。

### 注意

如果重新启动 JBoss 或重新部署应用程序，所有数据将丢失。在搜索人员信息之前，您必须先保存数据。

# 总结

在本章中，我们创建了我们的第一个功能性应用程序——类似于*hello world*示例，但具有更接近真实世界的功能。

在本章中，我们涵盖的基本部分是熟悉我们将使用的工具。在后面的章节中，我们将假设这些概念已经清楚。例如，当使用 SoapUI 时，我们将逐步向前推进，因为这是一个将简化我们将要开发的功能测试任务的工具。这样，我们就可以避免为 Web 服务客户端编写代码的任务。

现在我们准备好审查下一章，其中包含 Java 提供的一些安全模型。我们将了解每一个模型，并学习如何实现它们。


# 第二章：保护 Web 服务的重要性

看看你，你已经到了第二章；恭喜！这一章非常重要，因为它与软件中隐含的概念相关，即**安全性**。这非常重要，因为软件被公司和像我们这样的人使用。有时，我们通过软件共享非常重要和机密的信息，这就是为什么这个主题对每个人都如此重要。

在本章中，我们将带您了解与计算机系统安全管理相关的基本方面。

我们将探索和实施不同的安全机制以及可以使用它们的场景。

此外，您将学习如何使用协议分析器。这将使我们能够演示攻击如何执行以及攻击达到目标时的影响，本例中是我们的信息。此外，您将能够想象更多的选项来在 Web 服务中实施安全性。

由于一切都需要实践，您将通过一个简单的代码示例了解认证和授权之间的区别。准备好迎接一个有趣且有用的主题。

在本章中，我们将涵盖以下内容：

+   理解安全管理的重要性

+   探索和实施不同的安全机制

+   使用协议分析器拦截请求

+   理解认证和授权之间的区别

# 安全性的重要性

在设计应用程序时，安全管理是需要考虑的主要方面之一。

无论如何，组织的功能或信息都不能对所有用户完全开放而没有任何限制。考虑一个人力资源管理应用程序的情况，它允许您查询员工的工资，例如：如果公司经理需要了解其员工的工资，这并不是什么重要的事情。然而，在同样的情境中，想象一下其中一名员工想要了解其同事的工资；如果对这些信息的访问完全开放，可能会在工资不同的员工之间产生问题。

更为关键的例子可能是银行 XYZ 每当客户或第三方使用 ATM 向其账户之一存款时都会增加银行余额。IT 经理设想这种功能可能会很普遍，并决定将其实施为 Web 服务。目前，此功能仅限于登录到使用此 Web 服务的应用程序的银行用户。假设 IT 经理对未来的设想成真，并且现在需要从 ATM 进行此功能；提出这一要求迅速表明此功能已实施，并且可以通过调用 Web 服务来使用。到目前为止，可能没有安全漏洞，因为 ATM 可能具有控制访问的安全系统，因此操作系统对 Web 服务功能的访问也间接受到控制。

现在，想象一下，公司 ABC 想要一个类似的功能，以增加其员工银行账户中的余额，以表彰其对公司的某种贡献。Web 服务的功能会发生什么变化？您认为您可以再次信任处理自己安全方案的应用程序来控制对其功能的访问吗？即使我们信任这种机制，如果请求被嗅探器拦截会怎么样？那么，任何知道如何执行请求的人都可以增加余额。这些问题在回答时以相当合乎逻辑的方式得到了解答。因此，这些场景现在听起来相当合乎逻辑，因此，认证用户以访问此功能的是 Web 服务，并且应该在任何情况下都信任其管理方案安全系统。无论调用是来自组织本身还是来自外部机构，都必须存在安全控制，以暴露像我们刚刚概述的这样的敏感功能。

在通过 Web 服务共享现有信息或功能时，众所周知，我们不依赖于编程语言、架构或系统平台进行交互。这使我们具有灵活性，并使我们免于重写现有功能。此外，我们应该了解这些功能对数据机密性的影响，因为我们将与实体或系统共享信息和/或功能。这样，我们可以实现业务目标，并确保入侵者无法阅读我们的信息；甚至更糟的是，未经授权的第三方可以访问我们的服务所暴露的功能。因此，对它们的访问必须进行严格分析，并且我们暴露的服务必须得到正确的保障。

# 安全管理选项

Java 提供了一些安全管理选项。现在，我们将解释其中一些，并演示如何实现它们。所有认证方法实际上都基于客户端向服务器传递凭据。有几种方法可以执行这一点，包括：

+   基本认证

+   摘要认证

+   客户端证书认证

+   使用 API 密钥

使用 Java 构建的应用程序的安全管理，包括具有 RESTful Web 服务的应用程序，始终依赖于 JAAS。

Java 身份验证和授权服务（JAAS）是 Java 平台企业版的一部分。因此，它是处理 Java 应用程序安全性的默认标准；它允许您实现授权，并允许对应用程序进行身份验证控制，以保护属于应用程序的资源。如果您想了解更多关于 JAAS 的信息，可以查看以下链接：

[`docs.oracle.com/javase/7/docs/technotes/guides/security/jaas/tutorials/GeneralAcnOnly.html`](http://docs.oracle.com/javase/7/docs/technotes/guides/security/jaas/tutorials/GeneralAcnOnly.html)

如果您不想使用 JAAS，当然可以创建我们自己的实现来处理安全性，但这将很困难。那么，为什么不通过实现这项有用的技术来节省时间、精力和平静呢？建议尽可能使用标准实现。在我们的开发练习中，我们将使用 JAAS 来进行前三种认证方法。

## 授权和认证

当您使用这些术语时，很容易感到困惑，但在安全系统方法中，它们具有不同的含义。为了澄清这些术语，我们将在本节中对它们进行解释。

### 认证

简而言之，这个术语指的是*您是谁*。这是识别用户的过程，通常通过他们的*用户名*和*密码*。当我们使用这个概念时，我们试图确保用户的身份，并验证用户声称的身份。此外，这与用户的访问权限无关。

安全研究已经指定了一系列应该验证的因素，以实现积极的身份验证。这个清单包含三个元素，通常使用其中两个是很常见的，但最好使用全部。这些元素包括：

+   **知识因素**：这个元素意味着用户**知道**的东西，例如密码、口令或个人识别号码（PIN）。另一个例子是挑战响应，用户必须回答问题，软件令牌或作为软件令牌的电话。

+   **所有权因素**：这是用户*拥有*的东西，例如手环（在物理身份验证的情况下）、身份证、安全令牌或带有内置硬件令牌的手机。

+   **固有因素**：这是用户*是*或*做*的东西，例如指纹或视网膜图案、DNA 序列、签名、面部、声音、独特的生物电信号或其他生物识别标识符。

### 授权

简而言之，这个术语指的是*您可以做什么*。这是给用户权限做或拥有某些东西的过程。当我们谈论软件时，我们有一个系统管理员负责定义用户被允许访问的系统以及使用权限（例如访问哪些文件目录，访问期限，分配的存储空间等）。

授权通常被视为系统管理员设置权限的初始设置，以及在用户获取访问权限时检查已经设置的权限值。

## 访问控制

身份验证和授权的一个非常常见的用途是访问控制。一个计算机系统只能被授权用户使用，必须试图检测和拒绝未经授权的用户。访问由坚持身份验证过程来控制，以建立用户的身份并赋予特定身份的特权。让我们举一些涉及不同场景中身份验证的访问控制的例子，例如：

+   当承包商第一次到达房屋进行工作时要求身份证照片

+   实施验证码作为验证用户是人类而不是计算机程序的一种方式

+   在使用像手机这样的电信网络设备获得的**一次性密码**（**OTP**）作为身份验证密码/PIN 时

+   一个计算机程序使用盲凭证来验证另一个程序

+   当您用护照进入一个国家时

+   当您登录计算机时

+   当一个服务使用确认电子邮件来验证电子邮件地址的所有权

+   使用互联网银行系统

+   当您从 ATM 取款时

有时，便利性会与访问检查的严格性相抵触。例如，一个小额交易通常不需要经过认证人的签名作为交易授权的证明。

然而，安全专家认为不可能绝对确定用户的身份。只能应用一系列测试，如果通过，就被先前声明为确认身份的最低要求。问题在于如何确定哪些测试足够；这取决于公司来确定这个集合。

### 传输层安全

在这一部分，我们强调了 TLS 的一些主要特点：

+   它的前身是**安全套接字层**（**SSL**）

+   这是一个加密协议

+   它提供了互联网上的安全通信

+   它通过 X.509 证书（非对称加密）对对方进行身份验证

+   它允许客户端-服务器应用程序在网络上进行通信，并防止窃听和篡改

+   TLS 通常实现在传输层协议之上

+   它封装了特定于应用程序的协议，如 HTTP、FTP、SMTP、NNTP 和 XMPP

+   应该委托使用 TLS，特别是在执行凭据、更新、删除和任何类型的价值交易时

+   TLS 在现代硬件上的开销非常低，延迟略有增加，但这为最终用户提供了更多的安全性

## 通过提供用户凭据进行基本身份验证

可能，基本身份验证是所有类型应用程序中最常用的技术之一。在用户获得应用程序功能之前，会要求用户输入用户名和密码。两者都经过验证，以验证凭据是否正确（它们属于应用用户）。我们 99%确定您至少曾经执行过这种技术，也许是通过自定义机制，或者如果您使用了 JEE 平台，可能是通过 JAAS。这种控制被称为**基本身份验证**。

这种安全实现的主要问题是凭据以明文方式从客户端传播到服务器。这样，任何嗅探器都可以读取网络上传送的数据包。我们将考虑一个使用名为 Wireshark 的工具的示例；它是一个协议分析器，将显示这个问题。有关安装，我们可以转到链接[`www.wireshark.org/download.html`](http://www.wireshark.org/download.html)。

安装非常基本（一路点击“下一步”）。因此，我们不会展示这些步骤的截图。

现在，我们将修改第一章中的项目，*设置环境*，在该项目中，用户尝试调用 Web 服务的任何功能。用户将被要求输入用户名和密码；一旦这些验证通过，用户将可以访问 Web 服务功能。

为了有一个可工作的示例，让我们启动我们的应用服务器 JBoss AS 7；然后，转到`bin`目录并执行文件`add-user.bat`（对于 UNIX 用户是`.sh`文件）。最后，我们将创建一个新用户，如下所示：

![通过提供用户凭据进行基本身份验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_01.jpg)

这里最重要的是，您应该在第一个问题中选择“应用用户”并为其分配“管理员”角色。这将与`web.xml`文件中定义的信息相匹配，稍后在我们应用程序内实现安全性时将进行解释。结果，我们将在`JBOSS_HOME/standalone/configuration/application - users.properties`文件中拥有一个新用户。

JBoss 已经设置了一个名为`other`的默认安全域；此域使用我们前面提到的文件中存储的信息进行身份验证。现在，我们将配置应用程序以在`resteasy-examples`项目的`WEB-INF`文件夹中使用此安全域。让我们创建一个名为`jboss-web.xml`的文件，其中包含以下内容：

```java
<?xml version="1.0" encoding="UTF-8"?>
<jboss-web>
  <security-domain>other</security-domain>
</jboss-web>
```

好了，让我们配置文件`web.xml`以聚合安全约束。在下面的代码块中，您将看到应添加的内容。

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.0" 

  xsi:schemaLocation="http://java.sun.com/xml/ns/javaee 
  http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">
 <!-- Roles -->
 <security-role>
 <description>Any rol </description>
 <role-name>*</role-name>
 </security-role>

 <!-- Resource / Role Mapping -->
 <security-constraint>
 <display-name>Area secured</display-name>
 <web-resource-collection>
 <web-resource-name>protected_resources</web-resource-name>
 <url-pattern>/services/*</url-pattern>
 <http-method>GET</http-method>
 <http-method>POST</http-method>
 </web-resource-collection>
 <auth-constraint>
 <description>User with any role</description>
 <role-name>*</role-name>
 </auth-constraint>
 </security-constraint>

 <login-config>
 <auth-method>BASIC</auth-method>
 </login-config>
</web-app>
```

从终端，让我们转到`resteasy-examples`项目的主文件夹，并执行`mvn jboss-as:redeploy`。现在，我们将测试我们的 Web 服务，就像我们在第一章中所做的那样，*设置环境*，使用 SOAP UI。我们将使用`POST`方法向 URL`http://localhost:8080/resteasy-examples/services/person/`发出请求，并使用以下 XML：

```java
<person><name>Rene</name><lastname>Enriquez</lastname></person>
```

我们得到以下响应：

![通过提供用户凭据进行基本身份验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_02.jpg)

SOAP UI 向我们显示了 HTTP 401 错误，这意味着请求未经授权。这是因为我们在没有向服务器提供凭据的情况下执行了请求。为了做到这一点，我们必须点击 SOAP UI 左下角的(**…**)按钮，并输入我们刚刚创建的用户凭据，如下截图所示：

![通过提供用户凭据进行基本认证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_03.jpg)

现在是启用我们的流量分析器的时候了。让我们启动 Wireshark，并设置它来分析环回地址内的流量。从**主**菜单，导航到**捕获** | **接口**。

勾选**lo0**选项，如下截图所示，然后点击**开始**按钮。这样，所有通过地址 127.0.0.1 或其等效的本地主机的流量都将被拦截进行分析。

此外，在“过滤器”字段中，我们将输入`http`，以拦截 HTTP 请求和响应，如后面的截图所示：

![通过提供用户凭据进行基本认证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_04.jpg)

看一下以下截图：

![通过提供用户凭据进行基本认证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_05.jpg)

完成这一步后，我们将从 SOAP UI 执行请求操作。再次，SOAP UI 向我们显示了一个 HTTP 201 消息；这次，请求成功处理。您可以在 Wireshark 中看到以下信息列：

+   **编号**：这一栏以唯一方式标识了请求或响应

+   **时间**：这一栏标识了执行操作所需的时间

+   **源**：这一栏标识了请求/响应的发起地址

+   **目的地**：这一栏标识了执行 HTTP 请求/响应的目标 IP 地址

+   **协议**：这一栏标识了请求/响应所执行的协议

+   **长度**：这一栏标识了请求/响应的长度

+   **信息**：这一栏标识了与请求/响应相关的信息

现在，是时候在 Wireshark 上观察信息流量了，如下所示：

![通过提供用户凭据进行基本认证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_06.jpg)

注意 Wireshark 如何显示我们正在使用 HTTP 协议执行 POST（信息）操作，使用 XML 字符串（协议）发送到目标地址`127.0.0.1`（目的地）。此外，您可以读取用户名和密码。因此，这种方法对安全实施来说并不是很安全，因为任何人都可以访问这些信息并进行网络钓鱼攻击。

您可以在以下 URL 找到本章的源代码：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter02/basic-authentication`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter02/basic-authentication)

## 摘要访问认证

这种认证方法利用哈希函数对用户输入的密码进行加密，然后再发送到服务器。显然，这比基本认证方法要安全得多，基本认证方法中，用户的密码以明文形式传输，任何拦截它的人都可以轻易读取。为了克服这些缺点，摘要 md5 认证对用户名、应用安全领域和密码的值进行组合，并应用一个函数。结果，我们得到一个加密字符串，几乎无法被入侵者解释。

为了更好地理解这个过程，我们将向您展示一个简单的解释，摘自维基百科。

### 一个带解释的例子

*以下示例最初在 RFC 2617 中给出，这里扩展显示了每个请求和响应所期望的完整文本。请注意，此处仅涵盖了`auth`（身份验证）保护代码——在撰写本文时，已知只有 Opera 和 Konqueror 网络浏览器支持`auth-int`（带完整性保护的身份验证）。尽管规范提到了 HTTP 版本 1.1，但该方案可以成功地添加到版本 1.0 服务器，如下所示。*

*此典型交易包括以下步骤：*

*客户端请求需要身份验证的页面，但未提供用户名和密码。通常，这是因为用户只是输入了地址或者点击了页面链接。*

*服务器以 401“未经授权”的响应代码做出响应，提供身份验证领域和一个名为`nonce`的随机生成的一次性值。*

*此时，浏览器将向用户呈现身份验证领域（通常是正在访问的计算机或系统的描述）并提示输入用户名和密码。用户可以决定在这一点上取消。*

*一旦提供了用户名和密码，客户端会重新发送相同的请求，但会添加一个包含响应代码的身份验证标头。*

*在这个例子中，服务器接受了身份验证并返回了页面。如果用户名无效和/或密码不正确，服务器可能会返回*401*响应代码，客户端将再次提示用户。*

### 注意

客户端可能已经具有所需的用户名和密码，而无需提示用户，例如，如果它们以前已被 Web 浏览器存储。

如果您想了解更多关于这种机制的信息，可以访问维基百科，查看完整文章，链接如下[`en.wikipedia.org/wiki/Digest_access_authentication`](http://en.wikipedia.org/wiki/Digest_access_authentication)。

您还可以阅读规范 RFC 2617，该规范可在[`www.ietf.org/rfc/rfc2617.txt`](https://www.ietf.org/rfc/rfc2617.txt)上找到。

现在，让我们在我们的示例中测试这种机制。

为了开始，我们必须确保环境变量`JAVA_HOME`已经设置并添加到`PATH`变量中。因此，您可以通过在终端中输入以下命令来确定：

```java
java -version

```

这将显示以下截图中显示的信息：

![带解释的示例](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_07.jpg)

这个命令显示了我们 PC 上安装的 Java 版本。如果您获得的是错误而不是之前的输出，您应该创建环境变量`JAVA_HOME`，将其添加到`PATH`变量中，并重复验证。

现在，为了执行我们之前解释的内容，我们需要为我们的示例用户生成一个密码。我们必须使用我们之前讨论的参数——用户名、领域和密码来生成密码。让我们从终端进入`JBOSS_HOME/modules/org/picketbox/main/`目录，并输入以下内容：

`java -cp picketbox-4.0.7.Final.jar org.jboss.security.auth.callback.RFC2617Digest username MyRealmName password`

我们将获得以下结果：

```java
RFC2617 A1 hash: 8355c2bc1aab3025c8522bd53639c168

```

通过这个过程，我们获得了加密密码，并在我们的密码存储文件（`JBOSS_HOME/standalone/configuration/application-users.properties`文件）中使用它。我们必须替换文件中的密码，并且它将用于用户`username`。我们必须替换它，因为旧密码不包含应用程序的领域名称信息。作为替代方案，您可以使用文件`add-user.sh`创建一个新用户；您只需在被请求时提供领域信息。

为了使我们的应用程序工作，我们只需要在`web.xml`文件中进行一点修改。我们必须修改`auth-method`标签，将值`FORM`更改为`DIGEST`，并以以下方式设置应用程序领域名称：

```java
<login-config>

  <auth-method>DIGEST</auth-method>

  <realm-name>MyRealmName</realm-name>  
</login-config>
```

现在，让我们在 JBoss 中创建一个新的安全域，以便我们可以管理`DIGEST`身份验证机制。在`JBOSS_HOME/standalone/configuration/standalone.xml`文件的`<security-domains>`部分中，让我们添加以下条目：

```java
<security-domain name="domainDigest" cache-type="default"> <authentication>
    <login-module code="UsersRoles" flag="required"> <module-option name="usersProperties" value="${jboss.server.config.dir}/application-users.properties"/> <module-option name="rolesProperties" value="${jboss.server.config.dir}/application-roles.properties"/> <module-option name="hashAlgorithm" value="MD5"/> <module-option name="hashEncoding" value="RFC2617"/>
      <module-option name="hashUserPassword" value="false"/>
      <module-option name="hashStorePassword" value="true"/>
      <module-option name="passwordIsA1Hash" value="true"/> 
      <module-option name="storeDigestCallback" value="org.jboss.security.auth.callback.RFC2617Digest"/> </login-module>
  </authentication>
</security-domain>
```

最后，在应用程序中，更改文件`jboss-web.xml`中的安全域名称，如下面的代码所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<jboss-web>
  <security-domain>java:/jaas/domainDigest</security-domain>
</jboss-web>
```

我们将在`web.xml`文件中将身份验证方法从`BASIC`更改为`DIGEST`。此外，我们将输入安全域的名称。所有这些更改必须以以下方式应用于`login-config`标签：

```java
<login-config>
  <auth-method>DIGEST</auth-method>
  <realm-name>MyRealmName</realm-name
</login-config>
```

现在，重新启动应用服务器并在 JBoss 上重新部署应用程序。为此，在终端命令行中执行以下命令：

```java
mvn jboss-as:redeploy
```

让我们通过 Wireshark 启用流量捕获，并使用 SOAP UI 再次测试 Web 服务。首先，我们应该将`Authentication Type`字段从全局 HTTP 设置更改为**SPNEGO/Kerberos**。一个非常有用的技巧是告诉 SOAP UI 不要使用基本身份验证方法。一旦我们执行请求，Wireshark 将告诉我们以下截图中显示的消息：

![带解释的示例](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_08.jpg)

正如屏幕截图所示，让我们首先确认在此身份验证方法中执行了前面描述的所有步骤。让我们使用 Wireshark 中的**No**字段进行跟踪：

在第 5 步中，执行请求。

在第 7 步中，服务器返回带有生成的`nonce`值的错误消息代码 HTTP 401。`nonce`值有助于避免重放攻击。

在第 9 步中，再次执行请求。这次，所需的身份验证信息包括，并且所有这些信息都以与我们之前描述的相同的方式进行加密。

最后，在第 11 步中，我们获得了响应，告诉我们请求已成功执行。

正如您所注意到的，这是一种更安全的身份验证方法，主要用于如果您不想通过 TLS/SSL 加密进行完整传输安全的开销。

您可以在以下 URL 找到本章的源代码：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter02/digest-authentication`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter02/digest-authentication)

## 通过证书进行身份验证

这是一种机制，通过该机制，在服务器和客户端之间建立了信任协议，通过证书进行。它们必须由一个旨在确保用于身份验证的证书是合法的机构签署，这就是所谓的 CA。

让我们想象一个使用这种安全机制的应用程序。当客户端尝试访问受保护的资源时，它不是提供用户名或密码，而是向服务器呈现证书。这是包含用户信息用于身份验证的证书；换句话说，除了唯一的私钥-公钥对之外，还包括凭据。服务器通过 CA 确定用户是否合法。然后，它验证用户是否有权访问资源。此外，您应该知道，此身份验证机制必须使用 HTTPS 作为通信协议，因为我们没有安全通道，任何人都可以窃取客户端的身份。

现在，我们将展示如何在我们的例子中执行此操作。

在我们的例子中，我们把自己变成了 CA；它们通常是 VERISIGN 或其他公司。然而，由于我们想要为您节省金钱，我们将以这种方式进行。我们需要的第一件事是 CA 的密钥（也就是我们自己），我们将为应用服务器和用户签署证书。由于本书的目的是解释这种方法的工作原理，而不是如何生成证书，我们不会包括生成证书所需的所有步骤，但我们会在 GitHub 上的以下链接中包含它们：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter02/client-cert-authentication`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter02/client-cert-authentication)

好的，让我们开始。首先，将`server.keystore`和`server.trutstore`文件复制到文件夹目录`JBOSS_HOME/standalone/configuration/`中。您可以使用以下链接从 GitHub 下载这些文件：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter02/client-cert-authentication/certificates`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter02/client-cert-authentication/certificates)

现在，正如我们之前提到的，此安全机制要求我们的应用程序服务器使用 HTTPS 作为通信协议。因此，我们必须启用 HTTPS。让我们在`standalone.xml`文件中添加一个连接器；查找以下行：

```java
<connector name="http"
```

添加以下代码块：

```java
<connector name="https" protocol="HTTP/1.1" scheme="https" socket-binding="https" secure="true">
  <ssl password="changeit" 
certificate-key-file="${jboss.server.config.dir}/server.keystore" 
verify-client="want" 
ca-certificate-file="${jboss.server.config.dir}/server.truststore"/>

</connector>
```

接下来，我们添加安全域，如下所示：

```java
<security-domain name="RequireCertificateDomain">
                    <authentication>
    <login-module code="CertificateRoles" flag="required">
                            <module-option name="securityDomain" value="RequireCertificateDomain"/>
                            <module-option name="verifier" value="org.jboss.security.auth.certs.AnyCertVerifier"/>
                            <module-option name="usersProperties" value="${jboss.server.config.dir}/my-users.properties"/>
                            <module-option name="rolesProperties" value="${jboss.server.config.dir}/my-roles.properties"/>
                        </login-module>
  </authentication>
  <jsse keystore-password="changeit" keystore-url="file:${jboss.server.config.dir}/server.keystore" 
                        truststore-password="changeit" truststore-url="file:${jboss.server.config.dir}/server.truststore"/>
                </security-domain>
```

正如您所看到的，我们需要两个文件：`my-users.properties`和`my-roles.properties`；两者都为空，并位于`JBOSS_HOME/standalone/configuration`路径中。

我们将以以下方式在`web.xml`文件中添加`<user-data-constraint>`标签：

```java
<security-constraint>
...<user-data-constraint>

  <transport-guarantee>CONFIDENTIAL</transport-guarantee>
  </user-data-constraint>
</security-constraint>
```

然后，更改身份验证方法为`CLIENT-CERT`，如下所示：

```java
  <login-config>
    <auth-method>CLIENT-CERT</auth-method>
  </login-config>
```

最后，在`jboss-web.xml`文件中以以下方式更改安全域：

```java
<?xml version="1.0" encoding="UTF-8"?>
<jboss-web>
  <security-domain>RequireCertificateDomain</security-domain>
</jboss-web>
```

现在，重新启动应用程序服务器，并使用以下命令使用 Maven 重新部署应用程序：

```java
mvn jboss-as:redeploy
```

为了测试这种身份验证方法，我们首先必须在 SOAP UI 中执行一些配置。首先，让我们转到安装目录，找到文件`vmoptions.txt`，并添加以下行：

```java
-Dsun.security.ssl.allowUnsafeRenegotiation=true

```

现在，我们将更改 SOAP UI 的 SSL 设置。为此，您必须从主菜单中导航到**文件** | **首选项**。

从弹出窗口中，选择**SSL 设置**选项卡，并输入以下截图中显示的值：

![通过证书进行身份验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_09.jpg)

**KeyStore**是您应该复制`.pfx`文件的位置。请注意**KeyStore 密码**为`changeit`，并选中**需要客户端身份验证**选项。

现在，我们将测试刚刚进行的修改；因此，让我们启用流量分析器，并再次使用 SOAP UI 执行请求。Wireshark 将显示以下截图中显示的信息：

![通过证书进行身份验证](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_10.jpg)

正如您所看到的，所有信息都是加密的，无法解释。因此，如果数据包被传输并在网络中被拦截，信息不会容易受到攻击。

您可以在以下 URL 的 GitHub 上找到此部分的源代码：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter02/client-cert-authentication/resteasy-examples`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter02/client-cert-authentication/resteasy-examples)

# API 密钥

随着云计算的出现，很容易想到与云中许多其他应用程序集成的应用程序。现在，很容易看到应用程序如何与 Flickr、Facebook、Twitter、Tumblr 等进行交互。

为了启用这些集成，已开发了一种使用 API 密钥的新身份验证机制。当我们需要从另一个应用程序进行身份验证但不想访问另一个应用程序中托管的私人用户数据时，主要使用此身份验证方法。相反，如果您想访问此信息，必须使用 OAuth。如果您对此感兴趣，不用担心，我们将在本书的后面学习这项奇妙的技术。

我们想要了解 API 密钥的工作原理，所以让我们以 Flickr 为例。这里重要的是要理解 API 密钥的工作原理，因为相同的概念可以应用于谷歌、Facebook 等公司。对于不熟悉 Flickr 的人来说，它是一个云端应用，我们可以在其中存储照片、图像、截图或类似文件。

要开始使用这种身份验证模型，我们首先获得一个 API 密钥；在我们的 Flickr 示例中，您可以使用以下链接来做到这一点：

[`www.flickr.com/services/developer/api/`](https://www.flickr.com/services/developer/api/)

当我们请求我们的 API 密钥时，我们被要求输入我们将创建的应用程序的名称，并使用 API 密钥。一旦我们输入所请求的信息并提交，Flickr 将向我们提供一对值；它们是一个秘钥和一个密钥。两者都显示在以下截图中：

![API keys](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_11.jpg)

我们创建的每个应用程序都是 Flickr App Garden 的一部分。App Garden 只是由所有 Flickr 成员创建的所有应用程序的集合。

请记住，当创建 API 密钥时，我们有意接受提供者的某些使用条款。这些条款清楚地详细说明了我们可以做什么和不能做什么；例如，Flickr 说：

*a. 你应该：*

*遵守 Flickr 社区准则[www.flickr.com/guidelines.gne](http://www.flickr.com/guidelines.gne)，Flickr 使用条款[`www.flickr.com/terms.gne`](http://www.flickr.com/terms.gne)，以及 Yahoo!服务条款[`docs.yahoo.com/info/terms/`](http://docs.yahoo.com/info/terms/)。*

*…*

*b. 你不应该：*

*使用 Flickr API 来为任何试图复制或替代 Flickr.com 基本用户体验的应用程序*

*…*

因此，通过要求用户接受使用条款，API 密钥提供者防止了对其 API 的滥用使用。因此，如果有人开始不尊重协议，提供者将撤回 API 密钥。Flickr 有一系列我们可以在应用程序中使用的方法；我们将尝试其中一个来展示它们是如何工作的：

`flickr.photos.getRecent`方法列出了在 Flickr 中发布的所有最新照片，我们可以按照以下方式调用它：

`https://www.flickr.com/services/rest?method=flickr.photos.getRecent&;&api+key=[your_api_key_from_flicker]`

让我们使用之前生成的密钥，并让我们使用浏览器执行请求如下：

![API keys](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_02_12.jpg)

首先注意信息是如何通过安全通道（HTTPS）传输的。然后，在接收请求时，Flickr 通过读取属于用户的 API 密钥的秘钥来对用户进行身份验证。一旦这些验证成功，服务器将响应传递给客户端。因此，我们获得了最近在 Flickr 中发布的所有照片的响应。正如您将注意到的那样，通过这种方式，您可以轻松地使用提供者的 API 创建应用程序。此外，提供者将允许您进行身份验证，访问公共信息，并负责跟踪您使用 API 密钥进行的调用量或 API 调用次数，以验证使用是否符合协议。

# 总结

在本章中，我们介绍了所有可能的身份验证模型。我们将在下一章中使用它们，并将它们应用到我们刚刚创建的 Web 服务功能中。

即使您在任何示例中遇到问题，您也可以继续下一章。为了让您更好地理解，我们将逐步深入地介绍如何利用每个可用的身份验证模型。

正如您意识到的那样，选择正确的安全管理非常重要，否则信息将被暴露并且很容易被第三方拦截和使用。

最后，在本章中，我们回顾了身份验证和授权之间的区别。这两个概念都非常重要，在安全术语的背景下绝对不可忽视。

现在，我们会请你加入我们，继续前进并保护我们的网络服务。


# 第三章：使用 RESTEasy 进行安全管理

欢迎来到第三章。我们希望您能和我们一起享受并学习。在本章中，您将更深入地了解安全管理。您还将学习一些更高级的安全概念。

使用 RESTful Web 服务构建的应用程序中的安全管理可以比我们在上一章中审查的更加细粒度。如果我们考虑认证和授权主题，我们描述了前者；授权被搁置了。这是因为我们希望在本章中慢慢地并且在非常详细的层面上处理它。

本章涵盖的主题包括：

+   将认证和授权相关的安全限制实施到应用程序中。

+   实施细粒度安全

+   使用注释来获得对资源访问控制的更细粒度控制

# 细粒度和粗粒度安全

我们可以管理两个级别的安全：**细粒度**和**粗粒度**。

当我们在安全的上下文中提到粗粒度这个术语时，我们指的是通常在应用程序的高级别处理的安全系统。在第二章中的示例，*保护 Web 服务的重要性*，其中任何角色的用户都可以使用服务，是粗粒度的完美例子，因为粗粒度选项是在安全限制允许用户访问而不必担心角色或关于经过身份验证的用户更具体的功能的情况下使用的。这意味着为了系统允许访问功能，我们只需验证用户身份；换句话说，它对用户进行了认证。然而，在现实生活中，仅仅拥有应用程序的经过身份验证的用户是不够的。还需要用户被授权使用某些功能。我们可以使用细粒度控制来实现这一点。验证用户被分配的权限以访问功能意味着使用授权控制。

为了以实际方式演示这些概念，我们将利用我们在上一章中创建的应用程序。您可以在 GitHub 上的以下 URL 中访问源代码，在基本认证部分下：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter02/basic-authentication`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter02/basic-authentication)

让我们开始吧；假设我们只希望具有`管理员`角色的用户能够使用我们应用程序中的功能。首先要做的事情是更改`web.xml`文件并添加约束，如下所示。请注意，更改如何以粗体显示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.0" 

  xsi:schemaLocation="http://java.sun.com/xml/ns/javaee 
  http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">

  <security-role>
 <description>Application roles</description>
 <role-name>administrator</role-name>
  </security-role>
  <security-constraint>
    <display-name>Area secured</display-name>
    <web-resource-collection>
      <web-resource-name>protected_resources</web-resource-name>
      <url-pattern>/services/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
 <description>User with administrator role</description>
 <role-name>administrator</role-name>
    </auth-constraint>
  </security-constraint>
  <login-config>
    <auth-method>BASIC</auth-method>
  </login-config>
</web-app>
```

现在，让我们尝试使用我们刚刚创建的用户（`用户名`）进行请求。当您收到`403 Forbidden`错误时，您会感到惊讶。

请注意，如果您尝试使用无效凭据进行请求，您将收到错误`HTTP/1.1 401 Unauthorized`。错误非常明显；访问未经授权。这意味着我们发送了无效的凭据，因此用户无法被认证。我们刚刚收到的错误是`HTTP/1.1 403 Forbidden`，这表明用户已成功登录但未被授权使用他们需要的功能。这在下面的截图中有所展示：

细粒度和粗粒度安全

现在，让我们使用`JBOSS_HOME/standalone/bin/adduser.sh`文件创建一个具有`管理员`角色的新用户。按照以下截图中显示的信息输入请求的信息：

![Fine-grained and coarse-grained security](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_02.jpg)

当我们在 SoapUI 中更改凭据时，请求的结果是成功的，如下截图所示：

![Fine-grained and coarse-grained security](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_03.jpg)

正如您所看到的，我们使用了额外的控制，只限制了分配了`administrator`角色的经过身份验证的用户；他们能够使用 Web 服务功能。在管理真实世界应用程序的安全性时，使用这种控制是非常常见的。由于我们实施了更详细的控制级别，平台为我们提供了实施更细粒度控制的机会，这正是我们将立即看到的。

## 保护 HTTP 方法

JAAS 的一个好处是，我们甚至可以在 HTTP 方法的级别上进行控制。因此，我们可以实施安全控制，只允许具有特定角色的用户根据我们的方便使用特定方法；例如，一个角色保存信息，另一个删除信息，其他角色读取信息，依此类推。

为了实施这些控制，我们需要了解应用程序中 HTTP 方法的功能。在我们的示例中，我们已经知道为了保存信息，应用程序总是使用`HTTP POST`方法。同样，当我们想要读取信息时，应用程序使用`HTTP GET`方法。因此，我们将修改我们的示例，以便只有具有`administrator`角色的用户能够使用`savePerson`（`HTTP POST`）方法。与此同时，只有具有`reader`角色的用户才能使用`findById`（`HTTP GET`）方法读取信息。

为了实现这一目标，我们将修改我们的`web.xml`文件如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.0" 

xsi:schemaLocation="http://java.sun.com/xml/ns/javaee 
  http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">
  <!-- Roles -->
  <security-role>
    <description>Role for save information</description>
    <role-name>administrator</role-name>
  </security-role>
  <security-role>
    <description>Role for read information</description>
    <role-name>reader</role-name>
  </security-role>

  <!-- Resource / Role Mapping -->
  <security-constraint>
    <display-name>Administrator area</display-name>
    <web-resource-collection>
  <web-resource-name>protected_resources</web-resource-name>
      <url-pattern>/services/*</url-pattern>
      <http-method>POST</http-method>
    </web-resource-collection>
    <auth-constraint>
    <description>User with administrator role</description>
      <role-name>administrator</role-name>
    </auth-constraint>
  </security-constraint>
  <security-constraint>
    <display-name>Reader area</display-name>
    <web-resource-collection>
  <web-resource-name>protected_resources</web-resource-name>
      <url-pattern>/services/*</url-pattern>
      <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
      <description>User with reader role</description>
      <role-name>reader</role-name>
    </auth-constraint>
  </security-constraint>

  <login-config>
    <auth-method>BASIC</auth-method>
  </login-config>
</web-app>
```

在继续之前，我们必须使用`JBOSS_HOME/standalone/bin/adduser.sh`脚本创建一个具有`reader`角色的新用户（`readeruser`）。

现在，让我们使用 SoapUI 测试角色和其权限。

### HTTP 方法 - POST

我们将使用一个没有所需权限的角色来测试`POST`方法。您将看到权限错误消息。

角色：读者

使用此角色时，不允许此方法。在以下截图中进行了演示：

![HTTP 方法 - POST](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_04.jpg)

角色：管理员

使用此角色，您可以成功执行该方法。在以下截图中进行了演示：

![HTTP 方法 - POST](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_05.jpg)

### HTTP 方法 - GET

现在，我们将使用具有所需权限的用户来使用 GET 方法。执行应该成功。

角色：读者

现在，使用此角色执行成功。在以下截图中进行了演示：

![HTTP 方法 - GET](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_06.jpg)

角色：管理员

管理员角色无法访问此方法。在以下截图中进行了演示：

![HTTP 方法 - GET](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_07.jpg)

对 URL 模式可以使用相同的角色考虑。在我们的示例中，我们对`/services/*`模式应用了限制。但是，您可以在更深层次上应用它，例如`/services/person/*`。我们的意思是，如果我们有另一个服务暴露在 URL`/services/other-service/`下，我们可以设置一个角色可以访问路径`/services/person/*`下的服务，并在路径`/services/other-service/*`下实现不同级别的访问。这个例子非常简单，是作为读者的基本示例提出的。

应用所有更改后，我们在`web.xml`文件中设置了所有方法的安全性。然而，我们必须问自己一个问题；那些未被包括的方法会发生什么？

OWASP（开放 Web 应用程序安全项目）是一个致力于发现和修复软件安全漏洞的非营利组织，他们撰写了一篇关于此的论文，标题如下：

*通过 HTTP 动词篡改绕过 Web 身份验证和授权：如何无意中允许攻击者完全访问您的 Web 应用程序。*

如果您想查看完整的文档，可以通过访问以下链接进行：

[`dl.packetstormsecurity.net/papers/web/Bypassing_VBAAC_with_HTTP_Verb_Tampering.pdf`](http://dl.packetstormsecurity.net/papers/web/Bypassing_VBAAC_with_HTTP_Verb_Tampering.pdf)

OWASP 在前面提到的文件中描述的是简单的。它显示了如果我们不采取某些预防措施，JEE 在`web.xml`配置文件中暴露了潜在的安全漏洞，因为文件中未列出的所有方法都可以无限制地使用。这意味着在应用程序中未经身份验证的用户可以调用任何其他 HTTP 方法。

OWASP 在早期的文章中陈述了以下内容：

*不幸的是，几乎所有这种机制的实现都以意想不到的和不安全的方式运行。它们允许任何未列出的方法，而不是拒绝规则中未指定的方法。具有讽刺意味的是，通过在规则中列出特定方法，开发人员实际上允许了比他们预期的更多的访问权限。*

为了更好地理解这一点，让我们用一个类比来说明。

假设您有一个写书的网络应用程序，处理两种角色——一种是作者，他们能够写书的页面，另一种是评论者，他们只能阅读书籍并添加带有评论的注释。现在，假设一个用户因错误而最终获得了您应用程序的 URL。这个用户没有任何凭据可以提供，显而易见的是，这个用户甚至不应该能够访问应用程序。然而，OWASP 所展示的问题是，它实际上使未经身份验证的用户能够访问具有足够权限执行任何操作的应用程序，例如删除书籍，而不是做出明显的事情。

让我们举一个例子来看看这种不便，然后我们将实施 OWASP 的建议来解决它。

让我们在`PersonService`类中创建一个新的方法；这次我们将使用`web.xml`文件中未列出的方法之一。最常用的方法之一是`HTTP DELETE`；它的功能是使用其 ID 从内存中删除存储的条目。这将在 URL 中将记录的 ID 作为参数传递，因此请求的 URL 将如下所示：

`http://localhost:8080/resteasy-examples/services/person/[ID]`

方法的实现应该如下所示：

```java
@DELETE
@Path("{id}")
public Response delete(@PathParam("id") int id) {
  Person person = dataInMemory.get(id);
if (person == null) {
  // There is no person with this ID
throw new WebApplicationException(Response.Status.NOT_FOUND);
  }
  dataInMemory.remove(id);
  return Response.status(Status.GONE).build();
}
```

为了测试这种方法，我们必须首先通过 SoapUI 创建一对寄存器，还要使用`HTTP POST`方法和以下字符串：

```java
<person><name>Rene</name><lastname>Enriquez</lastname></person>
```

现在，在 SoapUI 中选择`DELETE`方法，删除我们用于身份验证的凭据信息，并使用其中一个项目 ID 执行请求，如下面的屏幕截图所示：

![HTTP 方法 - GET](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_08.jpg)

正如您所看到的，该项目已被删除，服务器返回消息`HTTP/1.1 410 Gone`。这表明资源不再可用。正如您所注意到的，当我们没有指定此方法默认应该受到保护时，它被标记为可用。在我们的情况下，任何用户都可以删除我们的应用程序资源，而无需进行身份验证。

为了克服这一缺点，OWASP 建议在`web.xml`文件中添加另一个安全约束。这个新的安全约束不应该在自身列出任何 HTTP 方法，这意味着拒绝所有 HTTP 方法的访问，如下面的代码所示：

```java
<security-constraint>
  <display-name>For any user</display-name>
  <web-resource-collection>
  <web-resource-name>protected_resources</web-resource-name>
    <url-pattern>/services/*</url-pattern>
  </web-resource-collection>
  <auth-constraint>
    <description>User with any role</description>
    <role-name>*</role-name>
  </auth-constraint>
</security-constraint> 
```

此外，我们还必须添加一个新的角色，以确定应用程序中的经过身份验证的用户，如下面的代码所示：

```java
<security-role>
    <description>Any role</description>
    <role-name>*</role-name>
  </security-role>
```

现在，我们从 SoapUI 运行请求，我们可以看到错误消息`HTTP/1.1 401 Unauthorized`。这表明您无法执行请求，因为用户尚未经过身份验证，这反过来意味着未经身份验证的用户无法使用`DELETE`或任何其他方法。

## 通过注释实现细粒度安全性

`web.xml`文件，允许所有安全设置的文件，不是实现细粒度安全的唯一方式；平台还提供了使用注解进行安全检查的可能性。为此，根据您的需求，可以选择以下三个选项：

+   `@RolesAllowed`

+   `@DenyAll`

+   `@PermitAll`

### `@RolesAllowed`注解

`@RolesAllowed`注解可以应用在方法或类级别。使用此注解，您可以定义一组允许使用被注解资源的角色。作为参数注解，让我们写下所有允许的角色。对于本例，我们将修改我们的`web.xml`文件如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.0" 

xsi:schemaLocation="http://java.sun.com/xml/ns/javaee 
  http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">
  <!-- Roles -->
 <context-param>
 <param-name>resteasy.role.based.security</param-name>
 <param-value>true</param-value>
 </context-param>
  <security-role>
    <description>Any role</description>
    <role-name>*</role-name>
  </security-role>
  <!-- Resource / Role Mapping -->
  <security-constraint>
  <display-name>Area for authenticated users</display-name>
    <web-resource-collection>
  <web-resource-name>protected_resources</web-resource-name>
      <url-pattern>/services/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
      <description>User with any role</description>
      <role-name>*</role-name>
    </auth-constraint>
  </security-constraint>
  <login-config>
    <auth-method>BASIC</auth-method>
  </login-config>
</web-app>
```

在`PersonService`类中，让我们在每个方法上使用注解，指定我们希望能够执行该方法的角色，如下所示：

```java
  @RolesAllowed({ "reader", "administrator" })
  @POST
  @Consumes("application/xml")
  public Response savePerson(Person person) {...

  @RolesAllowed({ "administrator" })
  @GET
  @Path("{id}")
  @Produces("application/xml")
  public Person findById(@PathParam("id") int id) {...
```

现在是时候通过 SoapUI 进行测试了。

#### savePerson 方法

现在，我们将使用管理员角色测试`PersonService`类的`savePerson`方法，如下截图所示：

![savePerson 方法](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_09.jpg)

执行成功，如前面的截图所示。原因是因为我们在`@RolesAllowed`注解中包含了两个角色。此外，我们将使用`reader`角色测试执行，以使其成功，如下截图所示：

![savePerson 方法](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_10.jpg)

如您所见，当我们使用`@RolesAllowed`注解时，我们授予特定角色的权限。对于此方法，我们使用了`administrator`和`reader`。

#### findById 方法

现在，我们将使用`administrator`角色测试`findById`方法，如下截图所示：

![findById 方法](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_11.jpg)

截图显示执行成功，因为`@RolesAllowed`注解包含了 admin。由于我们没有包含`reader`角色，下一次执行不应被授权。让我们立即测试，如下截图所示：

![findById 方法](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_03_12.jpg)

再次，我们使用`@RolesAllowed`注解在方法级别授予权限，但这次我们只指定了一个角色，即`administrator`。

本章的所有源代码都可以在以下网址找到：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter03`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter03)

### `@DenyAll`注解

`@DenyAll`注解允许我们定义无论用户是否经过身份验证或角色是否与用户相关，都无法调用的操作。规范将此注解定义如下：

*指定不允许安全角色调用指定的方法 - 即这些方法应该在 J2EE 容器中被排除在执行之外。*

### `@PermitAll`注解

当我们使用`@PermitAll`注解时，我们告诉容器，被注解的资源（方法或类的所有方法）可以被已登录到应用程序的任何用户调用。这意味着只需要用户经过身份验证；不需要分配任何特定的角色。

从这三个注解中，无疑最常用的是第一个（`@RolesAllowed`）；其他两个并不经常使用，因为`@PermitAll`可以很容易地在`web.xml`文件中替代，而`@DenyAll`只能在少数情况下使用。

## 细粒度安全的编程实现

除了提供我们已经看到的安全管理选项外，RESTEasy 还提供了另一种用于访问控制的机制。

在 Web 服务的操作中，您可以向方法添加额外的参数。这允许访问安全上下文，而不会改变客户端调用方法的方式或方法执行的操作。参数必须以以下方式包含：

```java
@GET...
@Consumes("text/xml")
public returnType methodName(@Context SecurityContext secContext, …) {...
```

假设在我们的示例中，在`savePerson`方法中，我们想要访问此功能。我们需要做的唯一更改如下所示。

之前，该方法只使用一个参数，如下所示的代码：

```java
@POST
@Consumes("application/xml")
public Response savePerson(Person person) {
  int id = dataInMemory.size() + 1;
  person.setId(id);
  dataInMemory.put(id, person);
  return Response.created(URI.create("/person/" + id)).build();
}
```

现在，该方法有另一个参数，如下所示的代码：

```java
@POST
@Consumes("application/xml")
public Response savePerson(@Context SecurityContext secContext, Person person) {
  int id = dataInMemory.size() + 1;
  person.setId(id);
  dataInMemory.put(id, person);
  return Response.created(URI.create("/person/" + id)).build();
}
```

接口`javax.ws.rs.core.SecurityContext`提供了以下三个有趣的功能：

+   `isUserInRole()`

+   `getUserPrincipal()`

+   `isSecure()`

方法`isUserInRole()`的功能类似于注解`@RolesAllowed`；其目标是进行检查，以确定已登录的用户是否属于指定的角色，如下所示：

```java
@POST
@Consumes("application/xml")
public Response savePerson(@Context SecurityContext secContext, Person person) {
  boolean isInDesiredRole = 	secContext.isUserInRole ("NameOfDesiredRole");
  int id = dataInMemory.size() + 1;
  person.setId(id);
  dataInMemory.put(id, person);
  return Response.created(URI.create("/person/" + id)).build();
}
```

`getUserPrincipal()`方法获取应用程序中的主要用户，换句话说，已登录的用户。通过此用户，您可以获取代表它的用户名等信息；这在您想要生成审计跟踪的场景中总是很有用。

最后，方法`isSecure()`确定调用是否通过安全的通信方式进行，例如您是否使用了 HTTPS。

正如您所知，HTTP 和 HTTPS 是用于交换信息的协议；前者通常用于共享非敏感信息，而后者通常用于共享敏感信息并且需要安全通道时。

让我们想象一下 ABC 银行的网站，特别是首页，它显示了关于服务和与银行业务相关的信息，可以使用 HTTP 进行管理。我们不能使用 HTTP 协议管理处理账户信息或资金转账的网页；这是因为信息没有受到保护。通过 HTTPS 协议，我们可以加密信息；当信息被 Wireshark 等流量分析器拦截时，它无法被解释。

通过对项目应用更改以启用 HTTPS，可以测试此功能，我们在第二章*保护 Web 服务的重要性*中向您展示了这一点。

当您使用 HTTP 调用此方法时，结果将为 false，但当您使用 HTTPS 调用相同的方法时，结果将为 true。

这三种方法在我们想要实现细粒度安全检查时非常有用。例如，当我们想要实现审计时，我们可以确定某个操作是否使用了诸如 HTTPS 之类的传输安全协议；此外，我们还可以发现执行该操作的用户的信息。

# 总结

在实现应用程序安全时，我们可能有各种需求。在本章中，我们看到了 JAX-RS 如何提供处理安全性的机制，从一个相当基本的模型（粗粒度）开始，到一个更精细的模型（细粒度），在后者中，您可以执行更彻底的控制，包括编程控制和通过配置文件进行的控制。

当然，始终建议将这些检查保存在诸如`web.xml`之类的配置文件中。由于您将控件集中在一个地方，这样做有助于维护。当安全性在源代码级别处理时，情况并非如此，因为当有许多类是项目的一部分时，如果需要对当前功能进行某种修改，任务就会变得复杂。

现在，您应该为下一章做准备，我们将讨论 OAuth。这是一个非常令人兴奋的话题，因为这个协议在互联网应用程序中被广泛接受和使用。世界范围内的明星公司，如谷歌、Twitter 和 Facebook 等，都非常成功地使用了它。


# 第四章：RESTEasy Skeleton Key

欢迎来到第四章！我们希望您喜欢这本书，更重要的是，学习和理解我们所传达和教授的内容。现在是时候向前迈进，沉浸在新的章节中了。

阅读完本章后，您将具备设计、实施和聚合额外安全级别到您的 RESTEasy 应用程序的知识，所有这些都使用 OAuth 和 RESTEasy Skeleton Key 以及这些技术的一些其他特定要求，比如设置一个 OAuth 服务器。您将通过应用程序的实际和描述性示例进行学习，就像我们在之前的章节中所做的那样；我们不会只停留在理论上，而是会实施应用程序并解释实现 OAuth 的特定方法和类。

在本章中，您将学习以下主题：

+   OAuth 和 RESTEasy

+   用于安全管理的 SSO 配置

+   访问令牌

+   自定义过滤器

+   用于测试的 Web 服务客户端

正如您可能已经经历过的那样，如果您在一个或多个社交网络上有账户，许多这些社交网络允许您在它们之间共享信息或在所有社交网络上发布内容。这表明应用程序需要共享信息，还需要使用其他应用程序中的资源。在这个例子中，可能是您的账户或联系人列表。这涉及到敏感信息，因此需要进行保护。此外，对资源的有限权限意味着第三方应用程序只能读取您的联系人列表。这为应用程序之间提供了一个非常重要、有吸引力和有用的功能，即代表用户使用资源的能力。当然，您可能会问后者如何授权使用？好吧，本章将向您展示。所以，让我们开始吧！

# OAuth 协议

这是一个开放协议，允许您从一个站点（服务提供者）向另一个站点（消费者）授予对您的私人资源的安全授权，而无需共享您的身份。

一个实际的例子是当您授权一个网站或应用程序使用您手机或社交网络中的联系人列表。

# OAuth 和 RESTEasy Skeleton Key

在本节中，我们将回顾一些与 OAuth 作为身份验证框架、RESTEasy Skeleton Key 以及它们如何一起工作相关的概念。您将了解这些技术的一些特性，并通过一些代码实际示例来动手实践。

## RESTEasy Skeleton Key 是什么？

RESTEasy Skeleton Key 为浏览器和 JAX-RS 客户端提供了一种统一的方式来进行安全保护。这允许在应用程序和服务网络中以安全和可扩展的方式执行和转发请求，而无需在每次出现请求时与中央身份验证服务器进行交互。

## OAuth 2.0 身份验证框架

这使第三方应用程序或服务能够代表资源所有者访问 HTTP 资源。它还防止第三方应用程序或服务与所有者的凭据联系。这是通过通过浏览器发放访问令牌并使用直接授权来实现的。

简而言之，通过这两个概念的解释，现在是时候描述它们之间的关系了。RESTEasy Skeleton Key 是一个 OAuth 2.0 实现，它使用 JBoss AS 7 安全基础设施来保护 Web 应用程序和 RESTful 服务。

这意味着您可以将 Web 应用程序转换为 OAuth 2.0 访问令牌提供程序，并且还可以将 JBoss AS 7 安全域转换为中央身份验证和授权服务器，应用程序和服务可以相互交互。

以下图表更好地描述了这个过程：

![OAuth 2.0 身份验证框架](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_04_01.jpg)

### 主要特点

我们希望帮助您了解这些技术并澄清它们的用途；这就是为什么我们将列出它们的一些主要特点。使用 OAuth 2.0 和 RESTEasy Skeleton Key，您可以执行以下功能：

+   将基于 servlet-form-auth 的 Web 应用程序转换为 OAuth 2.0 提供程序。

+   通过中央身份验证服务器提供分布式**单点登录**（**SSO**），以便一次登录并以安全方式访问在域中配置的任何基于浏览器的应用程序。

+   只使用一个链接并注销所有已配置 SSO 的分布式应用程序。

+   使 Web 应用程序使用访问令牌与远程 RESTful 服务进行交互。

+   使用 OAuth 2.0 签署访问令牌，并稍后使用这些令牌访问域中配置的任何服务。令牌具有身份和角色映射，因为令牌是数字签名的，所以没有必要在每次出现请求时过载中央身份验证服务器。

您可以在[`docs.jboss.org/resteasy/docs/3.0-beta-2/userguide/html/oauth2.html`](http://docs.jboss.org/resteasy/docs/3.0-beta-2/userguide/html/oauth2.html)找到有关这些主题的更多信息。

我们将讨论最重要的部分，但这对您可能有用。

## OAuth2 实施

我们刚刚回顾了本章中将要处理的一些主要概念，但这还不够。我们必须实施一个描述性示例，以便完全理解这些主题。

### 在 JBoss 中更新 RESTEasy 模块

为了不干扰您的 JBoss 配置或其他任何东西，我们将使用另一个全新的 JBoss 实例。我们必须更新一些与 RESTEasy 相关的模块。我们可以很容易地做到这一点。让我们访问链接[`resteasy.jboss.org/`](http://resteasy.jboss.org/)；在右侧，您会找到一个标题为**Useful Links**的面板，其中包含一个下载链接。单击它访问另一个页面，该页面上有一堆下载链接。在本例中，我们使用 3.0.7.Final 版本。下载这个版本以继续。

下载并解压缩后，您会找到另一个名为`resteasy-jboss-modules-3.0.7.Final`的`.zip`文件；该文件包含一些将更新您的 JBoss 模块的 JAR 文件。因此，请解压缩它，将所有文件夹复制到`JBOSS_HOME/modules/`，并替换所有匹配项。还有最后一步：我们必须更新 JBoss 中 JAR 文件的版本，并修改模块 XML，以将`org.apache.httpcomponents`设置为使用`httpclient-4.2.1.jar`、`httpcore-4.2.1.jar`和`httpmime-4.2.1.jar`，因为当前最新版本是 4.3.4，这也可以正常工作。因此，请复制这些 JAR 文件，并在`JBOSS_HOME/modules/org/apache`文件夹中的`module.xml`文件中更新版本。现在，我们已经更新了 RESTEasy 的模块。

### 在 JBoss 中设置配置

为了让我们的 JBoss 为示例做好下一步准备，我们必须转到[`github.com/restful-java-web-services-security/source-code/tree/master/chapter04`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter04)并下载`chapter04`示例 zip 文件。解压缩后，您会找到一个名为`configuration`的文件夹。该文件夹包含设置我们的 JBoss 配置所需的文件。因此，请复制这些文件并替换位于`JBOSS_HOME/standalone/configuration`的 JBoss 中的配置文件夹。

### 实施 OAuth 客户端

为了开发这个示例，我们调查了一个非常有用的示例并将其应用到一个新项目中。这个示例由几个项目组成；每个项目将生成一个 WAR 文件。这个示例的目的是演示 OAuth 的工作原理，并解释您可以在技术层面上实现这项技术的方式。因此，我们将模拟几件事情，以创建我们可以应用这个实现的环境。完整的代码可以从以下链接下载：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter04/oauth2-as7-example`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter04/oauth2-as7-example)

#### oauth-client 项目

首先，我们将创建`oauth-client` webapp 项目。您可以使用我们在之前章节中使用过的 Maven 命令，也可以使用 Eclipse IDE 来执行此操作。

之后，让我们添加一些依赖项以实现我们的客户端。这些依赖项适用于所有项目。转到`pom.xml`文件，并确保在`<dependencies>`标签内添加以下依赖项：

```java
       <dependency>
            <groupId>org.jboss.spec.javax.servlet</groupId>
            <artifactId>jboss-servlet-api_3.0_spec</artifactId>
            <version>1.0.1.Final</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.jboss.resteasy</groupId>
            <artifactId>resteasy-client</artifactId>
            <version>3.0.6.Final</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.jboss.resteasy</groupId>
            <artifactId>skeleton-key-core</artifactId>
            <version>3.0.6.Final</version>
            <scope>provided</scope>
        </dependency>
```

让我们首先创建包`com.packtpub.resteasy.example.oauth`。然后，创建类`public class Loader implements ServletContextListener`，它实现`ServletContextListener`，因为我们将加载密钥库并初始化上下文。

让我们在我们的类中添加一个字段`private ServletOAuthClient oauthClient`，它将代表我们的 OAuth 客户端对象。

然后，让我们创建以下代码片段中显示的方法：

```java
private static KeyStore loadKeyStore(String filename, String password) throws Exception 
{
KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
File keyStoreFile = new File(filename);
FileInputStream keyStoreStream = new FileInputStream(keyStoreFile);
    keyStore.load(keyStoreStream, password.toCharArray());
    keyStoreStream.close();
    return keyStore; 
}
```

此方法接收两个参数，文件名和密码，并创建`KeyStore`对象。它还从接收的文件名创建一个`FileInputStream`对象，以便可以使用它来加载`KeyStore`对象，并使用以 char 数组形式接收的密码。

之后，由于我们的类实现了`ServletContextListener`接口，我们必须重写一些方法。要重写的第一个方法是`contextInitialized`。让我们按照以下方式进行：

```java
@Override
 public void contextInitialized(ServletContextEvent sce) {
  String truststoreKSPath = "${jboss.server.config.dir}/client-truststore.ts";
  String truststoreKSPassword = "changeit";
  truststoreKSPath = EnvUtil.replace(truststoreKSPath);
  try {
   KeyStore truststoreKS = loadKeyStore(truststoreKSPath, 
     truststoreKSPassword);
   oauthClient = new ServletOAuthClient();
   oauthClient.setTruststore(truststoreKS);
   oauthClient.setClientId("third-party");
   oauthClient.setPassword("changeit");
   oauthClient.setAuthUrl("https://localhost:8443/oauth-server/login.jsp");
   oauthClient.setCodeUrl("https://localhost:8443/oauth-server/
     j_oauth_resolve_access_code");
   oauthClient.start();
   sce.getServletContext().setAttribute(ServletOAuthClient.class.getName(), oauthClient);
  } catch (Exception e) {
   throw new RuntimeException(e);
  }

 }
```

通过这种方法，我们将实现几件事情。正如您所看到的，我们设置了两个内部变量；一个设置为我们`client-truststore.ts`文件的路径，另一个设置为密码。确保将文件粘贴到我们在变量中指定的路径中（`JBOSS_HOME/standalone/configuration`）。

之后，我们使用在变量中指定的路径和密码加载`KeyStore`对象，通过这样获得另一个`KeyStore`对象。

现在，是时候实例化和设置我们的 OAuth 客户端对象的属性了。在前面的代码中，我们设置了以下属性：`trustStore`、`clientId`、`password`、`authUrl`和`codeUrl`。

最后，我们创建客户端以从代码中获取访问令牌。为了实现这一点，我们使用`start()`方法。同时，我们使用刚刚创建的 OAuth 客户端对象设置 servlet OAuth 客户端属性。

为了完成我们的 OAuth 客户端，我们需要重写第二个名为`public void contextDestroyed(ServletContextEvent sce)`的方法，如下所示：

```java
@Override
  public void contextDestroyed(ServletContextEvent sce) {
    oauthClient.stop();
  }
```

当 servlet 上下文即将关闭、我们的应用程序重新部署等情况时，将执行此方法。该方法关闭客户端实例及其所有关联资源。

我们为示例实现了我们的 OAuth 客户端。我们需要另一个资源。这一次，我们将创建一个作为我们紧凑光盘商店数据库客户端的类。因此，让我们命名为`CompactDiscsDatabaseClient`，并编写以下两个方法：

+   `public static void redirect(HttpServletRequest request, HttpServletResponse response)`

+   `public static List<String> getCompactDiscs(HttpServletRequest request)`

因此，让我们开始实现第一个方法。该方法的说明如下：

```java
public static void redirect(HttpServletRequest request, HttpServletResponse response) {
ServletOAuthClient oAuthClient = (ServletOAuthClient) request.getServletContext().getAttribute(ServletOAuthClient.class.getName());
    try {
oAuthClient.redirectRelative("discList.jsp", request, response);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
```

在前面的方法中，我们从请求中获取的`ServletContext`中获取了`ServletOAuthClient`对象；servlet OAuth 客户端作为名为`ServletOAuthClient`的属性存在于 servlet 上下文中。请记住，在我们创建的第一个类中，我们在 servlet 上下文中设置了此属性。

最后，通过`redirectRelative (String relativePath, HttpServletRequest request, HttpServletResponse response)`方法开始获取访问令牌，将浏览器重定向到认证服务器。

现在，让我们继续下一个加载光盘的方法。以下代码表示该方法：

```java
public static List<String> getCompactDiscs(HttpServletRequest request) {

ServletOAuthClient oAuthClient = (ServletOAuthClient) request.getServletContext().getAttribute(
        ServletOAuthClient.class.getName());

ResteasyClient rsClient = new 
ResteasyClientBuilder().trustStore(oAuthClient.getTruststore()).hostnameVerification(ResteasyClientBuilder.HostnameVerificationPolicy.ANY).build();

String urlDiscs = "https://localhost:8443/store/discs";
  try {
String bearerToken = "Bearer" + oAuthClient.getBearerToken(request);

Response response = rsClient.target(urlDiscs).request().header(HttpHeaders.AUTHORIZATION, bearerToken)
          .get();
    return response.readEntity(new GenericType<List<String>>() {
	      });
    } finally {
      rsClient.close();
    }
}
```

让我们检查一下我们在这里有什么。在前面的`getCompactDiscs()`方法中，我们创建了一个`ServletOAuthClient`对象，负责启动通过将浏览器重定向到认证服务器来获取访问令牌的过程。再次，我们从请求中获取`ServletContext`对象的属性。然后，我们使用`ResteasyClientBuilder()`的新实例创建一个`ResteasyClient`对象；这个类是创建客户端的抽象，并允许 SSL 配置。

然后，我们使用`trustStore()`方法设置客户端信任库。这个调用将返回一个`KeyStore`对象并设置客户端信任库。之后，我们调用`hostnameVerification()`方法，该方法设置用于验证主机名的 SSL 策略。最后，使用`build()`方法，我们使用先前在此客户端构建器中指定的整个配置构建一个新的客户端实例。这将返回一个`ResteasyClient`实例。

让我们继续创建一个内部变量，用于保存我们将设置为目标资源的资源的 URL。此外，我们将创建另一个内部变量来保存作为字符串的持有者令牌。这个字符串将由来自 servlet OAuth 客户端和请求的持有者令牌后面跟着的单词`Bearer`组成。

现在，为了创建响应，我们将使用刚刚创建的 servlet OAuth 客户端。让我们使用变量`urlDiscs`作为参数，并通过`target()`方法创建一个新的 web 资源目标。之后，使用`request()`方法，我们设置一个请求到刚刚设置的目标 web 资源。

最后，我们通过调用`header()`方法添加一个头，该方法将接收两个参数：第一个参数表示头的名称，第二个参数是头的值。之后，我们调用`HTTP GET`方法进行当前请求。

只是为了澄清，`HttpHeaders.AUTHORIZATION`常量代表特定情况下用户想要与服务器进行身份验证时的头字段。它通过在请求中添加授权请求头字段来实现。另一方面，授权字段值由包含用户在请求的资源领域中的身份验证信息的凭据组成。

创建响应对象后，我们使用`readEntity()`方法将消息实体输入流读取为指定 Java 类型的实例。通过这样做，我们用我们的紧凑光盘示例列表填充列表，以便在网页上呈现。这意味着我们访问了资源。

如果您想探索一下我们刚刚在描述的代码块中使用的内容，这里有一些链接作为参考。您可以查看它们，扩展您的知识，并获取有关`RestEasyClient`和`RestEasyClientBuilder`的更多详细信息：

+   [`www.w3.org/Protocols/rfc2616/rfc2616-sec14.html`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html)

+   [`docs.jboss.org/resteasy/docs/3.0.2.Final/javadocs/org/jboss/resteasy/client/jaxrs/ResteasyClient.html`](http://docs.jboss.org/resteasy/docs/3.0.2.Final/javadocs/org/jboss/resteasy/client/jaxrs/ResteasyClient.html)

+   [`docs.jboss.org/resteasy/docs/3.0.1.Final/javadocs/org/jboss/resteasy/client/jaxrs/ResteasyClientBuilder.html#truststore`](http://docs.jboss.org/resteasy/docs/3.0.1.Final/javadocs/org/jboss/resteasy/client/jaxrs/ResteasyClientBuilder.html#truststore)

#### discstore 项目

我们接下来要创建的项目是`discstore`项目；创建项目的步骤与上一个相同，您可以使用 Maven 命令或 Eclipse IDE。

在这个项目中，我们将创建一个类来创建紧凑光盘的列表。这个类非常简单，它使用了一些在前几章中已经讨论过的注解。这个类的名称将是`CompactDiscService`，它只有一个带有几个注解的方法。让我们从代码开始，然后在代码块后面添加一个简短的描述：

```java
@Path("discs")
public class CompactDiscService {
  @GET
 @Produces("application/json")
  public List<String> getCompactDiscs() {
    ArrayList<String> compactDiscList = new ArrayList<String>();
    compactDiscList.add("The Ramones");
    compactDiscList.add("The Clash");
    compactDiscList.add("Nirvana");
    return compactDiscList;
  }
}
```

正如你所看到的，`getCompactDiscs()`方法负责创建一个字符串列表，其中每个项目将表示为一个紧凑光盘，因为这是一个我们将添加三个项目的示例。

`@Produces`注解用于指定 MIME 媒体类型，如果应用在方法级别，这些注解将覆盖类级别的`@Produces`注解。`@GET`注解，正如你已经知道的，代表 HTTP 方法`GET`。同时，`@Path`注解将帮助我们将类设置为资源，它的名称将是`discs`。

所有后端都已经实现；现在我们需要开发一些其他资源，以便让我们的示例运行。记得我们在上面的类中指定了一些网页吗？那就是我们现在要实现的。

#### oauth-server 项目

与以前一样，为了创建这个项目，你可以使用 Maven 命令或 Eclipse IDE。

为了启动这个应用程序，我们必须创建`jboss-web.xml`文件，内容如下：

```java
<jboss-web>
    <security-domain>java:/jaas/commerce</security-domain>
    <valve>
        <class-name>org.jboss.resteasy.skeleton.key.as7.OAuthAuthenticationServerValve</class-name>
    </valve>
</jboss-web>
```

最后一件事：我们必须创建一个 JSON 文件，目的是在这个服务器上拥有我们的证书和安全配置。我们将把它命名为`resteasy-oauth`。正如你所看到的，这个文件并不复杂；它是一组属性和值。通过这个文件，我们指定了密钥库和密码，信任库路径等。这个文件将位于这个项目的`WEBINF`文件夹中。

```java
{
   "realm" : "commerce",
   "admin-role" : "admin",
   "login-role" : "login",
   "oauth-client-role" : "oauth",
   "wildcard-role" : "*",
   "realm-keystore" : "${jboss.server.config.dir}/realm.jks",
   "realm-key-alias" : "commerce",
   "realm-keystore-password" : "changeit",
   "realm-private-key-password" : "changeit",
   "truststore" : "${jboss.server.config.dir}/client-truststore.ts",
   "truststore-password" : "changeit",
   "resources" : [
      "https://localhost:8443/oauth-client",
      "https://localhost:8443/discstore/"
   ]
}
```

#### webapp/WEB-INF/ jboss-deployment-structure.xml

我们必须在所有项目中配置这个文件，因为我们更新了 JBoss AS 实例的一些模块。在这个文件中，我们必须指定我们的应用程序与 JBoss 的一些模块的依赖关系。然后，我们需要使用`<dependencies>`标签内的`<module>`标签清楚地设置它们，如下所示：

```java
<jboss-deployment-structure>
    <deployment>
        <!-- This allows you to define additional dependencies, it is the same as using the Dependencies: manifest attribute -->
        <dependencies>
            <module name="org.jboss.resteasy.resteasy-jaxrs" services="import"/>
            <module name="org.jboss.resteasy.resteasy-jackson-provider" services="import"/>
            <module name="org.jboss.resteasy.skeleton-key" />
        </dependencies>
    </deployment>
</jboss-deployment-structure>
```

#### 运行应用程序

我们已经解释了每个项目的主要部分，为了运行和测试应用程序，你可以从[`github.com/restful-java-web-services-security/source-code/tree/master/chapter04`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter04)下载本章的示例文件夹。下载 ZIP 文件后，解压缩，你会发现一个名为`OAuthExample`的文件夹。在这个文件夹中，有我们的三个项目。你可以复制它们并粘贴到你的工作区，并使用 Eclipse 导入这些项目。

我们已经在`configuration`文件夹中提供了密钥库、证书和信任库文件，你在设置 JBoss`configuration`时刚刚粘贴了进去。为了确保应用程序正常运行，你可以按照`configuration`文件夹中名为`keystoreCommands`的`.txt`文件中的说明更新这些文件。

为了启动我们的应用程序，我们必须部署它。所以，打开一个终端。让我们进入`JBOSS_HOME/bin`并以独立模式启动 JBoss；这意味着如果你在 Windows 上执行`standalone.bat`，如果你在 Linux 上执行`./standalone.sh`。然后，打开一个终端并进入工作区中我们应用程序的文件夹。我们必须执行以下命令：在我们创建的三个项目`discstore`、`oauth-client`和`oauth-server`中，分别执行`mvn clean install`和`mvn jboss-as:deploy`。

我们在`discstore`项目中创建了一个特殊的类。这个类包含一个`void main`方法，我们通过这个类测试我们的应用程序。我们把它命名为`OAuthClientTest`。这个类的代码如下：

```java
public class OauthClientTest {

  public static void main(String[] args) throws Exception {

    String truststorePath = "C:/Users/Andres/jboss/2do_jboss/jboss-as-7.1.1.Final/standalone/configuration/client-truststore.ts";
    String truststorePassword = "changeit";
    truststorePath = EnvUtil.replace(truststorePath);

    KeyStore truststore = loadKeyStore(truststorePath, truststorePassword);

         ResteasyClient client = new ResteasyClientBuilder()
                .disableTrustManager().trustStore(truststore).build();

    Form form = new Form().param("grant_type", "client_credentials");
    ResteasyWebTarget target = client.target("https://localhost:8443/oauth-server/j_oauth_token_grant");
    target.register(new BasicAuthentication("andres", "andres"));

    AccessTokenResponse tokenResponse = target.request().post(Entity.form(form), AccessTokenResponse.class);
    Response response = client.target("https://localhost:8443/discstore/discs")
        .request()
        .header(HttpHeaders.AUTHORIZATION,
            "Bearer " + tokenResponse.getToken()).get();
    try {
      String xml = response.readEntity(String.class);
      System.out.println(xml);
    } finally {
      client.close();
    }

  }
```

我们将首先解释前面的代码，首先，我们有两个变量，`truststorePath`和`truststorePassword`。第一个引用了我们的 JBoss 配置文件夹中`client-truststore.ts`文件的路径。您应该更改这个变量的值，以使此测试工作，因此请放置您的配置文件夹的路径。之后，通过我们已经解释的方法`loadKeyStore()`，我们使用前面的变量加载 KeyStore，并将这个值分配给一个名为`truststore`的`KeyStore`对象。从`truststore`，我们创建了名为`client`的`RestEasyClient`对象。

现在，我们将以编程方式获取访问令牌，因此我们可以通过使用 HTTPS 调用简单地从 auth-server 请求访问令牌。然后我们必须使用基本身份验证来识别我们的用户；结果，我们将获得该用户的签名访问令牌。

因此，我们对 auth-server 的上下文根执行简单的`POST`，在目标 URL 的末尾加上`j_oauth_token_grant`，因为当我们使用该 URL 和基本身份验证时，我们将为特定用户获取访问令牌。

之后，我们获得了访问令牌，这是一个简单的字符串。为了调用受持有者令牌身份验证保护的服务，我们必须构建一个字符串，由您的`HTTPS`请求的授权标头加上字符串`Bearer`和最后的访问令牌字符串组成。这将返回响应对象，因此我们可以读取它并像在测试中那样打印它。在控制台中，您将看到如下截图中显示的紧凑光盘列表：

运行应用程序

# 安全管理的 SSO 配置

SSO 是一种身份验证机制。它允许用户只需输入一次凭据即可访问多个系统或应用程序。我们认为您这些天更经常经历这种情况，因为我们生活在一个社交网络时代，大多数这些服务都让我们使用彼此的凭据来访问多个服务。

在讨论了 SSO 的一些概念之后，让我们尝试并实现这种机制。为了实现这一点，我们将使用 JBoss 7 应用服务器和我们之前的项目`secure-demo`。

作为对这个实现的简要介绍，我们想告诉您，我们将使用两个文件；一个文件属于 JBoss，另一个文件属于我们的应用程序。

属于 JBoss 的文件是`standalone.xml`。我们将向该文件添加一些行。在以下代码行中，让我们在`virtual-server`定义中添加 SSO 元素：

```java
<subsystem  default-virtual-server="default-host" native="false">
            <connector name="http" protocol="HTTP/1.1" scheme="http" socket-binding="http"/>
            <virtual-server name="default-host" enable-welcome-root="true">
                <alias name="localhost"/>
                <sso domain="localhost" reauthenticate="false"/>
            </virtual-server>
</subsystem>
```

`reauthenticate`属性允许我们确定每个请求是否需要重新对`securityReal`进行重新身份验证。默认值为`false`。

我们必须编辑的下一个文件是我们的应用程序中的`jboss-web.xml`。此外，我们需要向该文件添加一些代码行。这些代码行将声明将管理 SSO 的阀门。换句话说，每个请求都将通过此阀门，如下面的代码所示：

```java
<jboss-web>
    <security-domain>java:/jaas/other </security-domain>
          <valve>
        <class-name>org.apache.catalina.authenticator.SingleSignOn</class-name>
    </valve>
</jboss-web>
```

以防您忘记或删除它，我们在前几章中设置了一个安全域。以下代码块必须存在于`standalone.xml`文件中：

```java
<security-domain name="other" cache-type="default">
    <authentication>
      <login-module code="Remoting" flag="optional">
<module-option name="password-stacking"  value="useFirstPass"/>
      </login-module>
      <login-module code="RealmUsersRoles" flag="required">
<module-option name="usersProperties" value="${jboss.server.config.dir}/application-users.properties"/>
<module-option name="rolesProperties" value="${jboss.server.config.dir}/application-roles.properties"/>
<module-option name="realm" value="ApplicationRealm"/>
<module-option name="password-stacking" value="useFirstPass"/>
      </login-module>
     </authentication>
</security-domain>
```

由于我们正在使用`secure-demo`示例，这是我们必须修改的所有内容，以配置 SSO。

为了测试这种机制，我们需要另一个应用程序。我们必须复制我们刚刚在`secure-demo`示例中进行的配置。

当我们在其中一个中输入凭据时，我们不再需要在其他中输入凭据，因为我们已经应用了 SSO。我们将在两个应用程序中进行身份验证。

# 通过基本身份验证获取 OAuth 令牌

现在，让我们探索并实现一个使用令牌的简短示例。为了构建这个示例，我们将创建一个类。这个类，就像前面的示例一样，将模拟一个数据库客户端。它将具有相同的方法`getCompactDiscs()`，但是这次我们将修改这个示例中的内部函数。此外，这次它不会接收任何参数。

好了，让我们开始吧！首先，在类中创建两个静态字符串字段。第一个字段将保存 auth-server 中的认证 URL。另一个字段将有显示紧凑光盘列表的 URL；您可以重用之前示例中相同的网页。然后，您的变量应该如下所示：

```java
private static String urlAuth = "https://localhost:8443/auth-server /j_oauth_token_grant";
private static String urlDiscs = "https://localhost:8443/discstore/discs";
```

之后，让我们创建获取紧凑光盘列表的方法。以下代码片段向您展示了方法的执行方式：

```java
public static List<String> getCompactDiscs() {
  ResteasyClient rsClient = new ResteasyClientBuilder().disableTrustManager().build();
    Form form = new Form().param("grant_type", "client_credentials");
  ResteasyWebTarget resourceTarget = rsClient.target(urlAuth);
    resourceTarget.register(new BasicAuthentication("andres", "andres"));
  AccessTokenResponse accessToken = resourceTarget.request().post(Entity.form(form), AccessTokenResponse.class);
    try {
      String bearerToken = "Bearer " + accessToken.getToken();
      Response response = rsClient.target(urlDiscs).request().header(HttpHeaders.AUTHORIZATION, bearerToken).get();
      return response.readEntity(new GenericType<List<String>>() {
      });
    } finally {
      rsClient.close();
    }
  }
```

现在是时候检查我们刚刚做了什么。首先，我们创建了一个`ResteasyClient`对象。如果您注意到了，我们使用了一些东西来禁用信任管理和主机名验证。这个调用的结果是关闭服务器证书验证，允许中间人攻击。因此，请谨慎使用此功能。

之后，我们创建了一个`form`对象并传入一些参数。这些参数通过`param()`方法传入，分别表示参数名和参数值。这意味着我们指定了应用程序请求的授权类型，这将是`client_credentials`。

然后，就像我们之前在之前的示例中所做的那样，让我们创建一个 RESTEasy web 目标，将目标对准显示紧凑光盘列表的 URL。请记住，这个 URL 是我们之前创建的一个静态字段中设置的。这个 web 目标将是我们将要访问的`resourceTarget`对象。

当我们使用`register()`方法并传入一个`BasicAuthentication`对象时，我们注册了一个自定义的 JAX-RS 组件实例，以在可配置的上下文范围内被实例化和使用。

接下来，通过对我们的 web 目标执行请求，创建`AccessTokenResponse`类。然后，在同一行中，我们执行一个 post 请求，以便同步发送实体和我们想要获取的响应类型。`Entity.form()`方法从我们之前创建的`form`对象中创建`application/x-www-form-urlencoded`实体。现在，这将返回一个`AccessTokenResponse`对象；我们使用这个对象通过在令牌的开头添加`Bearer`一词来构建令牌。

最后，通过执行对`urlDiscs`变量中设置的 URL 的请求，让我们创建响应对象。我们应该使用`ResteasyClient`对象来对准这个资源，然后执行请求，并使用`HttpHeaders.AUTHORIZATION`将头字段设置为使用变量`bearerToken`中设置的`bearer`令牌。这样，我们就可以访问目标资源；在这种情况下，我们可以看到信息。

由于我们继续使用相同的应用业务，我们可以重用之前示例中的网页。确保在您的示例中，与之前示例中相同的路径中，包含网页`index.html`和`discsList.jsp`。我们还将使用`jboss-deployment-structure.xml`文件中设置的配置，因为我们使用相同的模块依赖关系。

我们的`web.xml`文件应该比之前的示例看起来更简单，可能是这样的：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app 

      xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
      version="3.0">
    <security-constraint>
        <web-resource-collection>
            <url-pattern>/*</url-pattern>
        </web-resource-collection>
        <user-data-constraint>
            <transport-guarantee>CONFIDENTIAL</transport-guarantee>
        </user-data-constraint>
    </security-constraint>
</web-app>
```

## 运行应用程序

您可以从[`github.com/restful-java-web-services-security/source-code/tree/master/chapter04`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter04)下载完整的代码和配置。解压文件，里面会有一个名为`token-grant`的文件夹。您必须使用相同的命令部署这个项目。作为要求，您必须部署`oauth-server`、`oauth-client`和`discstore`这些项目。

现在是运行我们的应用程序的时候了。让我们执行在之前示例中 OAuth 示例中所做的步骤。之后，我们必须打开我们喜欢的浏览器，输入 URL`https://localhost:8443/token-grant/`。这将引导我们到以下网页：

![运行应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_04_03.jpg)

嗯，正如你所注意到的，我们重复使用了同一个网页，只是为了这些例子的目的。然而，有一个小区别；当调用不同的网页时，你可以查看我们刚刚解释的核心。这将执行一个令牌，通过这个令牌，我们将执行一个请求，以访问我们想要访问的数据。结果，我们将在网页中读取我们的紧凑光盘列表，如下面的屏幕截图所示：

![运行应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_04_04.jpg)

最终结果是能够在网页中呈现光盘列表。然而，不要忘记发生了什么；我们只是使用请求、基本身份验证和一个表单获得了访问令牌响应。有了访问令牌响应，我们可以创建响应并呈现具有相应授权的数据。

# 自定义过滤器

简要介绍一下，JAX-RS 2.0 有两种不同的拦截概念：过滤器和拦截器。

拦截器是拦截 EJB 方法调用的组件。它们可以用于审计和记录 EJB 被访问的时间。这是本书不包括的一个主题，但如果你感到好奇，想要了解更多，我们给你以下链接作为参考，这样你就可以查找：

+   [`docs.oracle.com/javaee/6/tutorial/doc/gkigq.html`](http://docs.oracle.com/javaee/6/tutorial/doc/gkigq.html)

+   [`www.javacodegeeks.com/2013/07/java-ee-ejb-interceptors-tutorial-and-example.html`](http://www.javacodegeeks.com/2013/07/java-ee-ejb-interceptors-tutorial-and-example.html)

过滤器主要用于更改或处理传入和传出的请求或响应头。它们可以在请求和响应处理之前和之后执行。

此外，JAX-RS 2.0 为我们提供了两类过滤器：服务器端过滤器和客户端端过滤器。以下图表向我们展示了这个概念的更好分类：

![自定义过滤器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-websvc-sec/img/0109OS_04_05.jpg)

## 服务器端过滤器

当我们在服务器端时，这些过滤器有另一种分类；容器请求过滤器在调用 JAX-RS 资源方法之前执行。此外，我们还有容器响应过滤器；你可能已经猜到，它们在调用 JAX-RS 资源方法之后执行。然而，这并不是结束；容器请求过滤器还有另一种分类：预匹配和后匹配。

您可以通过`@PreMatching`注解指定一个预匹配容器请求过滤器，这意味着过滤器将在与传入的 HTTP 请求匹配 JAX-RS 资源方法之前执行。

容器请求过滤器可以通过执行`abortWith (Response)`方法来中止请求。如果过滤器实现了自定义身份验证协议，它可能希望中止请求。

一旦资源类方法被执行，JAX-RS 将运行所有容器响应过滤器。这些过滤器允许您在它被编组并发送到客户端之前修改传出响应。

## 客户端过滤器

正如我们已经告诉过你的，客户端端也有过滤器，与服务器端过滤器类似，它们也有两种类型的过滤器：客户端请求过滤器和客户端响应过滤器。客户端请求过滤器在将 HTTP 请求发送到服务器之前执行。另一方面，客户端响应过滤器在从服务器接收响应后执行，但在组装响应主体之前执行。

客户端请求过滤器也能够中止请求，并在不经过服务器的情况下提供响应。客户端响应过滤器能够在将响应主体组装之前修改响应对象。

## 过滤器的示例用法

在看了一些关于这个主题的必要理论之后，现在是时候让你亲自动手了。现在，我们将实现一个例子，以支持我们的新理论知识。所以，让我们开始吧！

我们将实现一个拦截器，它将根据请求中发送的用户名和密码验证用户的访问权限。您可以从以下链接下载这个示例的完整代码：

[`github.com/restful-java-web-services-security/source-code/tree/master/chapter04`](https://github.com/restful-java-web-services-security/source-code/tree/master/chapter04)

我们有我们的紧凑碟商店的主题。因此，以下类将代表我们的服务，并且它将具有按名称查找紧凑碟和更新紧凑碟信息的功能。这里使用的注解已经在前一章中学习过，所以您可能会发现以下代码易于理解：

```java
 @Path("/compactDisc-service")
public class CompactDiscService {
  @PermitAll
 @GET
 @Path("/compactDiscs/{name}")
  public Response getCompactDiscByName(@PathParam("name") String name, @Context Request request) {
    Response.ResponseBuilder rb = Response.ok(CompactDiscDatabase.getCompactDiscByName(name));
    return rb.build();
  }

  @RolesAllowed("ADMIN")
 @PUT
 @Path("/compactDiscs/{name}")
  public Response updatePriceByDiscName(@PathParam("name") String name) {
    // Update the User resource
    CompactDiscDatabase.updateCompactDisc(name, 10.5);
    return Response.status(200).build();
  }
}
```

正如您所看到的，我们只创建了两个方法，一个用于按名称检索紧凑碟，另一个用于更新紧凑碟的价格。注解让我们知道方法`getCompactDiscByName()`可以被所有人访问和执行；与此同时，方法`updatePriceByDiscName()`只能被具有`ADMIN`角色的用户访问和执行。

如果您注意到前面的代码中，我们使用了类`CompactDiscDatabase`，它模拟了一个数据库。我们在之前的示例中应用了相同的技术。由于它运行得非常好，让我们再做一次。这个类没有任何特殊的代码。您可以从以下代码中了解到这一点：

```java
public class CompactDiscDatabase {
  public static HashMap<String, CompactDisc> compactDiscs = new HashMap<String, CompactDisc>();

  static {
    CompactDisc ramonesCD = new CompactDisc();
    ramonesCD.setDiscName("Ramones Anthology");
    ramonesCD.setBandName("The Ramones");
    ramonesCD.setPrice(15.0);

    Calendar calendar = Calendar.getInstance();
    calendar.set(1980, 10, 22);
    Date realeaseDate = calendar.getTime();
    ramonesCD.setReleaseDate(realeaseDate);
    compactDiscs.put("Ramones Anthology", ramonesCD);

  }

  public static CompactDisc getCompactDiscByName(String name) {
    return compactDiscs.get(name);
  }

  public static void updateCompactDisc(String name, double newPrice) {
    CompactDisc cd = compactDiscs.get(name);
    cd.setPrice(newPrice);
  }
}
```

这里没有什么复杂的；我们只是创建了一个映射并放置了一个条目。这个条目是一个紧凑碟对象，正如您所看到的。我们有两个静态方法，将模拟查询——一个 SELECT 语句和一个 UPDATE 语句。

现在，让我们检查我们的`CompactDisc`类，如下所示的代码：

```java
@XmlAccessorType(XmlAccessType.NONE)
@XmlRootElement(name = "compactDisc")
public class CompactDisc implements Serializable {
  private static final long serialVersionUID = 1L;

  @XmlElement(name = "discName")
  private String discName;

  @XmlElement(name = "bandName")
  private String bandName;

  @XmlElement(name = "releaseDate")
  private Date releaseDate;

  @XmlElement(name = "price")
  private double price;
//getters and setters
}
```

在这个类中，我们只设置了代表常见紧凑碟属性的字段。注解`@XmlElement`用于将属性映射到从属性名称派生的 XML 元素。

现在，是时候实现过滤器了。我们将在这个简短的介绍之后展示代码，解释我们所做的事情，并解释实现中使用的一些技术概念。准备好了吗？我们开始吧！

由于这个类的代码有点长，我们将把它分开，并在每个代码块后包含一个简短的描述，如下所示：

```java
@Provider
public class SecurityFilter implements javax.ws.rs.container.ContainerRequestFilter {

  private static final String ADMIN = "ADMIN";
  private static final String RESOURCE_METHOD_INVOKER = "org.jboss.resteasy.core.ResourceMethodInvoker";
  private static final String AUTHORIZATION_PROPERTY = "Authorization";
  private static final String AUTHENTICATION_SCHEME = "Basic";
  private static final ServerResponse ACCESS_DENIED = new ServerResponse("Access denied for this resource", 401,
      new Headers<Object>());
  private static final ServerResponse ACCESS_FORBIDDEN = new ServerResponse("Nobody can access this resource", 403,
      new Headers<Object>());
```

让我们来看看这段代码。为了实现一个过滤器，第一步是注解`@Provider`。当我们在类级别放置这个注解时，我们将该类设置为过滤器。我们的类名是`SecurityFilter`，正如您所看到的，它实现了接口`ContainerRequestFilter`。如果您记得的话，这个过滤器将在服务器端执行，并在资源方法被调用之前执行。

在我们的类主体开始时，我们设置了一些稍后将使用的常量。`AUTHORIZATION_PROPERTY`常量只代表一个属性的名称，`RESOURCE_METHOD_INVOKER`常量也是如此。`AUTHENTICATION_SCHEME`常量只代表一个字符串。`ACCESS_DENIED`和`ACCESS_FORBIDDEN`常量代表两种不同的服务器响应对象，以便在请求被拒绝或用户没有足够权限时通知用户其请求的结果。

由于我们实现了接口`ContainerRequestFilter`，我们必须重写`filter()`方法。就是在这个方法中，我们将根据执行请求的用户来放置我们的逻辑，以便过滤请求。

让我们开始。作为第一步，我们使用常量`RESOURCE_METHOD_INVOKER`获取请求的方法。之后，我们将拥有一个`ResourceMethodInvoker`对象，然后是`Method`对象，如下所示：

```java
@Override
public void filter(ContainerRequestContext requestContext) {
    ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) requestContext
        .getProperty(RESOURCE_METHOD_INVOKER);
    Method method = methodInvoker.getMethod();
```

接下来，我们将对`method`执行一些简单的验证。我们将检查方法是否带有`@PermitAll`注解。如果没有，那么方法继续执行，我们将检查它是否带有`@DenyAll`注解。如果方法带有`DenyAll`注解，那么我们将中止请求，包括常量`ACCESS_FORBIDDEN`，如下所示的代码：

```java
// Access allowed for all
    if (!method.isAnnotationPresent(PermitAll.class)) {
      // Access denied for all
      if (method.isAnnotationPresent(DenyAll.class)) {
        requestContext.abortWith(ACCESS_FORBIDDEN);
        return;
      }
```

现在，我们必须获取用户名和密码。我们必须首先获取请求的头，并将其放入一个映射中。然后，我们使用`常量 AUTHORIZATION_PROPERTY`作为键获取授权字符串列表。这个列表将告诉我们用户是否有足够的权限。因此，我们检查列表是否为空或为 null；如果进入`if()`块，我们将中止请求，包括常量`ACCESS_DENIED`，如下面的代码所示：

```java
      final MultivaluedMap<String, String> headersMap = requestContext.getHeaders();

      final List<String> authorizationList = headersMap.get(AUTHORIZATION_PROPERTY);

      if (authorizationList == null || authorizationList.isEmpty()) {
        requestContext.abortWith(ACCESS_DENIED);
        return;
      }
```

这个列表的第一个元素是编码后的用户名和密码字符串。因此，我们执行替换并消除常量`AUTHENTICATION_SCHEME`中包含的字符串。然后，我们使用`Base64.decodeBase64`解码器对其进行解码，并通过`StringTokenizer`获取分开的用户名和密码。让我们看一下下面的代码：

```java
 final String encodedUserPassword = authorizationList.get(0).replaceFirst(AUTHENTICATION_SCHEME + " ", "");

      String usernameAndPassword = new String(Base64.decodeBase64(encodedUserPassword));

      // Split username and password tokens
      final StringTokenizer tokenizer = new StringTokenizer(usernameAndPassword, ":");
      final String userName = tokenizer.nextToken();
      final String password = tokenizer.nextToken();
```

现在是时候评估和检查用户是否有足够的权限了。首先，让我们检查`method`是否具有`@RolesAllowed`注解；如果有，我们使用`method`对象获取允许的角色集合。最后，我们检查常量`ADMIN`是否包含在此列表中。如果没有，请求将被中止，并且`ACCESS_DENIED`将再次包含在其中，如下面的代码所示：

```java
      // Verify user access
 if (method.isAnnotationPresent(RolesAllowed.class)) {
 RolesAllowed rolesAnnotation = method.getAnnotation(RolesAllowed.class);
        Set<String> rolesSet = new HashSet<String>(Arrays.asList(rolesAnnotation.value()));

        // Is user valid?
        if (!isUserAllowed(userName, password, rolesSet)) {
        requestContext.abortWith(ACCESS_DENIED);
          return;
        }
      }
    }
  }

  private boolean isUserAllowed(final String username, final String password, final Set<String> rolesSet) {
    boolean isAllowed = false;

    if (rolesSet.contains(ADMIN)) {
      isAllowed = true;
    }
    return isAllowed;
  }
}
```

# 总结

在这一章中，我们研究并实施了一种最有用和必要的技术，目的是共享和保护我们的信息。如今，应用程序之间的相互作用大大增加，因为它们希望满足客户、用户等的要求，而在此过程中既不损害数据的安全性也不损害数据的完整性。

在这一章中，我们研究了几种技术，用于保护、限制和授权第三方应用程序使用我们的资源，从 OAuth 2.0 认证、单点登录、过滤器和令牌的简要但描述性概念开始。

通过一个实际的例子和真实的代码，您可以看到如何授予第三方应用程序对特定资源的权限，以便共享信息并保持对其的控制。此外，我们检查并使用特定代码来实现最近使用的技术之一，特别是在社交网络世界中使用的单点登录。现在，您可以将这些概念和技术付诸实践，以便构建应用程序相互交互，选择要共享的资源，要用作单点登录的应用程序以及基于用户和角色的资源使用进行过滤。
