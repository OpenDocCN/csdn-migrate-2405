# SpringBoot2 和 React 全栈开发实用指南（一）

> 原文：[`zh.annas-archive.org/md5/B5164CAFF262E48113020BA46AD77AF2`](https://zh.annas-archive.org/md5/B5164CAFF262E48113020BA46AD77AF2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在本书中，我们将使用 Spring Boot 2.0 和 React 创建一个现代 Web 应用程序。我们将从后端开始，使用 Spring Boot 和 MariaDB 开发 RESTful Web 服务。我们还将保护后端并为其创建单元测试。前端将使用 React JavaScript 库开发。将使用不同的第三方 React 组件使前端更加用户友好。最后，应用程序将部署到 Heroku。该书还演示了如何将后端 Docker 化。

# 本书适合谁

这本书是为：

+   想要学习全栈开发的前端开发人员

+   想要学习全栈开发的后端开发人员

+   使用其他技术的全栈开发人员

+   熟悉 Spring 但从未构建过全栈应用程序的 Java 开发人员。

# 充分利用本书

读者应具备以下知识：

+   基本的使用一些终端，如 PowerShell 的知识

+   基本的 Java 和 JavaScript 编程知识

+   基本的 SQL 数据库知识

+   基本的 HTML 和 CSS 知识

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明进行操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React`](https://github.com/PacktPublishing/Hands-On-Full-Stack-Development-with-Spring-Boot-2.0-and-React)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“在`domain`包中创建一个名为`CarRepository`的新类。”

代码块设置如下：

```java
@Entity
public class Car {

}
```

任何命令行输入或输出都是这样写的：

```java
mvn clean install
```

**粗体**：指示一个新术语，一个重要的词，或者您在屏幕上看到的词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子：“在 Eclipse 的 Project Explorer 中激活根包，右键单击。从菜单中选择 New | Package。”

警告或重要说明会显示在这样的形式下。

提示和技巧会显示在这样的形式下。


# 第一章：设置环境和工具 - 后端

在本章中，我们将为使用 Spring Boot 进行后端编程设置环境和工具。Spring Boot 是一个现代的基于 Java 的后端框架，使开发速度比传统的基于 Java 的框架更快。使用 Spring Boot，您可以创建一个具有嵌入式应用服务器的独立 Web 应用程序。

在本章中，我们将研究以下内容：

+   为 Spring Boot 开发构建环境

+   Eclipse IDE 和 Maven 的基础知识

+   创建和运行 Spring Boot 项目

+   解决运行 Spring Boot 应用程序的常见问题

# 技术要求

使用 Eclipse IDE 需要 Java SDK 版本 8 或更高版本。

在本书中，我们使用的是 Windows 操作系统，但所有工具也适用于 Linux 和 macOS。

# 设置环境和工具

有许多不同的 IDE 工具可用于开发 Spring Boot 应用程序。在本书中，我们使用 Eclipse，这是一个用于多种编程语言的开源 IDE。我们将通过使用 Spring Initializr 项目启动页面来创建我们的第一个 Spring Boot 项目。然后将项目导入 Eclipse 并执行。阅读控制台日志是开发 Spring Boot 应用程序时的关键技能。

# 安装 Eclipse

Eclipse 是由 Eclipse 基金会开发的开源编程 IDE。安装包可以从[`www.eclipse.org/downloads`](https://www.eclipse.org/downloads)下载。Eclipse 适用于 Windows、Linux 和 macOS。您应该下载最新版本的 Eclipse IDE for Java EE developers。

您可以下载 Eclipse 的 ZIP 包或执行安装向导的安装程序包。如果使用 ZIP 包，您只需将包解压到本地磁盘上，它将包含一个可执行的`Eclipse.exe`文件，您可以通过双击该文件来运行它。

# Eclipse 和 Maven 的基础知识

Eclipse 是用于多种编程语言的 IDE，如 Java、C++和 Python。Eclipse 包含不同的透视图以满足您的需求。透视图是 Eclipse 工作台中的一组视图和编辑器。以下屏幕截图显示了 Java 开发的常见透视图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/21f6b430-4b00-4aee-975e-b8d0290586b7.png)

在左侧，我们有项目资源管理器，可以在其中查看项目结构和资源。项目资源管理器也用于双击打开文件。文件将在工作台中间的编辑器中打开。控制台视图位于工作台的下部。控制台视图非常重要，因为它显示应用程序的日志消息。

如果您愿意，可以为 Eclipse 获取**Spring Tool Suite**（**STS**），但在本书中我们不会使用它，因为纯净的 Eclipse 安装已经足够满足我们的需求。STS 是一组插件，使 Spring 应用程序开发更加简单（[`spring.io/tools`](https://spring.io/tools)）。

Apache Maven 是一个软件项目管理工具。Maven 的基础是**项目对象模型**（**pom**）。Maven 使软件开发过程更加简单，也统一了开发过程。您也可以在 Spring Boot 中使用另一个名为 Gradle 的项目管理工具，但在本书中，我们将专注于使用 Maven。

pom 是一个包含有关项目的基本信息的`pom.xml`文件。还有 Maven 应该下载的所有依赖项以能够构建项目。

可以在`pom.xml`文件的开头找到有关项目的基本信息，例如应用程序的版本、打包格式等。

`pom.xml`文件的最低版本应包含项目根目录、`modelVersion`、`groupId`、`artifactId`和`version`。

依赖项在依赖项部分中定义，如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>com.packt</groupId>
  <artifactId>cardatabase</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>

  <name>cardatabase</name>
  <description>Demo project for Spring Boot</description>

```

```java
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.0.1.RELEASE</version>
    <relativePath/> <!-- lookup parent from repository -->
  </parent>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
```

Maven 通常是从命令行中使用的。Eclipse 包含嵌入的 Maven，并处理我们需要的所有 Maven 操作。因此，我们在这里不专注于 Maven 命令行的使用。最重要的是要了解`pom.xml`文件的结构以及如何向其中添加新的依赖项。

# 使用 Spring Initializr 创建项目

我们将使用 Spring Intializr 创建我们的后端项目，这是一个用于创建 Spring Boot 项目的基于 Web 的工具。Spring Intializr 可以在[`start.spring.io`](https://start.spring.io)找到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/506bc928-20ef-4c53-813b-94a3301058ec.png)

我们将使用 Java 和最新的 Spring Boot 版本生成一个 Maven 项目。在“Group”字段中，我们将定义我们的 group ID，这也将成为我们 Java 项目中的基本包。在“Artifact”字段中，我们将定义 artifact ID，这也将是我们在 Eclipse 中项目的名称。

在“Dependencies”部分，我们将选择我们项目中需要的启动器和依赖项。Spring Boot 提供了简化 Maven 配置的启动器包。Spring Boot 启动器实际上是一组您可以包含在项目中的依赖项。您可以在搜索字段中键入依赖项的关键字，也可以点击“切换到完整版本”链接查看所有可用的依赖项。我们将通过选择两个依赖项——Web 和 DevTools 来启动我们的项目。您可以在搜索字段中键入依赖项，也可以切换到完整版本并查看所有可用的启动器包和依赖项： 

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/3fc7e3aa-21c8-4c67-bba0-d356b18ff5d4.png)

DevTools 依赖项为我们提供了 Spring Boot 开发工具，提供了自动重启功能。这样做可以加快开发速度，因为应用程序在保存更改后会自动重新启动。Web 启动器包是全栈开发的基础，并提供了嵌入式 Tomcat。

最后，您必须按“Generate Project”按钮，这将为我们生成项目启动器 ZIP 包。

# 如何运行项目

1.  在上一个主题中创建的项目 ZIP 包中提取并打开 Eclipse。

1.  我们将把项目导入到 Eclipse IDE 中。要开始导入过程，请选择“文件|导入”菜单，导入向导将打开。以下屏幕截图显示了向导的第一页：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/99a3be84-b10e-4d22-bd46-32baa4927237.png)

1.  在第一阶段，您应该从`Maven`文件夹下的列表中选择“Existing Maven Projects”，然后按“Next”按钮进入下一阶段。以下屏幕截图显示了导入向导的第二步：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/c3a17fd6-7875-4660-88c7-62dc2919b040.png)

1.  在此阶段，通过按“Browse...”按钮选择提取的项目文件夹。然后，Eclipse 会找到项目文件夹根目录下的`pom.xml`文件，并在窗口的“Projects”部分中显示它。

1.  按“Finish”按钮完成导入。如果一切顺利，您应该在 Eclipse 项目资源管理器中看到`cardatabase`项目。项目准备就绪需要一段时间，因为所有依赖项将在导入后由 Maven 加载。您可以在 Eclipse 右下角看到依赖项下载的进度。以下屏幕截图显示了成功导入后的 Eclipse 项目资源管理器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/30e8b5c1-9e30-4589-9f91-10553da21385.png)

项目资源管理器还显示了我们项目的包结构，现在一开始只有一个名为`com.packt.cardatabase`的包。在该包下是我们的主应用程序类，名为`CardatabaseApplication.java`。

1.  现在，我们的应用程序中没有任何功能，但我们可以运行它并查看是否一切顺利启动。要运行项目，请双击打开主类，然后在 Eclipse 工具栏中按“Run”按钮，或者选择运行菜单并按“Run as | Java Application”：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/72e8172c-ee62-4733-aec1-58268f340153.png)

您可以在 Eclipse 中看到控制台视图打开，其中包含有关项目执行的重要信息。这是所有日志文本和错误消息出现的视图，因此在出现问题时检查视图的内容非常重要。

现在，如果项目被正确执行，您应该在控制台的末尾看到文本`Started CardatabaseApplication in...`。以下屏幕截图显示了我们的 Spring Boot 项目启动后 Eclipse 控制台的内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/1f00d6bf-b504-4f06-9e42-2d7722157dd1.png)

在我们项目的根目录中有`pom.xml`文件，这是我们项目的 Maven 配置文件。如果您查看文件中的依赖项，您会发现现在有我们在 Spring Initializr 页面上选择的依赖项。还有一个测试依赖项自动包含，无需任何选择。在接下来的章节中，我们将为我们的应用程序添加更多功能，然后我们将手动向`pom.xml`文件添加更多依赖项：

```java
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-devtools</artifactId>
      <scope>runtime</scope>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>

```

让我们仔细看一下 Spring Boot 主类。在类的开头，有`@SpringBootApplication`注释。实际上，它是多个注释的组合，例如以下内容：

| **注释** | **描述** |
| --- | --- |
| `@EnableAutoConfiguration` | 启用 Spring Boot 自动配置。Spring Boot 将根据依赖项自动配置您的项目。例如，如果您有`spring-boot-starter-web`依赖项，Spring Boot 会假定您正在开发 Web 应用程序，并相应地配置您的应用程序。 |
| `@ComponentScan` | 启用 Spring Boot 组件扫描，以查找应用程序中的所有组件。 |
| `@Configure` | 定义可用作 bean 定义来源的类。 |

以下代码显示了 Spring Boot 应用程序的`main`类：

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CardatabaseApplication {

  public static void main(String[] args) {
    SpringApplication.run(CardatabaseApplication.class, args);
  }
}
```

应用程序的执行从`main`方法开始，就像标准的 Java 应用程序一样。

建议将`main`应用程序类放在其他类上方的根包中。应用程序无法正确工作的一个常见原因是 Spring Boot 无法找到一些关键类。

# Spring Boot 开发工具

Spring Boot 开发工具使应用程序开发过程更加轻松。如果将以下依赖项添加到 Maven 的`pom.xml`文件中，项目将包括开发人员工具：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-devtools</artifactId>
      <scope>runtime</scope>
    </dependency>
```

创建应用程序的完全打包生产版本时，开发工具将被禁用。

当您对项目类路径文件进行更改时，应用程序会自动重新启动。您可以通过向`main`类添加一行注释来测试。保存文件后，您可以在控制台中看到应用程序已重新启动：

```java
package com.packt.cardatabase;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CardatabaseApplication {

  public static void main(String[] args) {
    // After adding this comment the application is restarted
    SpringApplication.run(CardatabaseApplication.class, args);
  }
}
```

# 日志和问题解决

Spring Boot starter 包提供了一个 logback，我们可以在没有任何配置的情况下用于日志记录。以下示例代码显示了如何使用日志记录：

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CardatabaseApplication {
  private static final Logger logger = LoggerFactory.getLogger(CardatabaseApplication.class);
  public static void main(String[] args) {
    SpringApplication.run(CardatabaseApplication.class, args);
    logger.info("Hello Spring Boot");
  }
}
```

运行项目后，可以在控制台中看到日志消息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/c49a8750-9889-42a3-aec9-3d812ac16808.png)

日志记录有七个不同的级别——`TRACE`，`DEBUG`，`INFO`，`WARN`，`ERROR`，`FATAL`和`OFF`。您可以在 Spring Boot 的`application.properties`文件中配置日志记录级别。该文件可以在项目内的`resources`文件夹中找到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/2b2cf448-8526-4f57-a0bb-413aaba12765.png)

如果我们将日志级别设置为`INFO`，我们可以看到低于`INFO`级别（`INFO`，`WARN`，`ERROR`和`FATAL`）的日志消息。在下面的示例中，我们设置了根日志级别，但您也可以在包级别设置它：

```java
logging.level.root=INFO
```

现在，当您运行项目时，您将不再看到`TRACE`和`DEBUG`消息。这可能是应用程序生产版本的良好设置：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/25e9f9d4-4fdc-4c88-91c4-d02ceb95d964.png)

Spring Boot 默认使用 Apache Tomcat ([`tomcat.apache.org/`](http://tomcat.apache.org/))作为应用服务器。默认情况下，Tomcat 在端口`8080`上运行。您可以在`application.properties`文件中更改端口。以下设置将在端口`8081`上启动 Tomcat：

```java
server.port=8081
```

如果端口被占用，应用程序将无法启动，并且您将在控制台中看到以下消息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/797452b6-c4f3-4cfe-83b9-82742f1aa197.png)

您必须停止监听端口`8080`的进程，或在 Spring Boot 应用程序中使用另一个端口。

# 安装 MariaDB

在下一章中，我们将使用 MariaDB，因此我们将在本地计算机上安装它。MariaDB 是一个广泛使用的开源关系数据库。MariaDB 适用于 Windows 和 Linux，您可以从[`downloads.mariadb.org/`](https://downloads.mariadb.org/)下载最新稳定版本。MariaDB 是在 GNU GPL 2 许可下开发的。

对于 Windows，有 MSI 安装程序，我们将在这里使用。下载安装程序并执行它。从安装向导中安装所有功能：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/9b31bc8c-0924-4877-b114-d02e221657e2.png)

在下一步中，您应该为 root 用户提供密码。在下一章中，我们连接到数据库时需要此密码：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/4fae938c-a3aa-4875-b313-01d137018b5b.png)

在下一阶段，我们可以使用默认设置：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/84b2f956-de37-4aad-8021-029d9fc1e576.png)

现在安装开始了，MariaDB 将安装到您的本地计算机上。安装向导将为我们安装**HeidiSQL**。这是一个图形化易于使用的数据库客户端。我们将使用它来添加新数据库并对我们的数据库进行查询。您还可以使用安装包中包含的命令提示符：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ebd75046-230f-4433-8b68-1a6b3975b4ed.png)

# 总结

在本章中，我们安装了使用 Spring Boot 进行后端开发所需的工具。对于 Java 开发，我们使用了 Eclipse IDE，这是一个广泛使用的编程 IDE。我们通过使用 Spring Initializr 页面创建了一个新的 Spring Boot 项目。创建项目后，它被导入到 Eclipse 中，并最终执行。我们还介绍了如何解决 Spring Boot 的常见问题以及如何查找重要的错误和日志消息。最后，我们安装了一个 MariaDB 数据库，我们将在下一章中使用。

# 问题

1.  Spring Boot 是什么？

1.  Eclipse IDE 是什么？

1.  Maven 是什么？

1.  我们如何创建一个 Spring Boot 项目？

1.  我们如何运行 Spring Boot 项目？

1.  我们如何在 Spring Boot 中使用日志记录？

1.  我们如何在 Eclipse 中查找错误和日志消息？

# 进一步阅读

Packt 还有其他很好的资源可供学习 Spring Boot：

+   [`www.packtpub.com/application-development/learning-spring-boot-20-second-edition`](https://www.packtpub.com/application-development/learning-spring-boot-20-second-edition)

+   [`www.packtpub.com/web-development/spring-boot-getting-started-integrated-course`](https://www.packtpub.com/web-development/spring-boot-getting-started-integrated-course)


# 第二章：使用 JPA 创建和访问数据库

本章介绍了如何在 Spring Boot 中使用 JPA。我们将使用实体类创建数据库。在第一阶段，我们将使用 H2 内存数据库进行开发和演示。H2 是一个内存中的 SQL 数据库，非常适合快速开发或演示目的。在第二阶段，我们将从 H2 转移到使用 MariaDB。本章还描述了 CRUD 存储库的创建以及数据库表之间的一对多连接。

在本章中，我们将研究以下内容：

+   使用 JPA 的基础知识和好处

+   如何使用实体类定义数据库

+   如何使用 Spring Boot 后端创建数据库

# 技术要求

使用 Spring Boot 需要 Java SDK 版本 8 或更高版本（[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)）。

为了创建数据库应用程序，需要安装 MariaDB（[`downloads.mariadb.org/`](https://downloads.mariadb.org/)）。

# ORM、JPA 和 Hibernate 的基础知识和好处

**对象关系映射**（**ORM**）是一种技术，允许您使用面向对象的编程范式从数据库中提取和操作数据。ORM 对程序员来说非常好，因为它依赖于面向对象的概念，而不是数据库结构。它还可以加快开发速度，减少源代码量。ORM 大多数独立于数据库，开发人员不必担心特定于供应商的 SQL 语句。

**Java 持久 API**（**JPA**）为 Java 开发人员提供了对象关系映射。JPA 实体是一个 Java 类，表示数据库表的结构。实体类的字段表示数据库表的列。

Hibernate 是最流行的基于 Java 的 JPA 实现，它在 Spring Boot 中作为默认使用。Hibernate 是一个成熟的产品，在大型应用程序中被广泛使用。

# 创建实体类

实体类是一个简单的 Java 类，带有 JPA 的`@Entity`注解。实体类使用标准的 JavaBean 命名约定，并具有适当的 getter 和 setter 方法。类字段具有私有可见性。

当应用程序初始化时，JPA 会创建一个名为类名的数据库表。如果要为数据库表使用其他名称，可以使用`@Table`注解。

为了能够使用 JPA 和 H2 数据库，我们必须将以下依赖项添加到`pom.xml`文件中：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
```

以下是创建实体类的步骤：

1.  要在 Spring Boot 中创建实体类，我们首先将为实体创建自己的包。该包应该在根包下创建。

1.  在 Eclipse 项目资源管理器中激活根包，右键单击显示菜单。

1.  从菜单中选择 New | Package。以下截图显示了为实体类创建包：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/db4abdaa-1fcf-4e52-928d-76b55ab1a1a6.png)

1.  我们将包命名为`com.packt.cardatabase.domain`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/1a9b38e4-f800-4008-b706-12f225121521.png)

1.  接下来，我们创建实体类。激活一个新的实体包，右键单击，选择菜单中的 New | Class。因为我们要创建一个汽车数据库，实体类的名称是`Car`。在`Name`字段中输入`Car`，然后按下`Finish`按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/8fe3af1e-49e2-480e-8e33-ba06ffa7429e.png)

1.  在项目资源管理器中双击打开编辑器中的`Car`类文件。首先，我们必须使用`@Entity`注解对类进行注释。`Entity`注解从`javax.persistence`包中导入：

```java
      package com.packt.cardatabase.domain;

      import javax.persistence.Entity;

      @Entity
      public class Car {

      }
```

您可以使用 Eclipse IDE 中的*Ctrl* + *Shift* + *O*快捷键自动导入缺少的包。

1.  接下来，我们为我们的类添加一些字段。实体类字段映射到数据库表列。实体类还必须包含一个唯一的 ID，该 ID 用作数据库中的主键：

```java
      package com.packt.cardatabase.domain;

      import javax.persistence.Entity;
      import javax.persistence.GeneratedValue;
      import javax.persistence.GenerationType;
      import javax.persistence.Id;

      @Entity
      public class Car {
        @Id
        @GeneratedValue(strategy=GenerationType.AUTO)
        private long id;
        private String brand, model, color, registerNumber;
        private int year, price;
      }
```

使用`@Id`注释定义主键。`@GeneratedValue`注释定义 ID 由数据库自动生成。我们还可以定义我们的键生成策略。类型`AUTO`表示 JPA 提供程序为特定数据库选择最佳策略。您还可以通过使用`@Id`注释对多个属性进行注释来创建复合主键。

默认情况下，数据库列的命名按类字段命名。如果要使用其他命名约定，可以使用`@Column`注释。使用`@Column`注释，还可以定义列的长度以及列是否可为空。以下代码显示了使用`@Column`注释的示例。通过这个定义，在数据库中列的名称是`desc`，列的长度是`512`，并且它是不可为空的：

```java
@Column(name="desc", nullable=false, length=512)
private String description
```

1.  最后，我们为实体类添加 getter、setter 和带属性的构造函数。由于自动生成 ID，我们不需要在构造函数中添加 ID 字段。`Car`实体类构造函数的源代码如下：

Eclipse 提供了自动生成 getter、setter 和构造函数的功能。将光标放在类内并右键单击。从菜单中选择“Source | Generate Getters and Setters...”或“Source | Generate Constructor using fields...”

```java
package com.packt.cardatabase.domain;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class Car {
  @Id
  @GeneratedValue(strategy=GenerationType.AUTO)
  private long id;
  private String brand, model, color, registerNumber;
  private int year, price;

  public Car() {}

  public Car(String brand, String model, String color, 
    String registerNumber, int year, int price) {
    super();
    this.brand = brand;
    this.model = model;
    this.color = color;
    this.registerNumber = registerNumber;
    this.year = year;
    this.price = price;
  }
```

以下是`Car`实体类的 getter 和 setter 的源代码：

```java
  public String getBrand() {
    return brand;
  }
  public void setBrand(String brand) {
    this.brand = brand;
  }
  public String getModel() {
    return model;
  }
  public void setModel(String model) {
    this.model = model;
  }
  public String getColor() {
    return color;
  }
  public void setColor(String color) {
    this.color = color;
  }
  public String getRegisterNumber() {
    return registerNumber;
  }
  public void setRegisterNumber(String registerNumber) {
    this.registerNumber = registerNumber;
  }
  public int getYear() {
    return year;
  }
  public void setYear(int year) {
    this.year = year;
  }
  public int getPrice() {
    return price;
  }
  public void setPrice(int price) {
    this.price = price;
  } 
}
```

当我们运行应用程序时，数据库中必须创建名为`car`的表。为了确保这一点，我们将在`application.properties`文件中添加一个新属性。这将使 SQL 语句的日志记录到控制台：

```java
spring.jpa.show-sql=true
```

当运行应用程序时，我们现在可以看到表创建语句：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/5ea5f7d7-c3d8-45c4-a545-1fd6b27b0c94.png)

H2 提供了一个基于 Web 的控制台，可用于探索数据库并执行 SQL 语句。要启用控制台，我们必须将以下行添加到`application.properties`文件中。第一个设置启用 H2 控制台，第二个设置定义了我们可以使用的端点来访问控制台：

```java
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console
```

您可以通过在 Web 浏览器中导航到`localhost:8080/h2-console`来访问 H2 控制台。在登录窗口中，使用`jdbc:h2:mem:testdb`作为 JDBC URL，并在密码字段中留空。按下“连接”按钮登录到控制台：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/54d517da-1a8d-4868-9a48-4853231caafe.png)

现在您可以在数据库中看到我们的`car`表。您可能会注意到注册号之间有一个下划线。这是由于属性（`registerNumber`）的驼峰命名法：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f8de2f11-fdfe-4ca4-9128-acb7e19e414c.png)

# 创建 CRUD 存储库

Spring Boot Data JPA 为 CRUD 操作提供了`CrudRepository`接口。它为我们的实体类提供了 CRUD 功能。

现在，我们将在`domain`包中创建我们的存储库，如下所示：

1.  在`domain`包中创建一个名为`CarRepository`的新类，并根据以下代码片段修改文件：

```java
      package com.packt.cardatabase.domain;

      import org.springframework.data.repository.CrudRepository;

      public interface CarRepository extends CrudRepository <Car, Long> {

      }
```

我们的`CarRepository`现在扩展了 Spring Boot JPA 的`CrudRepository`接口。`<Car, Long>`类型参数定义了这是`Car`实体类的存储库，ID 字段的类型是 long。

`CrudRepository`提供了多个 CRUD 方法，我们现在可以开始使用。以下表列出了最常用的方法：

| **方法** | **描述** |
| --- | --- |
| `long count()` | 返回实体的数量 |
| `Iterable<T> findAll()` | 返回给定类型的所有项目 |
| `Optional<T> findById(ID Id)` | 通过 id 返回一个项目 |
| `void delete(T entity)` | 删除实体 |
| `void deleteAll()` | 删除存储库的所有实体 |
| `<S extends T> save(S entity)` | 保存实体 |

如果方法只返回一个项目，则返回`Optional<T>`而不是`T`。`Optional`类在 Java 8 SE 中引入。`Optional`是一种单值容器类型，可以有值，也可以没有。通过使用`Optional`，我们可以防止空指针异常。

1.  现在我们准备向我们的 H2 数据库添加一些演示数据。为此，我们将使用 Spring Boot 的`CommandLineRunner`。`CommandLineRunner`接口允许我们在应用程序完全启动之前执行额外的代码。因此，这是向数据库添加演示数据的好时机。`CommandLineRunner`位于主类中：

```java
      import org.springframework.boot.CommandLineRunner;
      import org.springframework.boot.SpringApplication;
      import org.springframework.boot.autoconfigure.SpringBootApplication;
      import org.springframework.context.annotation.Bean;

      @SpringBootApplication
      public class CardatabaseApplication {

        public static void main(String[] args) {
          SpringApplication.run(CardatabaseApplication.class, args);
        }

        @Bean
        CommandLineRunner runner(){
          return args -> {
            // Place your code here
          };
        } 
      }
```

1.  接下来，我们必须将我们的 car repository 注入到主类中，以便能够将新的 car 对象保存到数据库中。使用`@Autowired`注解来启用依赖注入。依赖注入允许我们将依赖项传递给对象。在我们注入了存储库类之后，我们可以使用它提供的 CRUD 方法。以下示例代码显示了如何向数据库中插入一些汽车：

```java
      import org.springframework.beans.factory.annotation.Autowired;
      import org.springframework.boot.CommandLineRunner;
      import org.springframework.boot.SpringApplication;
      import org.springframework.boot.autoconfigure.SpringBootApplication;
      import org.springframework.context.annotation.Bean;

      import com.packt.cardatabase.domain.Car;
      import com.packt.cardatabase.domain.CarRepository;

      @SpringBootApplication
      public class CardatabaseApplication {
        @Autowired 
        private CarRepository repository;

        public static void main(String[] args) {
          SpringApplication.run(CardatabaseApplication.class, args);
        }

        @Bean
        CommandLineRunner runner(){
          return args -> {
            // Save demo data to database
            repository.save(new Car("Ford", "Mustang", "Red",
             "ADF-1121", 2017, 59000));
            repository.save(new Car("Nissan", "Leaf", "White",
             "SSJ-3002", 2014, 29000));
```

```java
            repository.save(new Car("Toyota", "Prius", "Silver",
             "KKO-0212", 2018, 39000));
          };
        } 
      }
```

`Insert`语句可以在应用程序执行后在 Eclipse 控制台中看到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/9eb6f592-c706-4423-9ac2-229f78df8ed1.png)

您还可以使用 H2 控制台从数据库中获取汽车，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/022a3422-30f9-449a-8c37-ec146b27ffc4.png)

您可以在 Spring Data 存储库中定义自己的查询。查询必须以前缀开头，例如`findBy`。在前缀之后，您定义在查询中使用的实体类字段。以下是三个简单查询的示例代码：

```java
import java.util.List;

import org.springframework.data.repository.CrudRepository;

public interface CarRepository extends CrudRepository <Car, Long> {
  // Fetch cars by brand
  List<Car> findByBrand(String brand);

  // Fetch cars by color
  List<Car> findByColor(String color);

  // Fetch cars by year
  List<Car> findByYear(int year);

}
```

在`By`关键字之后可以有多个字段，使用`And`或`Or`关键字连接：

```java
package com.packt.cardatabase.domain;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

public interface CarRepository extends CrudRepository <Car, Long> {
  // Fetch cars by brand and model
  List<Car> findByBrandAndModel(String brand, String model);

  // Fetch cars by brand or color
  List<Car> findByBrandOrColor(String brand, String color); 
}
```

可以使用查询方法中的`OrderBy`关键字对查询进行排序：

```java
package com.packt.cardatabase.domain;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

public interface CarRepository extends CrudRepository <Car, Long> {
  // Fetch cars by brand and sort by year
  List<Car> findByBrandOrderByYearAsc(String brand);
}
```

您还可以通过`@Query`注解使用 SQL 语句创建查询。以下示例展示了在`CrudRepository`中使用 SQL 查询的用法：

```java
package com.packt.cardatabase.domain;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

public interface CarRepository extends CrudRepository <Car, Long> {
  // Fetch cars by brand using SQL
  @Query("select c from Car c where c.brand = ?1")
  List<Car> findByBrand(String brand);
}
```

您还可以使用`@Query`注解进行更高级的表达式，例如`like`。以下示例展示了在`CrudRepository`中使用`like`查询的用法：

```java
package com.packt.cardatabase.domain;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

public interface CarRepository extends CrudRepository <Car, Long> {
  // Fetch cars by brand using SQL
  @Query("select c from Car c where c.brand like %?1")
  List<Car> findByBrandEndsWith(String brand);
}
```

Spring Data JPA 还提供了`PagingAndSortingRepository`，它扩展了`CrudRepository`。它提供了使用分页和排序获取实体的方法。如果您处理大量数据，这是一个很好的选择。`PagingAndSortingRepository`可以类似于我们使用`CrudRepository`创建：

```java
package com.packt.cardatabase.domain;

import org.springframework.data.repository.PagingAndSortingRepository;

```

```java
public interface CarRepository extends PagingAndSortingRepository<Car, Long> {

}
```

在这种情况下，您现在拥有了存储库提供的两个新的附加方法：

| **方法** | **描述** |
| --- | --- |
| `Iterable<T> findAll(Sort sort)` | 返回按给定选项排序的所有实体 |
| `Page<T> findAll(Pageable pageable)` | 根据给定的分页选项返回所有实体 |

# 表之间的关系

接下来，我们创建一个名为`owner`的新表，它与`car`表具有一对多的关系。所有者可以拥有多辆汽车，但一辆汽车只能有一个所有者。以下的 UML 图显示了表之间的关系：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/97ade669-bf1f-4f12-bdec-5fe34cf5d487.png)

以下是创建新表的步骤：

1.  首先，在`domain`包中创建`Owner`实体和存储库。`Owner`实体和存储库的创建方式与`Car`类相似。以下是`Owner`实体类和`OwnerRepository`的源代码：

```java
      // Owner.java

      package com.packt.cardatabase.domain;

      import javax.persistence.Entity;
      import javax.persistence.GeneratedValue;
      import javax.persistence.GenerationType;
      import javax.persistence.Id;

      @Entity
      public class Owner {
        @Id
        @GeneratedValue(strategy=GenerationType.AUTO)
        private long ownerid;
        private String firstname, lastname;

        public Owner() {}

        public Owner(String firstname, String lastname) {
          super();
          this.firstname = firstname;
          this.lastname = lastname;
        }

        public long getOwnerid() {
          return ownerid;
        }
        public void setOwnerid(long ownerid) {
          this.ownerid = ownerid;
        }
        public String getFirstname() {
          return firstname;
        }
        public void setFirstname(String firstname) {
          this.firstname = firstname;
        }
        public String getLastname() {
          return lastname;
        }
        public void setLastname(String lastname) {
          this.lastname = lastname;
        } 
      }
```

```java
      // OwnerRepository.java

      package com.packt.cardatabase.domain;

      import org.springframework.data.repository.CrudRepository;

```

```java
      public interface OwnerRepository extends CrudRepository<Owner, Long> 
      {

      }
```

1.  在这个阶段，检查一切是否正确完成是很重要的。运行项目并检查数据库表是否都已创建，并且控制台中没有错误。下面的截图显示了在创建表时控制台的消息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/6f219664-b827-48a6-974a-789cac7ba8df.png)

现在，我们的 domain 包含两个实体类和存储库：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/0aac2b0d-6e2e-447a-a717-9de4535894c4.png)

1.  一对多关系可以通过使用`@ManyToOne`和`@OneToMany`注解来添加。在包含外键的汽车实体类中，您将使用`@ManyToOne`注解定义与所有者的关系。还要为所有者字段添加 getter 和 setter。建议对所有关联使用`FetchType.LAZY`。对于`toMany`关系，这是默认值，但对于`toOne`关系，您应该定义它。`FetchType`定义了从数据库中获取数据的策略。该值可以是`EAGER`或`LAZY`。在我们的情况下，懒惰策略意味着当从数据库中获取所有者时，将在需要时获取与所有者关联的所有汽车。`Eager`意味着汽车将立即与所有者一起获取。以下源代码显示了如何在`Car`类中定义一对多关系：

```java
      // Car.java

      @ManyToOne(fetch = FetchType.LAZY)
      @JoinColumn(name = "owner")
      private Owner owner;

      //Getter and setter
      public Owner getOwner() {
        return owner;
      }

      public void setOwner(Owner owner) {
        this.owner = owner;
      }
```

在所有者实体站点上，使用`@OneToMany`注解定义了关系。字段的类型是`List<Car>`，因为所有者可能拥有多辆汽车。还为此添加 getter 和 setter：

```java
      // Owner.java  

      @OneToMany(cascade = CascadeType.ALL, mappedBy="owner")
      private List<Car> cars;

      //Getter and setter
      public List<Car> getCars() {
        return cars;
      }

      public void setCars(List<Car> cars) {
        this.cars = cars;
      }
```

`@OneToMany`注解有两个我们正在使用的属性。`cascade`属性定义了级联如何影响实体。属性设置`ALL`意味着如果所有者被删除，与该所有者关联的汽车也将被删除。`mappedBy="owner"`属性设置告诉我们`Car`类具有所有者字段，这是该关系的外键。

当您运行项目时，您可以从控制台看到关系现在已经创建：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/65c81d66-5d5c-4226-97d8-3cc6cd3ec050.png)

1.  现在，我们可以使用`CommandLineRunner`向数据库添加一些所有者。让我们还修改`Car`实体类的构造函数并在那里添加一个所有者：

```java
      // Car.java constructor 

      public Car(String brand, String model, String color,
      String registerNumber, int year, int price, Owner owner) {
        super();
        this.brand = brand;
        this.model = model;
        this.color = color;
        this.registerNumber = registerNumber;
        this.year = year;
        this.price = price;
        this.owner = owner;
      }
```

1.  我们首先创建两个所有者对象并将其保存到数据库中。为了保存所有者，我们还必须将`OwnerRepository`注入到主类中。然后我们通过`Car`构造函数将所有者连接到汽车。以下是应用程序主类`CardatabaseApplication`的源代码：

```java
      @SpringBootApplication
      public class CardatabaseApplication {
        // Inject repositories
        @Autowired 
        private CarRepository repository;

        @Autowired 
        private OwnerRepository orepository;

        public static void main(String[] args) {
          SpringApplication.run(CardatabaseApplication.class, args);
        }

        @Bean
        CommandLineRunner runner() {
          return args -> {
            // Add owner objects and save these to db
            Owner owner1 = new Owner("John" , "Johnson");
            Owner owner2 = new Owner("Mary" , "Robinson");
            orepository.save(owner1);
            orepository.save(owner2);

            // Add car object with link to owners and save these to db.
            Car car = new Car("Ford", "Mustang", "Red", 
                "ADF-1121", 2017, 59000, owner1);
            repository.save(car);
            car = new Car("Nissan", "Leaf", "White",
                "SSJ-3002", 2014, 29000, owner2);
            repository.save(car);
            car = new Car("Toyota", "Prius", "Silver",
                "KKO-0212", 2018, 39000, owner2);
            repository.save(car);
          };
        } 
      }
```

如果现在运行应用程序并从数据库中获取汽车，您会发现所有者现在与汽车关联起来了。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/13e22a64-525c-4c56-8c71-1352688039b9.png)

如果要创建多对多关系，也就是说，在实践中，一个所有者可以拥有多辆汽车，一辆汽车可以有多个所有者，您应该使用`@ManyToMany`注解。在我们的示例应用程序中，我们将使用一对多关系，但以下是如何将关系更改为多对多的示例。在多对多关系中，建议使用`Set`而不是`List`与 hibernate 一起使用：

1.  在`Car`实体类的多对多关系中，以以下方式定义 getter 和 setter：

```java
      @ManyToMany(mappedBy = "cars") 
      private Set<Owner> owners; 

      public Set<Owner> getOwners() {
        return owners;
      }

      public void setOwners(Set<Owner> owners) {
        this.owners = owners;
      }
```

在所有者实体中，定义如下：

```java
      @ManyToMany(cascade = CascadeType.MERGE)
      @JoinTable(name = "car_owner", joinColumns = { @JoinColumn(name =
       "ownerid") }, inverseJoinColumns = { @JoinColumn(name = "id") }) 
      private Set<Car> cars = new HashSet<Car>(0); 

      public Set<Car> getCars() {
        return cars;
      }

      public void setCars(Set<Car> cars) {
        this.cars = cars;
      }
```

1.  现在，如果运行应用程序，将创建一个新的连接表，该表位于`car`和`owner`表之间。使用`@JoinTable`注解定义连接表。通过该注解，我们可以设置连接表的名称和连接列。以下是在使用多对多关系时数据库结构的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/586b87e4-1b95-4af1-b41d-9e95b1440794.png)

# 设置 MariaDB 数据库

现在，我们将数据库从 H2 切换到 MariaDB。数据库表仍然由 JPA 自动创建。但在运行应用程序之前，我们必须为其创建一个数据库。可以使用 HeidiSQL 创建数据库。打开 HeidiSQL，并按照以下步骤操作：

1.  右键单击数据库列表中的鼠标。

1.  然后，选择新建|数据库：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/bc77682b-cdf2-4ded-87cc-11e37a6790d8.png)

1.  让我们将数据库命名为`cardb`。按下 OK 后，您应该在数据库列表中看到新的`cardb`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a92e8240-513d-4ce7-bdfe-c4b20b8441be.png)

1.  在应用程序中，我们向`pom.xml`文件添加了 MariaDB 依赖项，并删除了不再需要的 H2 依赖项：

```java
      <dependency>
        <groupId>org.mariadb.jdbc</groupId>
        <artifactId>mariadb-java-client</artifactId>
      </dependency> 
```

1.  在`application.properties`文件中，您定义了数据库连接。首先，您将定义数据库的`url`、`username`、`password`和数据库驱动程序类。`spring.jpa.generate-ddl`设置定义了 JPA 是否应初始化数据库（`true`/`false`）。`spring.jpa.hibernate.ddl-auto`设置定义了数据库初始化的行为。可能的值有`none`、`validate`、`update`、`create`和`create-drop`。Create-drop 意味着在应用程序启动时创建数据库，并在应用程序停止时删除数据库。如果您不定义任何值，create-drop 也是默认值。Create 值仅在应用程序启动时创建数据库。Update 值创建数据库并在架构更改时更新架构。

```java
      spring.datasource.url=jdbc:mariadb://localhost:3306/cardb
      spring.datasource.username=root
      spring.datasource.password=YOUR_PASSWORD
      spring.datasource.driver-class-name=org.mariadb.jdbc.Driver

      spring.jpa.generate-ddl=true
      spring.jpa.hibernate.ddl-auto=create-drop
```

1.  现在，在运行应用程序后，您应该在 MariaDB 中看到表。以下截图显示了数据库创建后的 HeidiSQL UI。您的应用程序现在已准备好与 MariaDB 一起使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/13b4481b-9fd1-4995-9b3c-51bf2e2af457.png)

# 总结

在本章中，我们使用 JPA 来创建 Spring Boot 应用程序数据库。首先，我们创建了实体类，这些类映射到数据库表。然后，我们为我们的实体类创建了`CrudRepository`，它为实体提供了 CRUD 操作。之后，我们通过使用`CommandLineRunner`成功向我们的数据库添加了一些演示数据。我们还在两个实体之间创建了一对多的关系。在本章的开头，我们使用了 H2 内存数据库，而在结尾，我们将数据库切换到了 MariaDB。在下一章中，我们将为我们的后端创建 RESTful web 服务。

# 问题

1.  ORM、JPA 和 Hibernate 是什么？

1.  如何创建实体类？

1.  如何创建`CrudRepository`？

1.  `CrudRepository`如何为您的应用程序提供支持？

1.  如何在表之间创建一对多的关系？

1.  如何使用 Spring Boot 向数据库添加演示数据？

1.  如何访问 H2 控制台？

1.  如何将 Spring Boot 应用程序连接到 MariaDB？

# 进一步阅读

Packt 还有其他学习 Spring Boot 的资源：

+   [`www.packtpub.com/application-development/learning-spring-boot-20-second-edition`](https://www.packtpub.com/application-development/learning-spring-boot-20-second-edition)

+   [`www.packtpub.com/web-development/spring-boot-getting-started-integrated-course`](https://www.packtpub.com/web-development/spring-boot-getting-started-integrated-course)


# 第三章：使用 Spring Boot 创建 RESTful Web 服务

在本章中，我们将首先使用控制器类创建一个 RESTful Web 服务。之后，我们将演示如何使用 Spring Data REST 创建一个自动覆盖所有 CRUD 功能的 RESTful Web 服务。我们将使用前一章中创建的数据库应用作为起点。

在本章中，我们将研究以下内容：

+   RESTful Web 服务是什么

+   如何使用 Spring Boot 创建 RESTful Web 服务

+   如何测试 RESTful web 服务

# 技术要求

之前创建的 Spring Boot 应用程序是必需的。

需要使用 Postman、cURL 或其他适当的工具来使用各种 HTTP 方法传输数据。

# 使用 Spring Boot 创建 RESTful Web 服务

Web 服务是使用 HTTP 协议在互联网上进行通信的应用程序。有许多不同类型的 Web 服务架构，但所有设计的主要思想都是相同的。在本书中，我们正在从目前非常流行的设计中创建一个 RESTful Web 服务。

# REST 的基础知识

**REST**（**表述状态转移**）是一种用于创建 Web 服务的架构风格。REST 不是标准，但它定义了一组由 Roy Fielding 定义的约束。这六个约束如下：

+   **无状态**：服务器不保存有关客户端状态的任何信息。

+   **客户端服务器**：客户端和服务器独立运行。服务器不会在没有客户端请求的情况下发送任何信息。

+   **可缓存**：许多客户端经常请求相同的资源，因此缓存响应以提高性能是有用的。

+   **统一接口**：来自不同客户端的请求看起来是相同的。客户端可以是浏览器、Java 应用程序和移动应用程序等。

+   **分层系统**：REST 允许我们使用分层系统架构。

+   **按需编码**：这是一个可选的约束。

统一接口是一个重要的约束，它定义了每个 REST 架构应该具有以下元素：

+   **资源的识别**：有资源及其唯一标识符，例如基于 Web 的 REST 服务中的 URI。REST 资源应该公开易于理解的目录结构 URI。因此，良好的资源命名策略非常重要。

+   **通过表示来操作资源**：当向资源发出请求时，服务器会以资源的表示形式做出响应。通常，表示的格式是 JSON 或 XML。

+   **自描述消息**：消息应该包含足够的信息，以便服务器知道如何处理它们。

+   **超媒体和应用状态引擎（HATEOAS）**：响应可以包含到服务的其他区域的链接。

在接下来的主题中，我们将开发一个遵循 REST 架构原则的 RESTful Web 服务。

# 创建 RESTful Web 服务

在 Spring Boot 中，所有的 HTTP 请求都由控制器类处理。为了能够创建一个 RESTful web 服务，首先我们必须创建一个控制器类。我们将为我们的控制器创建自己的 Java 包：

1.  在 Eclipse 项目资源管理器中激活根包并右键单击。从菜单中选择 New | Package。我们将为我们的新包命名为`com.packt.cardatabase.web`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/8af105c5-d9c6-40c6-a1a4-99e4ba6af9d7.png)

1.  接下来，我们将在一个新的 Web 包中创建一个新的控制器类。在 Eclipse 项目资源管理器中激活`com.packt.cardatabase.web`包并右键单击。从菜单中选择 New | Class。我们将为我们的类命名为`CarController`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/06e6c5f3-0ea3-429f-bea1-7a14ef6362e1.png)

1.  现在，您的项目结构应该如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/decf853a-39e9-4624-a18e-f0f8869a8db1.png)

如果您意外地在错误的包中创建类，您可以在 Eclipse 项目资源管理器之间拖放文件。有时，当您进行一些更改时，Eclipse 项目资源管理器视图可能无法正确呈现。刷新项目资源管理器有所帮助（激活项目资源管理器并按*F5*）。

1.  在编辑窗口中打开您的控制器类，并在类定义之前添加`@RestController`注解。请参阅以下源代码。`@RestController`注解标识这个类将成为 RESTful Web 服务的控制器：

```java
      package com.packt.cardatabase.web;

      import org.springframework.web.bind.annotation.RestController;

      @RestController
      public class CarController { 
      }
```

1.  接下来，我们在我们的控制器类中添加一个新的方法。该方法使用`@RequestMapping`注解进行标注，定义了方法映射到的端点。接下来，您可以看到示例源代码。在这个例子中，当用户导航到`/cars`端点时，`getCars()`方法被执行：

```java
      package com.packt.cardatabase.web;

      import org.springframework.web.bind.annotation.RestController;

      @RestController
      public class CarController {
        @RequestMapping("/cars")
        public Iterable<Car> getCars() {

        } 
      }
```

`getCars()`方法返回所有汽车对象，然后由 Jackson 库转换为 JSON 对象。

默认情况下，`@RequestMapping`处理所有 HTTP 方法（`GET`，`PUT`，`POST`等）的请求。您可以使用以下`@RequestMapping("/cars", method=GET)`参数定义接受的方法。现在，这个方法只处理来自`/cars`端点的`GET`请求。

1.  为了能够从数据库中返回汽车，我们必须将我们的`CarRepository`注入到控制器中。然后，我们可以使用存储库提供的`findAll()`方法来获取所有汽车。以下源代码显示了控制器代码：

```java
      package com.packt.cardatabase.web;

      import org.springframework.beans.factory.annotation.Autowired;
      import org.springframework.web.bind.annotation.RequestMapping;
      import org.springframework.web.bind.annotation.RestController;

      import com.packt.cardatabase.domain.Car;
      import com.packt.cardatabase.domain.CarRepository;

      @RestController
      public class CarController {
        @Autowired
        private CarRepository repository;

        @RequestMapping("/cars")
        public Iterable<Car> getCars() {
          return repository.findAll();
        }
      }
```

1.  现在，我们准备运行我们的应用程序并导航到`localhost:8080/cars`。我们可以看到有些问题，应用程序似乎陷入了无限循环。这是由于我们的汽车和所有者表之间的一对多关系导致的。实际上会发生什么——首先，汽车被序列化，它包含一个所有者，然后被序列化，反过来，包含汽车，然后被序列化...依此类推。为了避免这种情况，我们必须在`Owner`类的`cars`字段上添加`@JsonIgnore`注解：

```java
      // Owner.java

      @OneToMany(cascade = CascadeType.ALL, mappedBy="owner")
      @JsonIgnore
      private List<Car> cars;
```

1.  现在，当您运行应用程序并导航到`localhost:8080/cars`时，一切都应该如预期般进行，并且您将以 JSON 格式从数据库中获取所有的汽车，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/305e5dea-ad05-46ca-a230-e663c0f62b14.png)

我们已经完成了我们的第一个 RESTful Web 服务，它返回所有的汽车。Spring Boot 提供了一个更强大的方式来创建 RESTful Web 服务，这将在下一个主题中进行探讨。

# 使用 Spring Data REST

Spring Data REST 是 Spring Data 项目的一部分。它提供了一种简单快捷的方式来使用 Spring 实现 RESTful Web 服务。要开始使用 Spring Data REST，您必须将以下依赖项添加到`pom.xml`文件中：

```java
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-rest</artifactId>
</dependency>
```

默认情况下，Spring Data REST 会查找应用程序中的所有公共存储库，并为您的实体自动创建 RESTful Web 服务。

您可以在`application.properties`文件中定义服务的端点：

```java
spring.data.rest.basePath=/api
```

现在，您可以从`localhost:8080/api`端点访问 RESTful Web 服务。通过调用服务的根端点，它返回可用的资源。Spring Data REST 以**HAL**（**超文本应用语言**）格式返回 JSON 数据。HAL 格式提供了一套约定，用于在 JSON 中表示超链接，使得前端开发人员更容易使用您的 RESTful Web 服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/85f89d74-3ada-4901-a9ca-4f71b1c75236.png)

我们可以看到有指向汽车和所有者实体服务的链接。Spring Data Rest 服务的路径名是从实体名称派生的。然后将名称变为复数形式并取消大写。例如，实体 Car 服务的路径名将被命名为`cars`。配置文件链接由 Spring Data Rest 生成，其中包含特定于应用程序的元数据。

现在，我们开始更仔细地检查不同的服务。有多种工具可用于测试和使用 RESTful Web 服务。在本书中，我们使用 Postman，但您也可以使用您熟悉的工具，如 cURL。Postman 可以作为桌面应用程序或作为浏览器插件获取。cURL 也可通过使用 Windows Ubuntu Bash 在 Windows 10 上使用。

如果您使用`GET`方法向`http://localhost:8080/api/cars`端点发出请求，您将获得所有`cars`的列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/3bda9f9b-22a3-45e9-9a81-4404dc9617c1.png)

在 JSON 响应中，您可以看到有一个`cars`数组，每辆汽车都包含特定的汽车数据。所有汽车还具有`"_links"`属性，这是一组链接，通过这些链接，您可以访问汽车本身或获取汽车的所有者。要访问特定的汽车，路径将是`http://localhost:8080/api/cars/{id}`。

对`http://localhost:8080/api/cars/3/owner`的请求返回汽车的所有者。响应现在包含所有者数据，指向所有者的链接以及用户拥有的其他`cars`的链接：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/31f3bd7b-74e7-4630-ae0f-1236c809c3f7.png)

Spring Data Rest 服务提供所有 CRUD 操作。以下表格显示了您可以用于不同 CRUD 操作的 HTTP 方法：

| **HTTP 方法** | **CRUD** |
| --- | --- |
| `GET` | `读取` |
| `POST` | `创建` |
| `PUT`/`PATCH` | `更新` |
| `DELETE` | `删除` |

接下来，我们将看看如何通过使用我们的 RESTful web 服务从数据库中删除汽车。在删除操作中，您必须使用`DELETE`方法和将被删除的汽车的链接（`http://localhost:8080/api/cars/{id}`）。以下屏幕截图显示了如何使用 cURL 删除 ID 为`4`的汽车。删除请求后，您可以看到数据库中现在只剩下两辆汽车：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/407f8dec-9bcd-4873-94c7-d8511f5f6df1.png)

当我们想要向数据库中添加新的汽车时，我们必须使用`POST`方法，链接是`http://localhost:8080/api/cars`。标头必须包含带有值`Content-Type:application/json`的 Content-Type 字段，并且新的汽车对象将嵌入在请求体中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/4e18bf0b-cb25-4518-a14f-e75a5f33bd58.png)

响应将发送一个新创建的汽车对象。现在，如果您再次对`http://localhost:8080/api/cars`路径发出`GET`请求，您可以看到新的汽车存在于数据库中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/5145856e-3e35-4b27-9db3-68430cddd478.png)

要更新实体，我们必须使用`PATCH`方法和我们要更新的汽车的链接（`http://localhost:8080/api/cars/{id}`）。标头必须包含带有值`Content-Type:application/json`的 Content-Type 字段，并且带有编辑数据的汽车对象将放在请求体中。如果您使用`PATCH`，您必须仅发送更新的字段。如果您使用`PUT`，您必须包含所有字段以请求。让我们编辑我们在上一个示例中创建的汽车。我们将颜色更改为白色，并填写我们留空的注册号码。

我们还将使用 owner 字段将所有者链接到汽车。owner 字段的内容是指向所有者的链接（`http://localhost:8080/api/owners/{id}`）。以下屏幕截图显示了`PATCH`请求内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/08f4c1d3-94ce-423b-9fee-680672fc9265.png)

您可以看到，通过使用`GET`请求获取所有汽车后，汽车已更新：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ac790642-d5a0-4cda-b59e-1dac6a3d63aa.png)

在上一章中，我们创建了对我们的存储库的查询。这些查询也可以包含在我们的服务中。要包含查询，您必须将`@RepositoryRestResource`注释添加到存储库类中。查询参数使用`@Param`注释进行注释。以下源代码显示了我们带有这些注释的`CarRepository`：

```java
package com.packt.cardatabase.domain;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource
public interface CarRepository extends CrudRepository <Car, Long> {
  // Fetch cars by brand
  List<Car> findByBrand(@Param("brand") String brand);

  // Fetch cars by color
  List<Car> findByColor(@Param("color") String color);
}
```

现在，当你向`http://localhost:8080/api/cars`路径发出`GET`请求时，你会看到一个名为`/search`的新端点。调用`http://localhost:8080/api/cars/search`路径会返回以下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d0858edd-43c9-4651-9cf3-cf8cbad926c2.png)

从响应中，你可以看到我们的服务现在都有这两个查询。以下 URL 演示了如何按品牌获取汽车：

```java
http://localhost:8080/api/cars/search/findByBrand?brand=Ford
```

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/e13154d6-9ac3-4f7d-bd97-1b99d6954498.png)

# 总结

在本章中，我们使用 Spring Boot 创建了一个 RESTful web 服务。首先，我们创建了一个控制器和一个以 JSON 格式返回所有汽车的方法。接下来，我们使用 Spring Data REST 获得了一个具有所有 CRUD 功能的完全功能的 web 服务。我们涵盖了使用 CRUD 功能所需的不同类型的请求。最后，我们还将我们的查询包含在服务中。在下一章中，我们将使用 Spring Security 保护我们的后端。

# 问题

1.  REST 是什么？

1.  你如何使用 Spring Boot 创建一个 RESTful web 服务？

1.  你如何使用我们的 RESTful web 服务获取项目？

1.  你如何使用我们的 RESTful web 服务删除项目？

1.  你如何使用我们的 RESTful web 服务添加项目？

1.  你如何使用我们的 RESTful web 服务更新项目？

1.  你如何使用我们的 RESTful web 服务进行查询？

# 进一步阅读

Pack 还有其他关于学习 Spring Boot RESTful Web 服务的资源：

+   [`www.packtpub.com/application-development/learning-spring-boot-20-second-edition`](https://www.packtpub.com/application-development/learning-spring-boot-20-second-edition)

+   [`www.packtpub.com/web-development/spring-boot-getting-started-integrated-course`](https://www.packtpub.com/web-development/spring-boot-getting-started-integrated-course)

+   [`www.packtpub.com/web-development/building-restful-web-service-spring`](https://www.packtpub.com/web-development/building-restful-web-service-spring)


# 第四章：保护和测试您的后端

本章将解释如何保护和测试您的 Spring Boot 后端。我们将使用上一章中创建的数据库应用程序作为起点。

在本章中，我们将研究以下内容：

+   如何使用 Spring Boot 保护您的 Spring Boot 后端

+   如何使用 JWT 保护您的 Spring Boot 后端

+   如何测试您的后端

# 技术要求

需要在之前章节创建的 Spring Boot 应用程序。

# Spring Security

Spring Security ([`spring.io/projects/spring-security`](https://spring.io/projects/spring-security))为基于 Java 的 Web 应用程序提供安全服务。Spring Security 项目始于 2003 年，之前被称为 Spring 的 Acegi 安全系统。

默认情况下，Spring Security 启用以下功能：

+   具有内存单个用户的`AuthenticationManager` bean。用户名为`user`，密码打印到控制台输出。

+   忽略常见静态资源位置的路径，例如`/css`、`/images`等。

+   所有其他端点的 HTTP 基本安全。

+   发布到 Spring `ApplicationEventPublisher`的安全事件。

+   默认情况下启用常见的低级功能（HSTS、XSS、CSRF 等）。

您可以通过将以下依赖项添加到`pom.xml`文件中，将 Spring Security 包含在应用程序中：

```java
 <dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-security</artifactId>
 </dependency>
```

当您启动应用程序时，您可以从控制台看到 Spring Security 已创建一个内存用户，用户名为`user`。用户的密码可以在控制台输出中看到：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/018a154a-75b2-4e7e-9eab-1a83275a29ed.png)

如果您对 API 端点进行`GET`请求，您将看到它现在是安全的，并且您将收到`401 Unauthorized`错误：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/7e3bb567-1e85-40b8-b687-38e415595f20.png)

要能够成功进行`GET`请求，我们必须使用基本身份验证。以下截图显示了如何在 Postman 中进行操作。现在，通过身份验证，我们可以看到状态为 200 OK，并且响应已发送：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/96f9e18a-e8cc-4ff4-bc61-b48ab790a4bf.png)

要配置 Spring Security 的行为，我们必须添加一个新的配置类，该类扩展了`WebSecurityConfigurerAdapter`。在应用程序的根包中创建一个名为`SecurityConfig`的新类。以下源代码显示了安全配置类的结构。`@Configration`和`@EnableWebSecurity`注解关闭了默认的 Web 安全配置，我们可以在这个类中定义自己的配置。在`configure(HttpSecurity http)`方法中，我们可以定义应用程序中哪些端点是安全的，哪些不是。实际上，我们还不需要这个方法，因为我们可以使用所有端点都受保护的默认设置：

```java
package com.packt.cardatabase;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {

  }

}
```

我们还可以通过在`SecurityConfig`类中添加`userDetailsService()`方法来向我们的应用程序添加内存用户。以下是该方法的源代码，它将创建一个用户名为`user`，密码为`password`的内存用户：

```java
  @Bean
  @Override
  public UserDetailsService userDetailsService() {
      UserDetails user =
           User.withDefaultPasswordEncoder()
              .username("user")
              .password("password")
              .roles("USER")
              .build();

      return new InMemoryUserDetailsManager(user);
  } 
```

在开发阶段使用内存用户是很好的，但是真正的应用程序应该将用户保存在数据库中。要将用户保存到数据库中，您必须创建一个用户实体类和存储库。密码不应以明文格式保存到数据库中。Spring Security 提供了多种哈希算法，例如 BCrypt，您可以使用它们来哈希密码。以下步骤显示了如何实现这一点：

1.  在`domain`包中创建一个名为`User`的新类。激活`domain`包，右键单击鼠标。从菜单中选择 New | Class，并将新类命名为`User`。之后，您的项目结构应如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a149cf61-44de-432d-9180-a74600669ab2.png)

1.  使用`@Entity`注解对`User`类进行注释。添加类字段——ID、用户名、密码和角色。最后，添加构造函数、getter 和 setter。我们将所有字段设置为可为空，并使用`@Column`注解使用户名必须是唯一的。请参阅以下`User.java`字段和构造函数的源代码：

```java
package com.packt.cardatabase.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, updatable = false)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String role;

    public User() {
    }

  public User(String username, String password, String role) {
    super();
    this.username = username;
    this.password = password;
    this.role = role;
  }
```

以下是`User.java`源代码的其余部分，包括 getter 和 setter：

```java
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getRole() {
    return role;
  }

  public void setRole(String role) {
    this.role = role;
  }
}
```

1.  在`domain`包中创建一个名为`UserRepository`的新类。激活`domain`包，右键单击鼠标。从菜单中选择新建|类，并将新类命名为`UserRepository`。

1.  仓库类的源代码与我们在上一章中所做的类似，但有一个查询方法`findByUsername`，我们在接下来的步骤中需要。请参阅以下`UserRepository`源代码：

```java
package com.packt.cardatabase.domain;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Long> { 
    User findByUsername(String username);
}
```

1.  接下来，我们创建一个实现 Spring Security 提供的`UserDetailsService`接口的类。Spring Security 用于用户身份验证和授权。在根包中创建一个名为`service`的新包。激活根包，右键单击鼠标。从菜单中选择新建|包，并将新包命名为`service`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/c4fbe47c-e3df-4bae-8125-ae4e9e40db61.png)

1.  在我们刚刚创建的`service`包中创建一个名为`UserDetailServiceImpl`的新类。现在，您的项目结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/65caec36-f8b2-485c-a505-120a0a443068.png)

1.  我们必须将`UserRepository`类注入到`UserDetailServiceImpl`类中，因为在 Spring Security 处理身份验证时需要从数据库中获取用户。`loadByUsername`方法返回所需的`UserDetails`对象进行身份验证。以下是`UserDetailServiceImpl.java`的源代码：

```java
package com.packt.cardatabase.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.packt.cardatabase.domain.User;
import com.packt.cardatabase.domain.UserRepository;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
  @Autowired
  private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    { 
      User currentUser = repository.findByUsername(username);
        UserDetails user = new org.springframework.security.core
            .userdetails.User(username, currentUser.getPassword()
            , true, true, true, true, 
            AuthorityUtils.createAuthorityList(currentUser.getRole()));
        return user;
    }

}
```

1.  在我们的安全配置类中，我们必须定义 Spring Security 应该使用数据库中的用户而不是内存中的用户。从`SecurityConfig`类中删除`userDetailsService()`方法以禁用内存中的用户。添加一个新的`configureGlobal`方法以启用来自数据库的用户。我们不应该将密码明文保存到数据库中。因此，我们将在`configureGlobal`方法中定义密码哈希算法。在本例中，我们使用 BCrypt 算法。这可以很容易地通过 Spring Security 的`BCryptPasswordEncoder`类实现。以下是`SecurityConfig.java`的源代码。现在，密码在保存到数据库之前必须使用 BCrypt 进行哈希处理：

```java
package com.packt.cardatabase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.packt.cardatabase.service.UserDetailServiceImpl;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
  @Autowired
  private UserDetailServiceImpl userDetailsService; 

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService)
    .passwordEncoder(new BCryptPasswordEncoder());
  }
}
```

1.  最后，我们可以在我们的`CommandLineRunner`中将一对测试用户保存到数据库中。打开`CardatabaseApplication.java`文件，并在类的开头添加以下代码，将`UserRepository`注入到主类中：

```java
@Autowired 
private UserRepository urepository;
```

1.  使用哈希密码将用户保存到数据库。您可以使用在互联网上找到的任何 BCrypt 计算器：

```java
  @Bean
  CommandLineRunner runner() {
    return args -> {
      Owner owner1 = new Owner("John" , "Johnson");
      Owner owner2 = new Owner("Mary" , "Robinson");
      orepository.save(owner1);
      orepository.save(owner2);

      repository.save(new Car("Ford", "Mustang", "Red", "ADF-1121", 
        2017, 59000, owner1));
      repository.save(new Car("Nissan", "Leaf", "White", "SSJ-3002", 
        2014, 29000, owner2));
      repository.save(new Car("Toyota", "Prius", "Silver", "KKO-0212", 
        2018, 39000, owner2));

```

```java
 // username: user password: user
 urepository.save(new User("user",
      "$2a$04$1.YhMIgNX/8TkCKGFUONWO1waedKhQ5KrnB30fl0Q01QKqmzLf.Zi",
      "USER"));
 // username: admin password: admin
 urepository.save(new User("admin",
      "$2a$04$KNLUwOWHVQZVpXyMBNc7JOzbLiBjb9Tk9bP7KNcPI12ICuvzXQQKG", 
      "ADMIN"));
 };
  } 
```

运行应用程序后，您会看到数据库中现在有一个`user`表，并且保存了两条用户记录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d2acbb3e-93d2-4b8a-9033-7da7536584c7.png)

现在，如果您尝试在没有身份验证的情况下向`/api`端点发送`GET`请求，您将收到`401 Unauthorized`错误。您应该进行身份验证才能发送成功的请求。与前一个示例的不同之处在于，我们使用数据库中的用户进行身份验证。

您可以在以下截图中看到对`/api`端点的`GET`请求，使用`admin`用户：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/8e5bc254-4f49-4fef-a52e-0c3c8146f97b.png)

# 使用 JWT 保护您的后端

在前一节中，我们介绍了如何在 RESTful Web 服务中使用基本身份验证。当我们要用 React 开发自己的前端时，这是不可用的。我们将在我们的应用程序中使用 JSON Web Tokens（JWT）身份验证。JWT 是在现代 Web 应用程序中实现身份验证的一种紧凑方式。JWT 非常小，因此可以在 URL、POST 参数或标头中发送。它还包含有关用户的所有必需信息。

JSON Web 令牌由三个由点分隔的不同部分组成。第一部分是标头，定义了令牌的类型和哈希算法。第二部分是有效载荷，通常在认证的情况下包含有关用户的信息。第三部分是签名，用于验证令牌在传输过程中未被更改。您可以看到以下 JWT 令牌的示例：

```java
eyJhbGciOiJIUzI1NiJ9.
eyJzdWIiOiJKb2UifD.
ipevRNuRP6HflG8cFKnmUPtypruRC4fc1DWtoLL62SY
```

以下图表显示了 JWT 身份验证过程的主要思想：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a5489d53-929b-4830-af03-89e4814bbf9f.png)

成功认证后，用户发送的请求应始终包含在认证中收到的 JWT 令牌。

我们将使用 Java JWT 库（[`github.com/jwtk/jjwt`](https://github.com/jwtk/jjwt)），这是 Java 和 Android 的 JSON Web 令牌库；因此，我们必须将以下依赖项添加到`pom.xml`文件中。JWT 库用于创建和解析 JWT 令牌：

```java
<dependency>
  <groupId>io.jsonwebtoken</groupId>
  <artifactId>jjwt</artifactId>
  <version>0.9.0</version>
</dependency>
```

以下步骤显示了如何在我们的后端启用 JWT 身份验证：

1.  在`service`包中创建一个名为`AuthenticationService`的新类。在类的开头，我们将定义一些常量；`EXPIRATIONTIME`定义了令牌的过期时间（以毫秒为单位）。`SIGNINGKEY`是用于数字签名 JWT 的特定于算法的签名密钥。您应该使用 Base64 编码的字符串。PREFIX 定义了令牌的前缀，通常使用 Bearer 模式。`addToken`方法创建令牌并将其添加到请求的`Authorization`标头中。签名密钥使用 SHA-512 算法进行编码。该方法还使用`Authorization`值向标头添加`Access-Control-Expose-Headers`。这是因为我们默认情况下无法通过 JavaScript 前端访问`Authorization`标头。`getAuthentication`方法使用`jjwt`库提供的`parser()`方法从响应的`Authorization`标头中获取令牌。整个`AuthenticationService`源代码可以在此处看到：

```java
package com.packt.cardatabase.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

import static java.util.Collections.emptyList;

public class AuthenticationService {
  static final long EXPIRATIONTIME = 864_000_00; // 1 day in milliseconds
  static final String SIGNINGKEY = "SecretKey";
  static final String PREFIX = "Bearer";

  // Add token to Authorization header
  static public void addToken(HttpServletResponse res, String username) {
    String JwtToken = Jwts.builder().setSubject(username)
        .setExpiration(new Date(System.currentTimeMillis() 
            + EXPIRATIONTIME))
        .signWith(SignatureAlgorithm.HS512, SIGNINGKEY)
        .compact();
    res.addHeader("Authorization", PREFIX + " " + JwtToken);
  res.addHeader("Access-Control-Expose-Headers", "Authorization");
  }

  // Get token from Authorization header
  static public Authentication getAuthentication(HttpServletRequest request) {
    String token = request.getHeader("Authorization");
    if (token != null) {
      String user = Jwts.parser()
          .setSigningKey(SIGNINGKEY)
          .parseClaimsJws(token.replace(PREFIX, ""))
          .getBody()
          .getSubject();

      if (user != null) 
        return new UsernamePasswordAuthenticationToken(user, null,
            emptyList());
    }
    return null;
  }
}
```

1.  接下来，我们将添加一个新的简单 POJO 类来保存认证凭据。在`domain`包中创建一个名为`AccountCredentials`的新类。该类有两个字段——`username`和`password`。以下是该类的源代码。该类没有`@Entity`注释，因为我们不必将凭据保存到数据库中：

```java
package com.packt.cardatabase.domain;

public class AccountCredentials {
  private String username;
  private String password;

  public String getUsername() {
    return username;
  }
  public void setUsername(String username) {
    this.username = username;
  }
  public String getPassword() {
    return password;
  }
  public void setPassword(String password) {
    this.password = password;
  } 
}
```

1.  我们将使用过滤器类进行登录和身份验证。在根包中创建一个名为`LoginFilter`的新类，处理对`/login`端点的`POST`请求。`LoginFilter`类扩展了 Spring Security 的`AbstractAuthenticationProcessingFilter`，需要设置`authenticationManager`属性。认证由`attemptAuthentication`方法执行。如果认证成功，则执行`succesfulAuthentication`方法。然后，此方法将调用我们的服务类中的`addToken`方法，并将令牌添加到`Authorization`标头中：

```java
package com.packt.cardatabase;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.packt.cardatabase.domain.AccountCredentials;
import com.packt.cardatabase.service.AuthenticationService;

public class LoginFilter extends AbstractAuthenticationProcessingFilter {

  public LoginFilter(String url, AuthenticationManager authManager) {
    super(new AntPathRequestMatcher(url));
    setAuthenticationManager(authManager);
  }

  @Override
  public Authentication attemptAuthentication(
  HttpServletRequest req, HttpServletResponse res)
      throws AuthenticationException, IOException, ServletException {
  AccountCredentials creds = new ObjectMapper()
        .readValue(req.getInputStream(), AccountCredentials.class);
  return getAuthenticationManager().authenticate(
        new UsernamePasswordAuthenticationToken(
            creds.getUsername(),
            creds.getPassword(),
            Collections.emptyList()
        )
    );
  }

  @Override
  protected void successfulAuthentication(
      HttpServletRequest req,
      HttpServletResponse res, FilterChain chain,
      Authentication auth) throws IOException, ServletException {
    AuthenticationService.addToken(res, auth.getName());
  }
}
```

1.  在根包中创建一个名为`AuthenticationFilter`的新类。该类扩展了`GenericFilterBean`，这是任何类型过滤器的通用超类。此类将处理除`/login`之外的所有其他端点的身份验证。`AuthenticationFilter`使用我们的服务类中的`addAuthentication`方法从请求的`Authorization`标头中获取令牌：

```java
package com.packt.cardatabase;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.packt.cardatabase.service.AuthenticationService;

public class AuthenticationFilter extends GenericFilterBean {
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    Authentication authentication = AuthenticationService.getAuthentication((HttpServletRequest)request);

    SecurityContextHolder.getContext().
        setAuthentication(authentication);
    filterChain.doFilter(request, response);
  }
}
```

1.  最后，我们必须对我们的`SecurityConfig`类的`configure`方法进行更改。在那里，我们定义了对`/login`端点的`POST`方法请求允许无身份验证，并且对所有其他端点的请求需要身份验证。我们还通过使用`addFilterBefore`方法定义了要在`/login`和其他端点中使用的过滤器：

```java
  //SecurityConfig.java  
  @Override
    protected void configure(HttpSecurity http) throws Exception {
     http.cors().and().authorizeRequests()
      .antMatchers(HttpMethod.POST, "/login").permitAll()
          .anyRequest().authenticated()
          .and()
          // Filter for the api/login requests
          .addFilterBefore(new LoginFilter("/login",
           authenticationManager()),
                  UsernamePasswordAuthenticationFilter.class)
          // Filter for other requests to check JWT in header
          .addFilterBefore(new AuthenticationFilter(),
                  UsernamePasswordAuthenticationFilter.class);
    }
```

1.  我们还将在安全配置类中添加**CORS**（跨源资源共享）过滤器。这对于前端是必需的，因为它会从其他来源发送请求。CORS 过滤器拦截请求，如果识别为跨源，它会向请求添加适当的标头。为此，我们将使用 Spring Security 的`CorsConfigurationSource`接口。在此示例中，我们将允许所有 HTTP 方法和标头。如果需要更精细的定义，您可以在此处定义允许的来源、方法和标头列表。将以下源代码添加到您的`SecurityConfig`类中以启用 CORS 过滤器：

```java
  // SecurityConfig.java  
  @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = 
            new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("*"));
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setAllowCredentials(true);
        config.applyPermitDefaultValues();

        source.registerCorsConfiguration("/**", config);
        return source;
  } 

```

现在，在运行应用程序之后，我们可以使用`POST`方法调用`/login`端点，在成功登录的情况下，我们将在`Authorization`标头中收到 JWT 令牌：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a6b3b37a-a2ca-40b9-aa7c-20c512c6dc47.png)

成功登录后，我们可以通过在`Authorization`标头中发送从登录接收到的 JWT 令牌来调用其他 RESTful 服务端点。请参见以下屏幕截图中的示例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d2b23561-369a-4d47-9d19-35ad998e3073.png)

现在，我们已经实现了后端所需的所有功能。接下来，我们将继续进行后端单元测试。

# Spring Boot 中的测试

当我们创建项目时，Spring Initializr 会自动将 Spring Boot 测试启动器包添加到`pom.xml`中。这是在 Spring Initializr 页面中没有任何选择的情况下自动添加的：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
```

Spring Boot 测试启动器为测试提供了许多方便的库，如 JUnit、Mockito、AssertJ 等。如果您查看，您的项目结构已经为测试类创建了自己的包：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/39d91eed-cc54-42bb-8a37-3db63c79f0bf.png)

默认情况下，Spring Boot 在测试中使用内存数据库。我们现在使用 MariaDB，但也可以通过将以下依赖项添加到`pom.xml`文件中来使用 H2 进行测试。范围定义了 H2 数据库仅用于运行测试；否则，应用程序将使用 MariaDB 数据库：

```java
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>test</scope>
    </dependency> 
```

如果您还想在测试中使用默认数据库，可以使用`@AutoConfigureTestDatabase`注解。

# 创建单元测试

对于单元测试，我们使用的是 JUnit，这是一个流行的基于 Java 的单元测试库。以下源代码显示了 Spring Boot 测试类的示例框架。`@SpringBootTest`注解指定该类是一个常规测试类，运行基于 Spring Boot 的测试。方法前的`@Test`注解定义了该方法可以作为测试用例运行。`@RunWith(SpringRunner.class)`注解提供了 Spring `ApplicationContext`并将 bean 注入到测试实例中：

```java
@RunWith(SpringRunner.class)
@SpringBootTest
public class MyTestsClass {

  @Test
  public void testMethod() {
    ...
  }

}
```

首先，我们将创建我们的第一个测试用例，该测试用例将在创建任何正式测试用例之前测试应用程序的主要功能。打开已为您的应用程序创建的`CardatabaseApplicationTest`测试类。有一个名为`contextLoads`的测试方法，我们将在其中添加测试。以下测试检查控制器的实例是否已成功创建和注入：

```java
package com.packt.cardatabase;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.packt.cardatabase.web.CarController;

@RunWith(SpringRunner.class)
@SpringBootTest
public class CardatabaseApplicationTests {
  @Autowired
  private CarController controller;

  @Test
  public void contextLoads() {
    assertThat(controller).isNotNull();
  }

}
```

要在 Eclipse 中运行测试，请在项目资源管理器中激活测试类，然后右键单击鼠标。从菜单中选择 Run As | JUnit test。现在应该在 Eclipse 工作台的下部看到 JUnit 选项卡。测试结果显示在此选项卡中，测试用例已通过：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/22eec50f-35aa-4b81-ad41-ade87dd66484.png)

接下来，我们将为我们的汽车存储库创建单元测试，以测试 CRUD 操作。在根测试包中创建一个名为`CarRepositoryTest`的新类。如果测试仅关注 JPA 组件，则可以使用`@DataJpaTest`注解，而不是`@SpringBootTest`注解。使用此注解时，H2 数据库、Hibernate 和 Spring Data 会自动配置进行测试。SQL 日志记录也将被打开。测试默认是事务性的，并在测试用例结束时回滚。`TestEntityManager`用于处理持久化实体，并设计用于测试。您可以在以下看到 JPA 测试类骨架的源代码：

```java
package com.packt.cardatabase;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.junit4.SpringRunner;

import com.packt.cardatabase.domain.Car;
import com.packt.cardatabase.domain.CarRepository;

@RunWith(SpringRunner.class)
@DataJpaTest
public class CarRepositoryTest {
  @Autowired
  private TestEntityManager entityManager;

  @Autowired
  private CarRepository repository;

   // Test cases..
}
```

我们将添加第一个测试用例来测试向数据库添加新汽车。使用`TestEntityManager`提供的`persistAndFlush`方法创建一个新的`car`对象并保存到数据库中。然后，我们检查如果成功保存，汽车 ID 不能为空。以下源代码显示了测试用例方法。将以下方法代码添加到您的`CarRepositoryTest`类中：

```java
  @Test
  public void saveCar() {
    Car car = new Car("Tesla", "Model X", "White", "ABC-1234",
        2017, 86000);
    entityManager.persistAndFlush(car);

    assertThat(car.getId()).isNotNull();
  }
```

第二个测试用例将测试从数据库中删除汽车。创建一个新的`car`对象并保存到数据库中。然后，从数据库中删除所有汽车，最后，`findAll()`查询方法应返回一个空列表。以下源代码显示了测试用例方法。将以下方法代码添加到您的`CarRepositoryTest`类中：

```java
  @Test
  public void deleteCars() {
    entityManager.persistAndFlush(new Car("Tesla", "Model X", "White",
        "ABC-1234", 2017, 86000));
    entityManager.persistAndFlush(new Car("Mini", "Cooper", "Yellow",
        "BWS-3007", 2015, 24500));

    repository.deleteAll();
    assertThat(repository.findAll()).isEmpty();
  } 
```

运行测试用例并在 Eclipse JUnit 选项卡上检查测试是否通过：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/7f5825b7-bea8-459e-9302-7e19c896e6fe.png)

接下来，我们将展示如何测试 RESTful Web 服务 JWT 身份验证功能。对于测试控制器或任何公开的端点，我们可以使用`MockMvc`。通过使用`MockMvc`，服务器不会启动，但测试是在 Spring 处理 HTTP 请求的层中执行的，因此它模拟了真实情况。`MockMvc`提供了`perform`方法来发送请求。要测试身份验证，我们必须向请求体添加凭据。我们执行两个请求；第一个具有正确的凭据，我们检查状态是否正常。第二个请求包含不正确的凭据，我们检查是否收到 4XX 的 HTTP 错误：

```java
package com.packt.cardatabase;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class CarRestTest {
  @Autowired
    private MockMvc mockMvc;

  @Test
  public void testAuthentication() throws Exception {
    // Testing authentication with correct credentials
        this.mockMvc.perform(post("/login")
          .content("{\"username\":\"admin\", \"password\":\"admin\"}")).
          andDo(print()).andExpect(status().isOk());

    // Testing authentication with wrong credentials
        this.mockMvc.perform(post("/login")
          .content("{\"username\":\"admin\", \"password\":\"wrongpwd\"}")).
          andDo(print()).andExpect(status().is4xxClientError());

  }

}
```

现在，当我们运行身份验证测试时，我们可以看到测试通过了：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d6976c26-8eda-4b6c-a6a6-7aaf5ff0508e.png)

现在，我们已经介绍了 Spring Boot 应用程序中测试的基础知识，您应该具备实现更多测试用例的所需知识。

# 摘要

在本章中，我们专注于保护和测试 Spring Boot 后端。首先使用 Spring Security 进行保护。前端将在接下来的章节中使用 React 进行开发；因此，我们实现了 JWT 身份验证，这是一种适合我们需求的轻量级身份验证方法。我们还介绍了测试 Spring Boot 应用程序的基础知识。我们使用 JUnit 进行单元测试，并为 JPA 和 RESTful Web 服务身份验证实现了测试用例。在下一章中，我们将为前端开发设置环境和工具。

# 问题

1.  什么是 Spring Security？

1.  如何使用 Spring Boot 保护后端？

1.  什么是 JWT？

1.  如何使用 JWT 保护后端？

1.  如何使用 Spring Boot 创建单元测试？

1.  如何运行和检查单元测试的结果？

# 进一步阅读

Packt 还有其他很好的资源，可以了解 Spring Security 和测试的知识：

+   [`www.packtpub.com/application-development/spring-security-third-edition`](https://www.packtpub.com/application-development/spring-security-third-edition)

+   [`www.packtpub.com/web-development/mastering-software-testing-junit-5`](https://www.packtpub.com/web-development/mastering-software-testing-junit-5)
