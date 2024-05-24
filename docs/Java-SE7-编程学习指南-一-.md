# Java SE7 编程学习指南（一）

> 原文：[`zh.annas-archive.org/md5/F72094373E33408AE85D942CB0C47C3B`](https://zh.annas-archive.org/md5/F72094373E33408AE85D942CB0C47C3B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

无论你是在追求 Java 认证还是想要丰富你的知识并在使用 Java 时获得更多的信心，你都会发现这本书很有用。这本书采用了一种不同的方法来为你准备认证。它旨在为你提供考试中的主题内容，并为你提供对 Java 的使用和 Java 应用程序开发的额外见解。通过提供更广泛的覆盖范围，它超越了直接的认证焦点，并提供了更全面的语言覆盖。

对于那些追求 Java 认证的人，本书围绕 Java 的主要方面进行组织，并涵盖了 Java SE 7 程序员 I（1Z0-803）考试涵盖的认证主题。每一章都涉及特定的认证主题，尽管有些主题在多个章节中涵盖。每章末尾都有认证问题，这将让你了解你可能在考试中遇到的问题的性质。本书的目的不是提供一套详尽的问题，而是解决那些重要的 Java 概念，以便你准备回答认证问题。

对于那些想要提高他们的 Java 知识的人，这本书提供了对 Java 的深入了解，可能是你以前没有见过的。特别是，图表将有望增强和巩固你对 Java 工作原理的理解，特别是那些描述程序堆栈和堆使用的图表。书中提供了许多示例，涵盖了开发 Java 应用程序中常见的许多陷阱。

无论你阅读这本书的原因是什么，我希望你会觉得这本书是有益的和令人满足的。

# 本书内容

第一章《开始学习 Java》使用一个简单的 Java 应用程序概述了 Java 的主要方面。演示了创建`customer`类，以及使用 getter 和 setter 方法。还讨论了开发过程、支持的 Java 应用程序类型、Java 中的文档过程以及注解的使用，这些注解大大增强了 Java 的表现力。

第二章《Java 数据类型及其用法》介绍了 Java 中可用的基本数据类型及其对应的运算符。使用图表解释了程序堆栈和堆如何相互关联以及它们如何影响变量的范围和生命周期。此外，还说明了`String`和`StringBuilder`类的使用，以及类和对象之间的区别。

第三章《决策结构》专注于 Java 中用于做出决策的结构，包括 if 和 switch 语句。由于这些结构依赖于逻辑表达式，因此涵盖了这些类型的表达式。还演示了 Java 7 中可用的基于字符串的 switch 语句。正确使用决策结构是通过理解和避免各种陷阱来实现的，例如未使用块语句和在比较中使用浮点数时可能出现的多种问题。

第四章《使用数组和集合》专注于数组的使用，以及`Arrays`和`ArrayList`类。单维和多维数组都有例子。介绍了`Arrays`类，因为它具有许多重要的方法，用于操作数组，如填充和排序数组。`ArrayList`类很重要，因为它为许多问题提供了比数组更灵活的容器。

第五章，*循环结构*，演示了 Java 中迭代的概念，通过 while 和 for 循环等结构。这些内容与在使用它们时可能出现的常见错误一起讨论。介绍了 for-each 语句和迭代器的使用，以及无限循环、break 和 continue 语句的覆盖。

第六章，*类、构造函数和方法*，涉及对象的创建和使用，并使用堆栈/堆来解释这个过程。讨论了重载构造函数和方法，以及签名、实例/静态类成员和不可变对象的概念。数据封装贯穿整个章节。

第七章，*继承和多态*，涵盖了继承和多态的关键主题，并增强了对构造函数和方法的讨论。当使用覆盖时，签名的使用再次变得重要。解释了`super`关键字在构造函数和方法中的作用。重新审视了作用域，并探讨了 final 和 abstract 类的概念。还介绍了始终存在的`Object`类。

第八章，*应用程序中的异常处理*，涵盖了异常处理，包括使用新的 try-with-resource 块和`|`操作符在 catch 块中的使用。提供了几条指南和处理异常的示例，以帮助读者避免在使用中常见的错误。

第九章，*Java 应用程序*，研究了 Java 应用程序中包的使用。这包括讨论包和导入语句的使用，包括静态导入语句。还讨论了使用资源包支持需要面向国际社区的应用程序以及如何使用 JDBC 连接和使用数据库。

# 您需要为本书做好准备

要使用本书中的示例，您需要访问 Java 7 SE。可以从[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。读者可能更喜欢使用支持 Java 7 的**集成开发环境**（**IDE**），如 NetBeans、Eclipse 或类似的环境。

# 这本书是为谁准备的

本书适用于那些准备参加 Java SE 7 程序员 I（1Z0-803）考试和/或希望扩展其对 Java 的知识的人。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词如下所示：“例如，一个`person`对象和一个`square`对象都可以有一个`draw`方法。”

代码块设置如下：

```java
public class Application {
   public static void main(String[] args) {
      // Body of method
   }
}
```

任何命令行输入或输出都是这样写的：

```java
set path= C:\Program Files\Java\jdk1.7.0_02\bin;%path%

```

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧如下所示。

# 读者反馈

我们的读者的反馈总是受欢迎的。请告诉我们您对本书的看法——您喜欢或可能不喜欢的地方。读者的反馈对我们开发真正能让您受益的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提到书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)账户中购买的所有 Packt 图书中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)注册，直接将文件发送到您的邮箱。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激地向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/support`](http://www.packtpub.com/support)报告，选择您的书，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站上，或者添加到该标题的现有勘误列表中的勘误部分。您可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看任何现有的勘误。

## 盗版

互联网上盗版版权材料是所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过链接到涉嫌盗版材料的邮箱`<copyright@packtpub.com>`与我们联系。

我们感谢您在保护我们的作者和为您带来有价值的内容方面的帮助。

## 问题

如果您在书的任何方面遇到问题，请通过`<questions@packtpub.com>`与我们联系，我们将尽力解决。 


# 第一章：Java 入门

本章介绍了 Java 的基本元素以及如何编写简单的 Java 程序。通过简单的解释应用程序开发过程，可以全面了解 Java 开发环境。提供了一个作为起点和讨论参考的 Java 控制台程序。

在本章中，我们将研究：

+   Java 是什么

+   面向对象的开发过程

+   Java 应用程序的类型

+   创建一个简单的程序

+   类和接口的定义

+   Java 应用程序开发

+   Java 环境

+   Java 文档技术

+   Java 中的注释使用

+   核心 Java 包

# 理解 Java 作为一种技术

Sun Microsystems 在 1990 年代中期开发了该语言的原始规范。Patrick Naughton、Mike Sheridan 和 James Gosling 是 Java 的原始发明者，该语言最初被称为 Oak。

Java 是一种完整的面向对象的编程语言。它是平台无关的，通常是解释性的，而不是像 C/C++那样编译性的。它在语法和结构上模仿了 C/C++，并执行各种编译时和运行时的检查操作。Java 执行自动内存管理，有助于大大减少其他语言和动态分配内存的库中发现的内存泄漏问题。

Java 支持许多功能，在其概念产生时，其他语言中并没有直接找到。这些功能包括线程、网络、安全和图形用户界面（GUI）开发。其他语言可以用来支持这些功能，但它们没有像 Java 那样集成在语言中。

Java 使用独立的字节码，这是与体系结构无关的。也就是说，它被设计为与机器无关。字节码由 Java 虚拟机（JVM）解释和执行。正如我们将在第三章 *决策结构*中看到的那样，它的所有原始数据类型都是完全指定的。Java 开发工具包（JDK）的各个版本和其他重要时刻如下时间线图所示：

![理解 Java 作为一种技术](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_01_01.jpg)

## 面向对象的软件开发

让我们暂时离题一下，考虑为什么我们要使用 Java。Java 最重要的一个方面是它是一种面向对象（OO）语言。OO 技术是一种流行的开发应用程序的范式。这种方法围绕一系列真实世界的对象建模应用程序，比如员工或船只。为了解决问题，有必要考虑构成问题域的真实世界对象。

OO 方法基于三个不同的活动：

+   面向对象分析（OOA）：这涉及确定系统的功能，即应用程序应该做什么

+   面向对象设计（OOD）：这涉及架构如何支持应用程序的功能

+   面向对象编程（OOP）：这涉及应用程序的实际实现

分析和设计步骤的产物通常被称为分析和设计工件。虽然可能会产生几种不同类型的工件，但对 OOP 步骤最感兴趣的是称为类图的工件。下图显示了一个部分类 UML 图，描述了两个类：`Customer`和`CustomerDriver`。在*一个简单的 Java 应用程序*部分，我们将研究这些类的代码。统一建模语言（UML）是一种广泛使用的 OO 技术，用于设计和记录应用程序。类图是该技术的最终产品之一，程序员用它来创建应用程序：

![面向对象软件开发](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_01_02.jpg)

每个方框代表一个类，分为三个部分：

+   方框顶部的第一部分是类的名称

+   第二部分列出了构成类的变量

+   最后一部分列出了类的方法

在变量和方法名称之前的符号指定了这些类成员的可见性。以下是类图中使用的符号：

+   `-`: 私有

+   `+`: 公共

+   `#`: 受保护的（与继承一起使用）

通常，类图由许多类组成，并通过带注释的线条相互连接，显示类之间的关系。

类图旨在清楚地显示系统中包含哪些对象以及它们如何相互作用。一旦类图完成，就可以使用 Java 等面向对象编程语言来实现它。

### 注意

面向对象的方法通常用于中等规模到大规模的项目，其中许多开发人员必须进行沟通和合作，以创建一个应用程序。对于只涉及少数程序员的较小项目，例如大多数编程课程中处理的项目，通常不使用面向对象的方法。

## 面向对象编程原则

虽然关于什么才真正使编程语言成为面向对象的编程语言存在一些分歧，但通常面向对象编程语言必须支持三个基本原则：

+   数据封装

+   继承

+   多态性

**数据封装**关注于从类的用户那里隐藏不相关的信息，并暴露相关的信息。数据封装的主要目的是降低软件开发的复杂性。通过隐藏执行操作所需的细节，使用该操作变得更简单。如何在 Java 中实现数据封装将在本章后面的*访问修饰符*部分中解释。

数据封装也用于保护对象的内部状态。通过隐藏表示对象状态的变量，可以通过方法来控制对对象的修改。方法中的代码验证状态的任何更改。此外，通过隐藏变量，消除了类之间信息的共享。这减少了应用程序中可能出现的耦合量。

继承描述了两个类之间的关系，使一个类重用另一个类的功能。这样可以实现软件的重用，从而提高开发人员的生产力。继承在第七章中有详细介绍，*继承和多态性*。

第三个原则是多态性，其主要关注点是使应用程序更易于维护和扩展。多态行为是指一个或多个相同方法的行为取决于执行该方法的对象。例如，`person`对象和`square`对象都可以有一个`draw`方法。它所绘制的内容取决于执行该方法的对象。多态性在第七章中讨论，*继承和多态性*。

这些原则总结在以下表中：

| 原则 | 是什么 | 为什么使用它 | 如何做到 |
| --- | --- | --- | --- |
| 数据封装 | 从类的用户隐藏信息的技术 | 降低软件开发复杂性的级别 | 使用`public`、`private`和`protected`等访问修饰符 |
| 继承 | 允许派生或子类使用基类或父类的部分的技术 | 促进软件的重用 | 使用`extends`关键字 |
| 多态性 | 支持方法的不同行为，取决于执行该方法的对象 | 使应用程序更易于维护 | Java 语言的固有特性 |

`implements`关键字用于支持多态行为，如第七章*继承和多态*中所解释的。

## 检查 Java 应用程序的类型

有几种类型的 Java 应用程序。这些类型使 Java 得以在许多不同领域蓬勃发展，并促使 Java 成为一种非常流行的编程语言。Java 用于开发以下内容：

+   控制台和窗口应用程序

+   由 Servlet、JSP、JSF 和其他 JEE 标准支持的基于服务器的 Web 应用程序

+   在浏览器中执行的小程序

+   嵌入式应用程序

+   使用 JavaBeans 的组件化构建块

虽然对 Java 应用程序类型的基本理解有助于将 Java 置于上下文中，但也有助于能够识别这些应用程序的基本代码。您可能不完全理解这些应用程序类型的所有细节，但看到简单的代码示例是有用的。

阅读代码对于理解一种语言和特定程序有很大帮助。在整本书中，我们将使用许多示例来说明和解释 Java 的各个方面。以下通过呈现对应用程序类型至关重要的简短代码片段来展示 Java 应用程序的基本类型。

一个简单的控制台应用程序由一个带有`main`方法的单个类组成，如下面的代码片段所示：

```java
public class Application {
   public static void main(String[] args) {
      // Body of method
   }
}
```

我们将更深入地研究这种类型的应用程序。

小程序通常嵌入在 HTML 页面中，并提供了一种实现客户端执行代码的方法。它没有`main`方法，而是使用浏览器用来管理应用程序的一系列回调方法。以下代码提供了小程序的一般外观：

```java
import java.applet.*;
import java.awt.Graphics;

public class SimpleApplet extends Applet {

   @Override
   public void init() {
      // Initialization code
   }

   @Override
   public void paint( Graphics g ) {
      // Display graphics
   }
}
```

`@Override`注解用于确保接下来的方法实际上是被覆盖的。这在本章的*注解*部分中有更详细的讨论。

Servlet 是一个在服务器端运行的应用程序，它呈现给客户端一个 HTML 页面。`doGet`或`doPut`方法响应客户端请求。以下示例中的`out`变量代表 HTML 页面。`println`方法用于编写 HTML 代码，如下面的代码片段所示：

```java
class Application extends HttpServlet {
   public void doGet(HttpServletRequest req,
            HttpServletResponse res)
            throws ServletException, IOException {
      res.setContentType("text/html");

      // then get the writer and write the response data
      PrintWriter out = res.getWriter();
      out.println(
         "<HEAD><TITLE> Simple Servlet</TITLE></HEAD><BODY>");
      out.println("<h1> Hello World! </h1>");
      out.println(
         "<P>This is output is from a Simple Servlet.");
      out.println("</BODY>");
      out.close();
   }
}
```

JavaServer Page（JSP）实际上是一个伪装的 Servlet。它提供了一种更方便的开发网页的方式。以下示例使用一个 JavaBean 在网页上显示“Hello World”。JavaBean 在以下示例中有详细说明：

```java
<html>
<head>
   <title>A Simple JSP Page</title>
</head>
<body>
Hello World!<br/>

<%
   // This is a scriptlet that can contain Java code
%>
<hr>
<jsp:useBean id="namebean" class="packt.NameBean" scope="session" >
<jsp:setProperty name="namebean" property="name" value=" Hello world"" />
</jsp:useBean>
<h1> <jsp:getProperty name="namebean" property="name" /></h1>
</body>
</html>
```

JavaBean 是共享应用程序功能的构建块。它们经常被设计用于多个应用程序，并遵循标准的命名约定。以下是一个简单的 JavaBean，用于保存一个名称（它在前面的 JSP 页面中使用）：

```java
package packt;
public class NameBean {

  private String name= "Default Name"";

  public String getName() {
     return this.name;
  }
  public void setName(String name) {
     this.name = name;
  }
}
```

企业 JavaBean（EJB）是设计用于在 Web 服务器上的客户端/服务器配置中使用的组件。这是一个相当专业化的主题，与认证的副级别无关。

还有其他几种 Java 技术，如 JSF 和 Facelets，它们是 JEE 的一部分。这些是对用于开发网页的旧 Servlet 和 JSP 技术的改进。

在本书中，我们只会使用简单的 Java 控制台应用程序。这种类型的应用程序已经足够解释 Java 的本质。

# 探索 Java 控制台程序的结构

让我们从一个简单的 Java 程序开始，然后使用它来探索 Java 的许多基本方面。首先，Java 应用程序由一个或多个文件组成，这些文件位于文件系统的某个位置。文件的名称和位置都很重要，我们很快就会看到。

### 提示

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)的帐户中购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便直接通过电子邮件接收文件。

## 一个简单的 Java 应用程序

我们的简单程序定义了一个`Customer`类，然后在`CustomerDriver`类中使用它，如下所示：

```java
package com.company.customer;

import java.math.BigDecimal;
import java.util.Locale;

public class Customer {
  private String name;
  private int accountNumber;
  private Locale locale;
  private BigDecimal balance;

  public Customer() {
    this.name = "Default Customer";
    this.accountNumber = 12345;
    this.locale = Locale.ITALY;
    this.balance = new BigDecimal("0");
  }

  public String getName() {
    return name;
  }
  public void setName(String name) throws Exception {
    if(name == null) {
         throw new IllegalArgumentException(
            "Names must not be null");
    } else {
      this.name = name;
    }
  }
  public int getAccountNumber() {
    return accountNumber;
  }

  public void setAccountNumber(int accountNumber) {
    this.accountNumber = accountNumber;
  }

  public BigDecimal getBalance() {
    return balance;
  }

  public void setBalance(float balance) {
    this.balance = new BigDecimal(balance);
  }

   public String toString() {
      java.text.NumberFormat format =
         java.text.NumberFormat.getCurrencyInstance(locale);
      StringBuilder value = new StringBuilder();
      value.append(String.format("Name: %s%n", this.name));
      value.append(String.format("Account Number: %d%n", 
            this.accountNumber));
      value.append(String.format("Balance: %s%n",
            format.format(this.balance)));
      return value.toString();
    }  
}

package com.company.customer;

public class CustomerDriver {

  public static void main(String[] args) {
      // Define a reference and creates a new Customer object
    Customer customer;      
    customer = new Customer();
    customer.setBalance(12506.45f);
    System.out.println(customer.toString());
  }
```

如何编译和执行此应用程序的详细信息在*在没有 IDE 的情况下开发 Java 应用程序*部分提供。执行此应用程序时，您将获得以下输出：

```java
Name: Default Customer
Account number: 12345
Balance: € 12.506,45

```

详细了解应用程序 以下部分详细介绍了示例程序的重要方面。这些将在接下来的章节中更详细地阐述。请注意，此应用程序中有两个类。`CustomerDriver`类包含`main`方法，并首先执行。在`main`方法中创建并使用了`Customer`类的一个实例。

### 包

包语句指定了类的`com.company.customer`包。包提供了一种将相似的类、接口、枚举和异常分组的方法。它们在第九章的*包*部分中更深入地讨论了*Java 应用程序*。

### 导入

`import`语句指示类使用了哪些包和类。这允许编译器确定包的成员是否被正确使用。所有类都需要导入包，但以下类除外：

+   在`java.lang`包中找到

+   位于当前包（在本例中为`com.company.customer`）

+   显式标记，如在`Customer`类的`toString`方法中使用的`java.text.NumberFormat`

### 注意

`import`语句通知编译器应用程序使用了哪些包和类以及如何使用它们。

### Customer 类

类定义的第一个单词是关键字`public`，这是 Java 为面向对象软件开发提供的支持的一部分。在这种情况下，它指定类在包外可见。虽然不是必需的，但大多数类经常使用它，并引出了第二个关键字`class`，它标识了一个 Java 类。

### 实例变量

接下来声明了四个私有实例变量。使用`private`关键字将它们隐藏在类的用户之外。`Locale`类支持可以在国际上透明工作的应用程序。`BigDecimal`是在 Java 中表示货币的最佳方式。

### 方法

通过将这些实例变量设为私有，设计者限制了对变量的访问。然后只能通过公共方法访问它们。私有变量和公共方法的组合是数据封装的一个例子。如果将实例变量改为公共的，其他用户可以直接访问变量。这将提高程序的效率，但可能会阻碍未来的维护工作。更改这些变量并对其进行任何验证检查将更加困难。

一系列的 getter 和 setter 方法用于返回和设置与私有实例变量相关的值。这以受控的方式暴露它们。使用 getter 和 setter 方法是实现封装的标准方法。例如，尝试将空值分配给名称将引发`IllegalArmumentException`异常。这些类型的方法在*方法声明*部分中讨论。

`toString`方法返回表示客户实例的字符串。在这种情况下，返回名称、帐号和余额的本地化版本。`StringBuilder`类的使用在第二章中讨论，*Java 数据类型及其使用*。

### 注意

方法在类中找到，类在包中找到。

### CustomerDriver 类的 main 方法

`CustomerDriver`类被称为驱动程序或控制器类。它的目的是拥有一个将创建和使用其他类的`main`方法。

在 Java 应用程序中，`main`方法是要执行的第一个方法。如果应用程序由多个类组成，通常只有一个类有`main`方法。Java 应用程序通常只需要一个`main`方法。

在`main`方法中，创建一个新的客户，设置余额，然后显示客户。在语句中添加了 C++风格的注释，以记录客户的声明和创建。这是以双斜杠（`//`）开头的行。注释在*注释*部分详细解释。

### 注意

在 Java 控制台应用程序中执行的第一种方法是`main`方法。

# 探索类的结构

编程可以被认为是代码操作数据。在 Java 中，代码围绕以下内容组织：

+   包

+   类

+   方法

包是具有类似功能的类的集合。类由支持类功能的方法组成。这种组织为应用程序提供了结构。类将始终在一个包中，方法将始终在一个类中。

### 注意

如果类定义中没有包语句，则该类将成为默认包的一部分，该默认包包括同一目录中没有包语句的所有类。

## 类、接口和对象

类是面向对象程序的基本构建块。它通常代表现实世界的对象。Java 中的类定义包括成员变量声明和方法声明。它以`class`关键字开始。类的主体用大括号括起来，包含所有实例变量和方法：

```java
  class classname {
    // define class level variables
    // define methods
  }
```

### 注意

一对开放和关闭大括号构成一个块语句。这在 Java 的许多其他部分中使用。

### 类和对象

类是用于创建具有相似特征的多个对象的模式或模板。它定义了类的变量和方法。它声明了类的功能。但是，在使用这些功能之前，必须创建一个对象。对象是类的实例化。也就是说，对象由为类的成员变量分配的内存组成。每个对象都有自己的一组成员变量。

### 提示

创建新对象时发生以下情况：

+   使用 new 关键字创建类的实例

+   为类的新实例物理分配内存

+   执行任何静态初始化程序（如第六章中*Java 初始化顺序*部分所述），*类、构造函数和方法*）

+   调用构造函数进行初始化

+   返回对对象的引用

对象的状态通常对对象的用户隐藏，并反映在其实例变量的值中。对象的行为由它拥有的方法决定。这是数据封装的一个例子。

### 注意

对象是类的实例化。每个类的实例都有自己独特的一组实例变量。

Java 中的对象总是分配在堆上。堆是用于动态分配内存（如对象）的内存区域。在 Java 中，对象在程序中分配，然后由 JVM 释放。这种内存释放称为垃圾回收，由 JVM 自动执行。应用程序对此过程的控制很少。这种技术的主要好处是最大限度地减少内存泄漏。

### 注意

当动态分配内存但从未释放时，就会发生内存泄漏。这在诸如 C 和 C++等语言中是一个常见问题，程序员有责任管理堆。

在 Java 中，如果分配了一个对象但在不再需要该对象时没有释放对该对象的引用，就可能发生内存泄漏。

### 构造函数

构造函数用于初始化对象。每当创建一个对象时，都会执行构造函数。默认构造函数是没有参数的构造函数，对所有类都会自动提供。这个构造函数将把所有实例变量初始化为默认值。

然而，如果开发人员提供了构造函数，编译器就不会再添加默认构造函数。开发人员需要显式添加一个默认构造函数。始终具有一个默认的无参数构造函数是一个良好的实践。

### 接口

接口类似于抽象类。它使用`interface`关键字声明，只包含抽象方法和最终变量。抽象类通常有一个或多个抽象方法。抽象方法是没有实现的方法。它旨在支持多态行为，如第七章中讨论的，*继承和多态*。以下代码定义了一个用于指定类能够被绘制的接口：

```java
  interface Drawable {
    final int unit = 1;
    public void draw();
  }
```

## 方法

所有可执行代码都在初始化程序列表或方法中执行。在这里，我们将研究方法的定义和用法。初始化程序列表在第六章中讨论，*类，构造函数和方法*。方法将始终包含在类中。方法的可见性由其访问修饰符控制，详细信息请参阅*访问修饰符*部分。方法可以是静态的或实例的。在这里，我们将考虑实例方法。正如我们将在第六章中看到的，*类，构造函数和方法*，静态方法通常访问类的对象之间共享的静态变量。

无论方法的类型如何，方法只有一个副本。也就是说，虽然一个类可能有零个、一个或多个方法，但类的每个实例（对象）都使用方法的相同定义。

### 方法声明

一个典型的方法包括：

+   一个可选的修饰符

+   返回类型

+   方法名称

+   括在括号中的参数列表

+   可选的 throws 子句

+   包含方法语句的块语句

以下`setName`方法说明了方法的这些部分：

```java
  public void setName(String name) throws Exception {
    if(name == null) {
      throw new Exception("Names must not be null");
    } else {
      this.name = name;
    }
  }
```

虽然在这个例子中 else 子句在技术上不是必需的，但始终使用 else 子句是一个良好的实践，因为它代表了可能的执行顺序。在这个例子中，如果 if 语句的逻辑表达式求值为 true，那么异常将被抛出，方法的其余部分将被跳过。异常处理在第八章中有详细介绍，*应用程序中的异常处理*。

方法经常操作实例变量以定义对象的新状态。在设计良好的类中，实例变量通常只能由类的方法更改。它们对类是私有的。因此，实现了数据封装。

方法通常是可见的，并允许对象的用户操作该对象。有两种方法对方法进行分类：

+   **Getter 方法**：这些方法返回对象的状态（也称为**访问器方法**）

+   **Setter 方法**：这些方法可以改变对象的状态（也称为**变异方法**）

在`Customer`类中，为所有实例变量提供了 setter 和 getter 方法，除了 locale 变量。我们本可以很容易地为这个变量包括一个 get 和 set 方法，但为了节省空间，我们没有这样做。

### 注意

具有获取方法但没有其他可见的设置方法的变量被称为**只读成员变量**。类的设计者决定限制对变量的直接访问。

具有设置方法但没有其他可见的获取方法的变量被称为**只写成员变量**。虽然您可能会遇到这样的变量，但它们很少见。

### 方法签名

方法的签名由以下组成：

+   方法的名称

+   参数的数量

+   参数的类型

+   参数的顺序

签名是一个重要的概念，用于方法和构造函数的重载/覆盖，如第七章中所讨论的，*继承和多态*。构造函数也将有一个签名。请注意，签名的定义不包括返回类型。

### 主方法

书中使用的示例将是控制台程序应用。这些程序通常从键盘读取并在控制台上显示输出。当操作系统执行控制台应用程序时，首先执行`main`方法。然后可能执行其他方法。

`main`方法可以用于从命令行传递信息。这些信息传递给`main`方法的参数。它由代表程序参数的字符串数组组成。我们将在第四章中看到这一点，*使用数组和集合*。

在 Java 中只有一种`main`方法的形式，如下所示：

```java
    public static void main(String[] args) {
       // Body of method
    }
```

以下表格显示了`main`方法的元素：

| 元素 | 意义 |
| --- | --- |
| `public` | 方法在类外可见。 |
| `static` | 该方法可以在不创建类类型对象的情况下调用。 |
| `void` | 该方法不返回任何内容。 |
| `args` | 代表传递的参数的字符串数组。 |

#### 从应用程序返回一个值

`main`方法返回`void`，这意味着在正常的方法调用序列中无法将值返回给操作系统。但是，有时将返回一个值以指示程序是否成功终止是有用的。当程序用于批处理类型操作时，返回这些信息是有用的。如果在执行序列中一个程序失败，那么序列可能会被改变。可以使用`System.exit`方法从应用程序返回信息。以下方法的使用将终止应用程序并返回零给操作系统：

```java
    System.exit(0);
```

### 注意

`exit`方法：

+   强制终止应用程序的所有线程

+   是极端的，应该避免

+   不提供优雅终止程序的机会

## 访问修饰符

变量和方法可以声明为以下四种类型之一，如下表所示：

| 访问类型 | 关键字 | 意义 |
| --- | --- | --- |
| 公共的 | `public` | 提供给类外用户的访问。 |
| 私有的 | `private` | 限制对类成员的访问。 |
| 受保护的 | `protected` | 提供给继承类或同一包中成员的访问。 |
| 包范围 | 无 | 提供对同一包中成员的访问。 |

大多数情况下，成员变量声明为私有，方法声明为公共。但是，其他访问类型的存在意味着控制成员可见性的其他潜在方法。这些用法将在第七章*继承和多态*中进行检查。

在`Customer`类中，所有类变量都声明为私有，所有方法都声明为公共。在`CustomerDriver`类中，我们看到了`setBalance`和`toString`方法的使用：

```java
    customer.setBalance(12506.45f);
    System.out.println(customer.toString());
```

由于这些方法被声明为 public，它们可以与`Customer`对象一起使用。不可能直接访问 balance 实例变量。以下语句尝试这样做：

```java
    customer.balance = new BigDecimal(12506.45f);
```

编译器将发出类似以下的编译时错误：

**balance 在 com.company.customer.Customer 中具有私有访问权限**

### 注意

访问修饰符用于控制应用程序元素的可见性。

## 文档

程序的文档是软件开发过程中的重要部分。它向其他开发人员解释代码，并提醒开发人员他们为什么这样做。

文档是通过几种技术实现的。在这里，我们将讨论三种常见的技术：

+   **注释**：这是嵌入在应用程序中的文档

+   **命名约定**：遵循标准的 Java 命名约定可以使应用程序更易读

+   **Javadoc**：这是一种用于生成 HTML 文件形式的应用程序文档的工具

### 注释

注释用于记录程序。它们不可执行，编译器会忽略它们。良好的注释可以大大提高程序的可读性和可维护性。注释可以分为三种类型——C 样式、C++样式和 Java 样式，如下表所总结：

| 注释类型 | 描述 |
| --- | --- |
| 例子 |
| --- |
| C 样式 | C 样式注释在注释的开头和结尾使用两个字符序列。这种类型的注释可以跨越多行。开始字符序列是`/*`，而结束序列由`*/`组成。 |

|

```java
  /* A multi-line comment
     …
  */

  /* A single line comment */
```

|

| C++样式 | C++样式注释以两个斜杠开头，注释一直持续到行尾。实质上，从`//`到行尾的所有内容都被视为注释。 |
| --- | --- |

|

```java
  // The entire line is a comment
  int total;	// Comment used to clarify variable
  area = height*width; 	// This computes the area of a rectangle
```

|

| Java 样式 | Java 样式与 C 样式注释的语法相同，只是它以`/**`开头，而不是`/*`。此外，可以在 Java 样式注释中添加特殊标签以进行文档目的。一个名为`javadoc`的程序将读取使用这些类型注释的源文件，并生成一系列 HTML 文件来记录程序。有关更多详细信息，请参阅*使用 Javadocs*部分。 |
| --- | --- |

|

```java
    /**
     * This method computes the area of a rectangle
     *
     * @param height	The height of the rectangle
     * @param width	The width of the rectangle
     * @return		The method returns the area of a rectangle
     *
     */
   public int computeArea(int height, int width)  {
      return height * width;
   }
```

|

### Java 命名约定

Java 使用一系列命名约定来使程序更易读。建议您始终遵循这些命名约定。通过这样做：

+   使您的代码更易读

+   它支持 JavaBeans 的使用

### 注意

有关命名约定的更多细节，请访问[`www.oracle.com/technetwork/java/codeconvtoc-136057.html`](http://www.oracle.com/technetwork/java/codeconvtoc-136057.html)。

Java 命名约定的规则和示例显示在以下表中：

| 元素 | 约定 | 例子 |
| --- | --- | --- |
| 包 | 所有字母都小写。 | `com.company.customer` |
| 类 | 每个单词的第一个字母大写。 | `CustomerDriver` |
| 接口 | 每个单词的第一个字母大写。 | `Drawable` |
| 变量 | 第一个单词不大写，但后续单词大写 | `grandTotal` |
| 方法 | 第一个单词不大写，但后续单词大写。方法应该是动词。 | `computePay` |
| 常量 | 每个字母都大写。 | `LIMIT` |

### 注意

遵循 Java 命名约定对于保持程序可读性和支持 JavaBeans 很重要。

### 使用 Javadocs

Javadoc 工具基于源代码和源代码中嵌入的 Javadoc 标签生成一系列 HTML 文件。该工具也随 JDK 一起分发。虽然以下示例并不试图提供 Javadocs 的完整处理，但它应该能给你一个关于 Javadocs 能为你做什么的好主意：

```java
public class SuperMath {
   /**
    * Compute PI - Returns a value for PI.
    *    Able to compute pi to an infinite number of decimal 
    *    places in a single machine cycle.
    * @return A double number representing PI
   */

   public static double computePI() {
      //
   }
}
```

`javadoc`命令与此类一起使用时，会生成多个 HTML 文件。`index.html`文件的一部分如下截图所示：

![使用 Javadocs](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_01_03.jpg)

### 注意

有关 Javadoc 文件的使用和创建的更多信息可以在[`www.oracle.com/technetwork/java/javase/documentation/index-137868.html`](http://www.oracle.com/technetwork/java/javase/documentation/index-137868.html)找到。

# 调查 Java 应用程序开发过程

Java 源代码被编译为中间字节码。然后在任何安装有**Java 虚拟机**（**JVM**）的平台上运行时解释这些字节码。然而，这个说法有些误导，因为 Java 技术通常会直接将字节码编译为机器码。已经有了许多即时编译器的改进，加快了 Java 应用程序的执行速度，通常会运行得几乎和本地编译的 C 或 C++应用程序一样快，有时甚至更快。

Java 源代码位于以`.java`扩展名结尾的文件中。Java 编译器将源代码编译为字节码表示，并将这些字节码存储在以`.class`扩展名结尾的文件中。

有几种**集成开发环境**（**IDE**）用于支持 Java 应用程序的开发。也可以使用**Java 开发工具包**（**JDK**）中的基本工具从命令行开发 Java 应用程序。

生产 Java 应用程序通常在一个平台上开发，然后部署到另一个平台。目标平台需要安装**Java 运行环境**（**JRE**）才能执行 Java 应用程序。有几种工具可以协助这个部署过程。通常，Java 应用程序会被压缩成一个**Java 存档**（**JAR**）文件，然后部署。JAR 文件只是一个嵌入有清单文档的 ZIP 文件。清单文档通常详细说明了正在创建的 JAR 文件的内容和类型。

## 编译 Java 应用程序

用于开发 Java 应用程序的一般步骤包括：

+   使用编辑器创建应用程序

+   使用 Java 编译器（`javac`）编译它

+   使用 Java 解释器（`java`）执行它

+   根据需要使用 Java 调试器可选择地调试应用程序

这个过程总结在下图中：

![编译 Java 应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_01_04.jpg)

Java 源代码文件被编译为字节码文件。这些字节码文件具有**.class**扩展名。当 Java 包被分发时，源代码文件通常不会存储在与`.class`文件相同的位置。

## SDK 文件结构

**Java 软件开发工具包**（**SDK**）可下载并用于创建和执行许多类型的 Java 应用程序。**Java 企业版**（**JEE**）是一个不同的 SDK，用于开发以 Web 应用程序为特征的企业应用程序。该 SDK 也被称为**Java 2 企业版**（**J2EE**），你可能会看到它被引用为 J2EE。在这里，我们只处理 Java SDK。

虽然 SDK 分发的实际结构会因版本而异，但典型的 SDK 由一系列目录组成，如下所列：

+   `bin`：这包含用于开发 Java 应用程序的工具，包括编译器和 JVM

+   `db`：这是 Apache Derby 关系数据库

+   `demo`：这包含一系列演示应用程序

+   `include`：这包含用于与 C 应用程序交互的头文件

+   `jre`：这是 JDK 使用的 JRE

+   `sample`：这个目录包含 Java 各种特性的示例代码

SDK 可能包括核心类的实际源代码。这通常可以在位于`JAVA_HOME`根目录下的`src.zip`文件中找到。

## IDE 文件结构

每个 IDE 都有一种首选的组织应用程序文件的方式。这些组织方案并不总是固定的，但这里介绍的是常见的文件排列方式。

例如，在 Eclipse IDE 中，一个简单的应用程序由两个项目文件和三个子目录组成。这些文件和目录列举如下：

+   `.classpath`：这是包含与类路径相关信息的 XML 文件

+   `.project`：这是描述项目的 XML 文档

+   `.settings`：这是一个包含`org.eclipse.jdt.core.prefs`文件的目录，该文件指定了编译器的偏好设置。

+   `bin`：这个目录用于包含包文件结构和应用程序的类文件

+   `src`：这个目录用于包含包文件结构和应用程序的源文件

这种组织方案是由开发工具使用的。这些工具通常包括编辑器、编译器、链接器、调试器等。这些语言经常使用 Make 工具来确定需要编译或以其他方式处理的文件。

## 在没有 IDE 的情况下开发 Java 应用程序

在本节中，我们将演示如何在 Windows 平台上使用 Java 7 编译和执行 Java 应用程序。这种方法与其他操作系统的方法非常相似。

在我们编译和执行示例程序之前，我们需要：

+   安装 JDK

+   为应用程序创建适当的文件结构

+   创建用于保存我们的类的文件

JDK 的最新版本可以在[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)找到。下载并安装符合您需求的版本。注意安装位置，因为我们很快将会用到这些信息。

如前所述，Java 类必须位于特定的文件结构中，与其包名称相对应。在文件系统的某个地方创建一个文件结构，其中有一个名为`com`的顶级目录，该目录下有一个名为`company`的目录，然后在`company`目录下有一个名为`customer`的目录。

在`customer`目录中创建两个文件，分别命名为`Customer.java`和`CustomerDriver.java`。使用在*一个简单的 Java 应用程序*部分中找到的相应类。

JDK 工具位于 JDK 目录中。当安装 JDK 时，通常会设置环境变量以允许成功执行 JDK 工具。然而，需要指定这些工具的位置。这可以通过`set`命令来实现。在下面的命令中，我们将`path`环境变量设置为引用`C:\Program Files\Java\jdk1.7.0_02\bin`目录，这是本章撰写时的最新版本：

```java
set path= C:\Program Files\Java\jdk1.7.0_02\bin;%path%

```

这个命令在之前分配的路径前面加上了`bin`目录的路径。`path`环境变量被操作系统用来查找在命令提示符下执行的命令。没有这些信息，操作系统将不知道 JDK 命令的位置。

要使用 JDK 编译程序，导航到`com`目录的上一级目录。由于作为该应用程序一部分的类属于`com.company.customer`包，我们需要： 

+   在`javac`命令中指定路径

+   从`com`目录的上一级目录执行该命令

由于这个应用程序由两个文件组成，我们需要编译它们两个。可以使用以下两个单独的命令来完成：

```java
javac com.company.customer.Customer.java
javac com.company.customer.CustomerDriver.java

```

或者，可以使用单个命令和星号通配符来完成：

```java
javac com.company.customer.*.java

```

编译器的输出是一个名为`CustomerDriver.class`的字节码文件。要执行程序，使用 Java 解释器和你的类文件，如下命令所示。类扩展名不包括在内，如果包含在文件名中会导致错误：

```java
java com.company.customer.CustomerDriver

```

你的程序的输出应该如下：

```java
Name: Default Customer
Account number: 12345
Balance: € 12.506,45

```

## Java 环境

Java 环境是用于开发和执行 Java 应用程序的操作系统和文件结构。之前，我们已经检查了 JDK 的结构，这些都是 Java 环境的一部分。与这个环境相关的是一系列的环境变量，它们被用来在不同时间进行各种操作。在这里，我们将更详细地检查其中的一些：

+   `CLASSPATH`

+   `PATH`

+   `JAVA_VERSION`

+   `JAVA_HOME`

+   `OS_NAME`

+   `OS_VERSION`

+   `OS_ARCH`

这些变量在下表中总结：

| 名称 | 目的 | 示例 |
| --- | --- | --- |
| `CLASSPATH` | 指定类的根目录。 | `.;C:\Program Files (x86)\Java\jre7\lib\ext\QTJava.zip` |
| `PATH` | 命令的位置。 |   |
| `JAVA_VERSION` | 要使用的 Java 版本。 | `<param name="java_version" value="1.5.0_11">` |
| `JAVA_HOME` | Java 目录的位置。 | `C:\Program Files (x86)\Java\jre6\bin` |
| `OS_NAME` | 操作系统的名称。 | Windows 7 |
| `OS_VERSION` | 操作系统的版本 | 6.1 |
| `OS_ARCH` | 操作系统架构 | AMD64 |

`CLASSPATH`环境变量用于标识包的根目录。设置如下：

```java
 c:>set CLASSPATH=d:\development\increment1;%CLASSPATH%

```

`CLASSPATH`变量只需要设置非标准包。Java 编译器将始终隐式地将系统的类目录附加到`CLASSPATH`。默认的`CLASSPATH`是当前目录和系统的类目录。

与应用程序相关的还有许多其他环境变量。以下代码序列可用于显示这些变量的列表：

```java
    java.util.Properties properties = System.getProperties();
    properties.list(System.out);
```

这段代码序列的部分输出如下：

```java
-- listing properties --
java.runtime.name=Java(TM) SE Runtime Environment
sun.boot.library.path=C:\Program Files\Java\jre7\bin
java.vm.version=22.0-b10
java.vm.vendor=Oracle Corporation
java.vendor.url=http://java.oracle.com/
path.separator=;
java.vm.name=Java HotSpot(TM) 64-Bit Server VM
…

```

## 注解

注解提供关于程序的信息。这些信息不驻留在程序中，也不会影响其执行。注解用于支持诸如编译器和程序执行期间的工具。例如，`@Override`注解通知编译器一个方法正在覆盖基类的方法。如果该方法实际上没有覆盖基类的方法，因为拼写错误，编译器将生成一个错误。

注解应用于应用程序的元素，如类、方法或字段。它以 at 符号`@`开头，后面跟着注解的名称，可选地跟着一组括号括起来的值的列表。

常见的编译器注解在下表中详细说明：

| 注解 | 用法 |
| --- | --- |
| `@Deprecated` | 编译器用来指示不应该使用该元素 |
| `@Override` | 该方法覆盖了基类的方法 |
| `@SuppressWarnings` | 用于抑制特定的编译器警告 |

注解可以添加到应用程序中，并由第三方工具用于特定目的。在需要时也可以编写自己的注解。

### 注意

注解对于向工具和运行时环境传达关于应用程序的信息非常有用

## Java 类库

Java 包括许多支持应用程序开发的类库。其中包括以下内容：

+   `java.lang`

+   `java.io`

+   `java.net`

+   `java.util`

+   `java.awt`

这些库是按包组织的。每个包包含一组类。包的结构反映在其底层文件系统中。`CLASSPATH`环境变量保存了包的位置。

有一组核心的包是 JDK 的一部分。这些包通过提供对一组标准功能的简单访问，为 Java 的成功提供了至关重要的元素，这些功能在其他语言中并不容易获得。

以下表格显示了一些常用包的列表：

| 包 | 用法 |
| --- | --- |
| `java.lang` | 这是基本语言类型的集合。它包括根类`Object`和`Class`，以及线程，异常，包装器和其他基本类等其他项目。 |
| `java.io` | 包括流和随机访问文件。 |
| `java.net` | 支持套接字，telnet 接口和 URL。 |
| `java.util` | 支持容器和实用类，如`Dictionary`，`HashTable`和`Stack`。编码器和解码器技术，如`Date`和`Time`，也可以在此库中找到。 |
| `java.awt` | 包含**抽象窗口工具包**（**AWT**），其中包含支持**图形用户界面**（**GUI**）的类和方法。它包括用于事件，颜色，字体和控件的类。 |

# 摘要

在本章中，我们研究了 Java 的基本方面和一个简单的 Java 控制台应用程序。从认证的角度来看，我们研究了一个使用`main`方法的类和 Java 应用程序的结构。

我们还介绍了一些将在后续章节中更详细讨论的其他主题。这包括对象的创建和操作，字符串和`StringBuilder`类的使用，类的实例和静态成员，以及在方法的重载和重写中使用签名。

有了这个基础，我们准备继续第二章，*Java 数据类型及其用法*，在那里我们将研究变量的性质以及它们的用法。

# 认证目标涵盖

在本章中，我们介绍了一些将在后续章节中更详细讨论的认证主题。在这里，我们深入讨论了以下主题：

+   定义 Java 类的结构（在*探索类的结构*部分）

+   创建一个带有主方法的可执行的 Java 应用程序（在*探索 Java 控制台程序结构*部分）

# 测试你的知识

1.  如果以下代码使用`java SomeClass hello world`命令运行，会打印出什么？

```java
public class SomeClass{
    public static void main(String argv[])
    {
  System.out.println(argv[1]);
    }
}
```

a. `world`

b. `hello`

c. `hello` `world`

d. 抛出`ArrayIndexOutOfBoundsException`

1.  考虑以下代码序列：

```java
public class SomeClass{
   public int i;
   public static void main(String argv[]){
      SomeClass sc = new SomeClass();
      // Comment line
   }
}
```

如果它们替换注释行，以下哪个语句将在不会出现语法或运行时错误的情况下编译？

a. `sc.i = 5;`

b. `int j = sc.i;`

c. `sc.i = 5.0;`

d. `System.out.println(sc.i);`


# 第二章：Java 数据类型及其使用

在本章中，我们将更多地了解 Java 如何组织和操作数据，特别是基本数据类型和字符串。除此之外，我们还将探讨各种相关概念，如作用域和变量的生命周期。虽然字符串在 Java 中不是基本数据类型，但它们是许多应用程序的重要组成部分，我们将探讨 Java 提供了什么。

在本章中，我们将重点关注：

+   基本数据类型的声明和使用

+   使用`String`和`StringBuilder`类

+   程序堆栈和堆如何相互关联

+   类和对象之间的区别

+   Java 中的常量和文字

+   变量的作用域和生命周期

+   运算符、操作数和表达式

# 理解 Java 如何处理数据

编程的核心是操作数据的代码。作为程序员，我们对数据和代码的组织感兴趣。数据的组织被称为**数据结构**。这些结构可以是静态的或动态的。例如，人口的年龄可以存储在数据结构中连续的位置，这种数据结构称为**数组**。虽然数组数据结构具有固定的大小，但内容可能会改变或不改变。数组在第四章中有详细讨论，*使用数组和集合*。

在本节中，我们将研究变量的几个不同方面，包括：

+   它们是如何声明的

+   基本数据类型与对象

+   它们在内存中的位置

+   它们是如何初始化的

+   它们的作用域和生命周期

## Java 标识符、对象和内存

变量被定义为特定类型，并分配内存。当创建对象时，构成对象的实例变量被分配在堆上。对象的静态变量被分配到内存的特殊区域。当变量被声明为方法的一部分时，变量的内存被分配在程序堆栈上。

## 堆栈和堆

对堆栈/堆和其他问题的彻底理解对于理解程序如何工作以及开发人员如何使用 Java 等语言来完成工作至关重要。这些概念为理解应用程序的工作方式提供了一个框架，并且是 Java 使用的运行时系统的实现的基础，更不用说几乎所有其他编程语言的实现了。

话虽如此，堆栈和堆的概念相当简单。**堆栈** 是每次调用方法时存储方法的参数和局部变量的区域。**堆** 是在调用`new`关键字时分配对象的内存区域。方法的参数和局部变量构成一个**激活记录**，也称为**堆栈帧**。激活记录在方法调用时被推送到堆栈上，并在方法返回时从堆栈上弹出。这些变量的临时存在决定了变量的生命周期。

![堆栈和堆](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_02_01.jpg)

当调用方法时，堆栈向堆增长，并在方法返回时收缩。堆不会按可预测的顺序增长，并且可能变得分散。由于它们共享相同的内存空间，如果堆和堆栈发生碰撞，程序将终止。

### 注意

理解堆栈和堆的概念很重要，因为：

+   它提供了一个基础，用于理解应用程序中数据的组织方式

+   它有助于解释变量的作用域和生命周期

+   它有助于解释递归的工作原理

我们将重复使用第一章中演示的程序，*Java 入门*，以演示堆栈和堆的使用。该程序已经在此处复制以方便您使用：

```java
package com.company.customer;
import java.math.BigDecimal;
import java.util.Locale;

public class Customer {
  private String name;
  private int accountNumber;
  private Locale locale;
  private BigDecimal balance;

  public Customer() {
    this.name = "Default Customer";
    this.accountNumber = 12345;
    this.locale = Locale.ITALY;
    this.balance = new BigDecimal("0");
  }

  public String getName() {
    return name;
  }
  public void setName(String name) throws Exception {
    if(name == null) {
      throw new Exception("Names must not be null");
    } else {
      this.name = name;
    }
  }

  public int getAccountNumber() {
    return accountNumber;
  }

  public void setAccountNumber(int accountNumber) {
    this.accountNumber = accountNumber;
  }

  public BigDecimal getBalance() {
    return balance;
  }

  public void setBalance(float balance) {
    this.balance = new BigDecimal(balance);
  }

  public String toString() {
    java.text.NumberFormat format;
    format = java.text.NumberFormat.getCurrencyInstance(locale);
    return format.format(balance);
  }
 }

package com.company.customer;
public class CustomerDriver {
  public static void main(String[] args) {
    Customer customer;      // defines a reference to a Customer
    customer = new Customer();  // Creates a new Customer object
    customer.setBalance(12506.45f);
    System.out.println(customer.toString());
  }
```

当执行`main`方法时，激活记录被推送到程序堆栈上。如下图所示，它的激活记录仅包括单个`args`参数和`customer`引用变量。当创建`Customer`类的实例时，将在堆上创建并分配一个对象。在此示例中反映的堆栈和堆的状态是在`Customer`构造函数执行后发生的。`args`引用变量指向一个数组。数组的每个元素引用表示应用程序命令行参数的字符串。在下图所示的示例中，我们假设有两个命令行参数，参数 1 和参数 2：

![堆栈和堆](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_02_02.jpg)

当执行`setBalance`方法时，它的激活记录被推送到程序堆栈上，如下所示。`setBalance`方法有一个参数`balance`，它被分配给`balance`实例变量。但首先，它被用作`BigDecimal`构造函数的参数。`this`关键字引用当前对象。

堆是为对象动态分配的内存。堆管理器控制这些内存的组织方式。当对象不再需要时，将执行垃圾收集例程以释放内存以便重新使用。在对象被处理之前，将执行对象的`finalize`方法。但是，不能保证该方法将执行，因为程序可能在不需要运行垃圾收集例程的情况下终止。原始的`BigDecimal`对象最终将被销毁。

![堆栈和堆](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_02_03.jpg)

### 注意

在 C++中，当对象即将被销毁时，其析构函数将被执行。Java 最接近的是`finalize`方法，当对象被垃圾收集器处理时将执行。但是，垃圾收集器可能不会运行，因此`finalize`方法可能永远不会执行。这种范式转变导致了我们在资源管理方面的重要差异。第八章中介绍的“try-with-resources”块，*应用程序中的异常处理*，提供了一种处理这种情况的技术。

## 声明变量

变量也称为标识符。术语“变量”意味着它的值可以更改。这通常是这样的。但是，如果标识符被声明为常量，如*常量*部分所讨论的那样，那么它实际上不是一个变量。尽管如此，变量和标识符这两个术语通常被认为是同义词。

变量的声明以数据类型开头，然后是变量名，然后是分号。数据类型可以是原始数据类型或类。当数据类型是类时，变量是对象引用变量。也就是说，它是对对象的引用。

### 注意

引用变量实际上是一个伪装的 C 指针。

变量可以分为以下三类：

+   实例变量

+   静态变量

+   局部变量

实例变量用于反映对象的状态。静态变量是所有实例共有的变量。局部变量在方法内声明，只在声明它们的块中可见。

标识符区分大小写，只能由以下内容组成：

+   字母、数字、下划线（_）和美元符号（$）

+   标识符只能以字母、下划线或美元符号开头

有效的变量名示例包括：

+   `numberWheels`

+   `ownerName`

+   `mileage`

+   `_byline`

+   `numberCylinders`

+   `$newValue`

+   `_engineOn`

按照惯例，标识符和方法以小写字母开头，后续单词大写，如第一章中的*Java 命名约定*部分所讨论的那样。常规声明的示例包括以下内容：

+   `int numberWheels;`

+   `int numberCylinders;`

+   `float mileage;`

+   `boolean engineOn;`

+   `int $newValue;`

+   `String ownerName;`

+   `String _byline;`

在前面的示例中，除了最后两个变量外，每个变量都声明为原始数据类型。最后一个声明为对`String`对象的引用。引用变量可以引用`String`对象，但在这个示例中，它被赋予了一个`null`值，这意味着它当前没有引用字符串。字符串在*String 类*部分中有更详细的介绍。以下代码片段声明了三个整数类型的变量：

```java
int i;
int j;
int k;
```

也可以在一行上声明所有三个变量，如下所示：

```java
int i, j, k;
```

## 原始数据类型

Java 中定义了八种原始数据类型，如下表所示。在 Java 中，每种数据类型的大小对所有机器来说都是相同的：

| 数据类型 | 字节大小 | 内部表示 | 范围 |
| --- | --- | --- | --- |
| `boolean` | -- | 没有精确定义 | `true` 或 `false` |
| `byte` | 1 | 8 位二进制补码 | `-128` 到 `+127` |
| `char` | 2 | Unicode | `\u0000` 到 `\uffff` |
| `short` | 2 | 16 位二进制补码 | `-32768` 到 `32767` |
| `int` | 4 | 32 位二进制补码 | `-2,147,483,648` 到 `2,147,483,647` |
| `long` | 8 | 64 位二进制补码 | `-9,223,372,036,854,775,808` 到 `9,223,372,036,854,775,807` |
| `float` | 4 | 32 位 IEEE 754 浮点数 | `3.4e +/- 38`（7 位数字） |
| `double` | 8 | 64 位 IEEE 754 浮点数 | `1.7e +/- 308`（15 位数字） |

`String`数据类型也是 Java 的一部分。虽然它不是原始数据类型，但它是一个类，并且在*String 类*部分中有详细讨论。

另一种常见的数据类型是货币。在 Java 中，有几种表示货币的方式，如下表所述。然而，推荐的方法是使用`BigDecimal`类。

| 数据类型 | 优点 | 缺点 |
| --- | --- | --- |
| 整数 | 适用于简单的货币单位，如一分钱。 | 它不使用小数点，如美元和美分中使用的那样。 |
| 浮点数 | 使用小数点 | 舍入误差非常常见。 |
| `BigDecimal`类 |

+   处理大数字。

+   使用小数点。

+   具有内置的舍入模式。

| 更难使用。 |
| --- |

在使用`BigDecimal`时，重要的是要注意以下几点：

+   使用带有`String`参数的构造函数，因为它在放置小数点时做得更好

+   `BigDecimal`是不可变的

+   `ROUND_HALF_EVEN`舍入模式引入了最小偏差

`Currency`类用于控制货币的格式。

### 提示

关于货币表示的另一个建议是基于使用的数字位数。

**数字位数** **推荐的数据类型**

小于 10 的整数或`BigDecimal`

小于 19 的长整型或`BigDecimal`

大于 19 `BigDecimal`

在大多数语言中，浮点数可能是问题的重要来源。考虑以下片段，我们在尝试获得值`1.0`时添加`0.1`：

```java
float f = 0.1f;
for(int i = 0; i<9; i++) {
   f += 0.1f;
}
System.out.println(f);
```

输出如下：

```java
1.0000001

```

它反映了十进制值`0.1`无法在二进制中准确表示的事实。这意味着我们在使用浮点数时必须时刻保持警惕。

## 包装类和自动装箱

包装类用于将原始数据类型值封装在对象中。在装箱可用之前，通常需要显式使用包装类，如`Integer`和`Float`类。这是为了能够将原始数据类型添加到`java.util`包中经常出现的集合中，包括`ArrayList`类，因为这些数据类的方法使用对象作为参数。包装类包括以下数据类型：

+   布尔

+   字节

+   字符

+   短

+   整数

+   长

+   浮点

+   双

这些包装类的对象是不可变的。也就是说，它们的值不能被改变。

**自动装箱**是将原始数据类型自动转换为其对应的包装类的过程。这是根据需要执行的，以消除在原始数据类型和其对应的包装类之间执行琐碎的显式转换的需要。**取消装箱**是指将包装对象自动转换为其等效的原始数据类型。实际上，在大多数情况下，原始数据类型被视为对象。

在处理原始值和对象时有一些需要记住的事情。首先，对象可以是`null`，而原始值不能被赋予`null`值。这有时可能会带来问题。例如，取消装箱一个空对象将导致`NullPointerException`。此外，在比较原始值和对象时要小心，当装箱不发生时，如下表所示：

| 比较 | 两个原始值 | 两个对象 | 一个原始值和一个对象 |
| --- | --- | --- | --- |
| `a == b` | 简单比较 | 比较引用值 | 被视为两个原始值 |
| `a.equals(b)` | 不会编译 | 比较值的相等性 | 如果 a 是原始值，否则它们的值将被比较 |

## 初始化标识符

Java 变量的初始化实际上是一个复杂的过程。Java 支持四种初始化变量的方式：

+   默认初始值

+   实例变量初始化程序

+   实例初始化程序

+   构造函数

在本章中，我们将研究前两种方法。后两种技术在第六章中进行了介绍，*类，构造函数和方法*，在那里整个初始化过程被整合在一起。

当未提供显式值时，对象创建时使用初始默认值。一般来说，当对象的字段被分配时，它会被初始化为零值，如下表所述：

| 数据类型 | 默认值（对于字段） |
| --- | --- |
| `boolean` | `false` |
| `byte` | `0` |
| `char` | `'`\`u0000'` |
| `short` | `0` |
| `int` | `0` |
| `long` | `0L` |
| `float` | `0.0f` |
| `double` | `0.0d` |
| `String`（或任何对象） | `null` |

例如，在以下类中，`name`被赋予`null`，`age`的值为`0`：

```java
class Person {
  String name;
  int age;
  …
}
```

实例变量初始化程序的运算符可以用来显式地为变量分配一个值。考虑`Person`类的以下变化：

```java
class Person {
  String name = "John Doe";
  int age = 23;
  …
}
```

当创建`Person`类型的对象时，`name`和`age`字段分别被赋予值`John Doe`和`23`。

然而，当声明一个局部变量时，它不会被初始化。因此，重要的是要在声明变量时使用初始化运算符，或者在为其分配值之前不使用该变量。否则，将导致语法错误。

## Java 常量，字面量和枚举

常量和字面量在不能被更改方面是相似的。变量可以使用`final`关键字声明为不能更改的原始数据类型，因此被称为常量。字面量是表示值的标记，例如`35`或`'C'`。显然，它也不能被修改。与此概念相关的是不可变对象——不能被修改的对象。虽然对象不能被修改，但指向对象的引用变量可以被更改。

枚举在本质上也是常量。它们用于提供一种方便的方式来处理值的集合作为列表。例如，可以创建一个枚举来表示一副牌的花色。

### 字面量

字面常量是表示数量的简单数字、字符和字符串。有三种基本类型：

+   数字

+   字符

+   字符串

#### 数字字面量

数字常量由一系列数字组成，可选的符号和可选的小数点。包含小数点的数字字面量默认为`double`常量。数字常量也可以以`0x`为前缀表示为十六进制数（基数 16）。以`0`开头的数字是八进制数（基数 8）。后缀`f`或`F`可以用来声明浮点字面量的类型为`float`。

| 数字字面量 | 基数 | 数据类型 | 十进制等价 |
| --- | --- | --- | --- |
| `25` | 10 | `int` | `25` |
| `-235` | 10 | `int` | `-235` |
| `073` | 8 | `int` | `59` |
| `0x3F` | 16 | `int` | `63` |
| `23.5` | 10 | `double` | `23.5` |
| `23.5f` | 10 | `float` | `23.5` |
| `23.5F` | 10 | `float` | `23.5` |
| `35.05E13` | 10 | `double` | `350500000000.00` |

整数字面量很常见。通常它们以十进制表示，但可以使用适当的前缀创建八进制和十六进制字面量。整数字面量默认为`int`类型。可以通过在字面量的末尾添加 L 来指定字面量的类型为`long`。下表说明了字面量及其对应的数据类型：

| 字面量 | 类型 |
| --- | --- |
| `45` | `int` |
| `012` | 以八进制数表示的整数。 |
| `0x2FFC` | 以十六进制数表示的整数。 |
| `10L` | `long` |
| `0x10L` | 以十六进制数表示的长整型。 |

### 注意

可以使用小写或大写的 L 来指定整数的长整型类型。但最好使用大写的 L，以避免将字母与数字 1 混淆。在下面的例子中，一个不小心的读者可能会将字面量看作是一百零一，而不是整数 10：

`10l`与`10L`

浮点字面量是包含小数点的数字，或者使用科学计数法写成的数字。

| 字面量 | 类型 |
| --- | --- |
| `3.14` | `double` |
| `10e6` | `double` |
| `0.042F` | `float` |

Java 7 增加了在数字字面量中使用下划线字符（`_`）的能力。这通过在字面量的重要部分之间添加可视间距来增强代码的可读性。下划线可以几乎添加到数字字面量的任何位置。它可以与浮点数和任何整数基数（二进制、八进制、十六进制或十进制）一起使用。此外，还支持基数 2 字面量。

下表说明了在各种数字字面量中使用下划线的情况：

| 示例 | 用法 |
| --- | --- |
| `111_22_3333` | 社会安全号码 |
| `1234_5678_9012_3456` | 信用卡号码 |
| `0b0110_00_1` | 代表一个字节的二进制字面量 |
| `3._14_15F` | 圆周率 |
| `0xE_44C5_BC_5` | 32 位数量的十六进制字面量 |
| `0450_123_12` | 24 位八进制字面量 |

在代码中使用字面量对数字的内部表示或显示方式没有影响。例如，如果我们使用长整型字面量表示社会安全号码，该数字在内部以二进制补码表示，并显示为整数：

```java
long ssn = 111_22_3333L;
System.out.println(ssn);
```

输出如下：

```java
111223333

```

如果需要以社会安全号码的格式显示数字，需要在代码中进行。以下是其中一种方法：

```java
long ssn = 111_22_3333L;
String formattedSsn = Long.toString(ssn);
for (int i = 0; i < formattedSsn.length(); i++) {
    System.out.print(formattedSsn.charAt(i));
    if (i == 2 || i == 4) {
        System.out.print('-');
    }
}
System.out.println();
```

执行时，我们得到以下输出：

```java
111-22-3333

```

下划线的使用是为了使代码对开发人员更易读，但编译器会忽略它。

在使用文字中的下划线时，还有一些其他要考虑的事情。首先，连续的下划线被视为一个，并且也被编译器忽略。此外，下划线不能放置在：

+   在数字的开头或结尾

+   紧邻小数点

+   在`D`、`F`或`L`后缀之前

以下表格说明了下划线的无效用法。这些将生成语法错误：`非法下划线`：

| 例子 | 问题 |
| --- | --- |
| `_123_6776_54321L` | 不能以下划线开头 |
| `0b0011_1100_` | 不能以下划线结尾 |
| `3._14_15F` | 不能紧邻小数点 |
| `987_654_321_L` | 不能紧邻`L`后缀 |

一些应用程序需要操作值的位。以下示例将对一个值使用掩码执行位 AND 操作。掩码是一系列用于隔离另一个值的一部分的位。在这个例子中，`value`代表一个希望隔离最后四位的位序列。二进制文字代表掩码：

```java
value & 0b0000_11111;
```

当与包含零的掩码进行 AND 操作时，AND 操作将返回零。在前面的例子中，表达式的前四位将是零。最后四位与一进行 AND 操作，结果是结果的最后四位与值的最后四位相同。因此，最后四位已被隔离。

通过执行以下代码序列来说明：

```java
byte value = (byte) 0b0111_1010;
byte result = (byte) (value & 0b0000_1111);
System.out.println("result: " + Integer.toBinaryString(result));
```

执行时，我们得到以下输出：

```java
result: 1010

```

以下图表说明了这个 AND 操作：

![数字文字](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_02_04.jpg)

#### 字符文字

字符文字是用单引号括起来的单个字符。

```java
char letter = 'a';
letter = 'F';
```

然而，一个或多个符号可以用来表示一个字符。反斜杠字符用于“转义”或赋予字母特殊含义。例如，`'\n'`代表回车换行字符。这些特殊的转义序列代表特定的特殊值。这些转义序列也可以在字符串文字中使用。转义序列字符列在下表中：

| 转义序列字符 | 含义 |
| --- | --- |
| `\a` | 警报（响铃） |
| `\b` | 退格 |
| `\f` | 换页 |
| `\n` | 换行 |
| `\r` | 回车 |
| `\t` | 水平制表符 |
| `\v` | 垂直制表符 |
| `\\` | 反斜杠 |
| `\?` | 问号 |
| `\'` | 单引号 |
| `\"` | 双引号 |
| `\ooo` | 八进制数 |
| `\xhh` | 十六进制数 |

#### 字符串文字

字符串文字是一系列用双引号括起来的字符。字符串文字不能跨两行分割：

```java
String errorMessage = "Error – bad input file name";
String columnHeader = "\tColumn 1\tColumn2\n";
```

### 常量

常量是其值不能改变的标识符。它们用于情况，其中应该使用更易读的名称而不是使用文字。在 Java 中，常量是通过在变量声明前加上`final`关键字来声明的。

在下面的例子中，声明了三个常量——`PI`、`NUMSHIPS`和`RATEOFRETURN`。根据标准*Java 命名约定*第第一章的*开始使用 Java*部分，每个常量都是大写的，并赋予一个值。这些值不能被改变：

```java
final double PI = 3.14159;
final int NUMSHIPS = 120;
final float RATEOFRETURN = 0.125F;
```

在下面的语句中，试图改变 PI 的值：

```java
PI = 3.14;
```

根据编译器的不同，将生成类似以下的错误消息：

```java
cannot assign a value to final variable PI

```

这意味着您不能改变常量变量的值。

### 注意

常量除了始终具有相同的值之外，还提供其他好处。常量数字或对象可以更有效地处理和优化。这使得使用它们的应用程序更有效和更易于理解。我们可以简单地使用`PI`而不是在需要的每个地方使用 3.14159。

### final 关键字

虽然`final`关键字用于声明常量，但它还有其他用途，如下表所述。我们将在后面的章节中介绍它在方法和类中的用法：

| 应用于 | 意义 |
| --- | --- |
| 原始数据声明 | 分配给变量的值无法更改。 |
| 引用变量 | 无法更改变量以引用不同的变量。但是，可能可以更改变量引用的对象。 |
| 方法 | 该方法无法被覆盖。 |
| 类 | 该类无法被扩展。 |

### 枚举

枚举实际上是`java.lang.Enum`类的子类。在本节中，我们将看一下简单枚举的创建。有关此主题的更完整处理，请参阅第六章中的*类，构造函数和方法*。

以下示例声明了一个名为`Directions`的枚举。此枚举表示四个基本点。

```java
public enum Directions {NORTH, SOUTH, EAST, WEST}
```

我们可以声明此类型的变量，然后为其分配值。以下代码序列说明了这一点：

```java
Directions direction;
direction = Directions.EAST;
System.out.println(direction);
```

此序列的输出如下：

```java
EAST

```

`enum`调用也可以作为 switch 语句的一部分，如下所示：

```java
switch(direction) {
case NORTH:
  System.out.println("Going North");
  break;
case SOUTH:
  System.out.println("Going South");
  break;
case EAST:
  System.out.println("Going East");
  break;
case WEST:
  System.out.println("Going West");
  break;
}
```

在与前面的代码一起执行时，我们得到以下输出：

```java
Going East

```

### 不可变对象

不可变对象是其字段无法修改的对象。在 Java 核心 SDK 中有几个类的对象是不可变的，包括`String`类。也许令人惊讶的是，`final`关键字并未用于此目的。这些将在第六章中详细讨论，*类，构造函数和方法*。

## 实例与静态数据

类中有两种不同类型的变量（数据）：实例和静态。当实例化对象（使用类名的`new`关键字）时，每个对象由组成该类的实例变量组成。但是，为每个类分配了静态变量的唯一副本。虽然每个类都有其自己的实例变量副本，但所有类共享静态变量的单个副本。这些静态变量分配到内存的一个单独区域，并且存在于类的生命周期内。

考虑添加一个可以选择性地应用于某些客户的常见折扣百分比，但不是所有客户。无论是否应用，百分比始终相同。基于这些假设，我们可以将静态变量添加到类中，如下所示：

```java
private static float discountPercentage;
```

静态方法和字段在第六章中有更详细的介绍，*类，构造函数和方法*。

## 范围和生命周期

范围指的是程序中特定变量可以使用的位置。一般来说，变量在其声明的块语句内可见，但在其外部不可见。块语句是由花括号封装的代码序列。

如果变量在范围内，则对代码可见并且可以访问。如果不在范围内，则无法访问变量，并且任何尝试这样做都将导致编译时错误。

变量的生命周期是指其分配了内存的时间段。当变量声明为方法的局部变量时，分配给变量的内存位于激活记录中。只要方法尚未返回，激活记录就存在，并且为变量分配内存。一旦方法返回，激活记录就从堆栈中移除，变量就不再存在，也无法使用。

从堆中分配的对象的生命周期始于分配内存时，终止于释放内存时。在 Java 中，使用`new`关键字为对象分配内存。当对象不再被引用时，对象及其内存被标记为释放。实际上，如果对象没有被回收，它将在未来的某个不确定的时间点被释放，如果有的话。如果一个对象没有引用，即使垃圾收集器尚未回收它，它也可以被使用或访问。

### 作用域规则

作用域规则对于理解诸如 Java 之类的块结构语言的工作方式至关重要。这些规则解释了变量何时可以使用，以及在命名冲突发生时将使用哪一个。

作用域规则围绕着块的概念。块由开放和闭合的大括号界定。这些块用于将代码分组在一起，并定义变量的范围。以下图表显示了三个变量`i`，`j`和`k`的范围：

![作用域规则](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_02_05.jpg)

## 访问修饰符

在声明实例和静态变量和方法时，可以使用访问修饰符作为前缀。修饰符以各种组合应用以提供特定的行为。修饰符的顺序并不总是重要的，但一致的风格会导致更可读的代码。所有修饰符都是可选的，尽管有一些默认修饰符。访问修饰符包括：

+   `public`：公共对象对其自身类内外的所有方法可见。

+   `protected`：这允许在当前类和子类之间进行保护。受保护的对象在类外是不可见的，对子类完全可见。

+   `private`：私有变量只能被定义它的类（包括子类）看到。

+   **包**：这种可见性是默认保护。只有包内的类才有访问权限（包内公共）。

要解释变量的作用域，请考虑以下图表中显示的包/类组织，箭头表示继承：

![访问修饰符](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_02_05a.jpg)

假设 A 类定义如下：

```java
public class A{
   public int  publicInt;
   private int privateInt;
   protected int  protectedInt;
   int defaultInt;  // default (package)
} 
```

所有变量都是`int`类型。`publicInt`变量是公共变量。它可以被这个类内外的所有方法看到。`privateInt`变量只在这个类内可见。`protectedInt`变量只对这个包内的类可见。`protectedInt`变量对这个类、它的子类和同一个包内的其他类可见。在其他地方是不可见的。以下表格显示了每种声明类型对每个类的可见性：

|   | A | B | C | D | E |
| --- | --- | --- | --- | --- | --- |
| `publicInt` | 可见 | 可见 | 可见 | 可见 | 可见 |
| `privateInt` | 可见 | 不可见 | 不可见 | 不可见 | 不可见 |
| `protectedInt` | 可见 | 可见 | 可见 | 不可见 | 可见 |
| `defaultInt` | 可见 | 可见 | 可见 | 不可见 | 不可见 |

## 数据摘要

以下表格总结了变量类型及其与 Java 编译时和运行时元素的关系：

| 程序元素 | 变量类型 | 的一部分 | 分配给 |
| --- | --- | --- | --- |
| 类 | 实例 | 对象 | 堆 |
| 静态 | 类 | 内存的特殊区域 |
| 方法 | 参数 | 激活记录 | 栈的激活记录 |
| 本地 |

# 使用操作数和运算符构建表达式

表达式由操作数和运算符组成。操作数通常是变量名或文字，而运算符作用于操作数。以下是表达式的示例：

```java
int numberWheels = 4;
System.out.println("Hello");
numberWheels = numberWheels + 1;
```

有几种分类运算符的方法：

+   算术

+   赋值

+   关系

+   逻辑补码

+   逻辑

+   条件

+   按位

表达式可以被认为是程序的构建块。它们用于表达程序的逻辑。

### 优先级和结合性

Java 运算符总结如下优先级和结合性表。这些运算符中的大多数都很简单：

| 优先级 | 运算符 | 结合性 | 运算符 |
| --- | --- | --- | --- |
| 1 | `++` | 右 | 前/后增量 |
| `--` | 右 | 前/后减量 |
| `+,-` | 右 | 一元加或减 |
| `~` | 右 | 位补 |
| `!` | 右 | 逻辑补 |
| (cast) | 右 | 强制转换 |
| 2 | `*`, `/`, 和 `%` | 左 | 乘法、除法和取模 |
| 3 | `+` 和 `-` | 左 | 加法和减法 |
| `+` | 左 | 字符串连接 |
| 4 | `<<` | 左 | 左移 |
| `>>` | 左 | 右移和符号填充 |
| `>>>` | 左 | 右移和零填充 |
| 5 | `<`, `<=`, `>`, `>=` | 左 | 逻辑 |
| `Instanceof` | 左 | 类型比较 |
| 6 | `==` 和 `!=` | 左 | 相等和不相等 |
| 7 | `&` | 左 | 位和布尔与 |
| 8 | `^` | 左 | 位和布尔异或 |
| 9 | ` | ` | 左 | 位和布尔或 |
| 10 | `&&` | 左 | 布尔与 |
| 11 | ` | | ` | 左 | 布尔或 |
| 12 | `?:` | 右 | 条件 |
| 13 | `=` | 右 | 赋值 |
| `+=`, `-=`, `*=`, `/=`, 和 `%=` | 右 | 复合 |

虽然大多数这些运算符的使用是直接的，但它们的更详细的用法示例将在后面的章节中提供。但请记住，在 Java 中没有其他变体和其他可用的运算符。例如，`+=`是一个有效的运算符，而`=+`不是。但是，它可能会带来意想不到的后果。考虑以下情况：

```java
total = 0;
total += 2;  // Increments total by 2
total =+ 2;  // Valid but simply assigns a 2 to total!
```

最后一条语句似乎使用了一个=+运算符。实际上，它是赋值运算符后面跟着的一元加运算符。一个`+2`被赋给`total`。请记住，Java 会忽略除了字符串文字之外的空格。

### 强制转换

当一种类型的数据被分配给另一种类型的数据时，可能会丢失信息。如果数据从更精确的数据类型分配到不太精确的数据类型，就可能会发生**缩小**。例如，如果浮点数`45.607`被分配给整数，小数部分`.607`就会丢失。

在进行此类分配时，应使用强制转换运算符。强制转换运算符只是您要转换为的数据类型，括在括号中。以下显示了几个显式转换操作：

```java
int i;
float f = 1.0F;
double d = 2.0;

i = (int) f;  // Cast a float to an int
i = (int) d;  // Cast a double to an int
f = (float) d;  // Cast a double to a float
```

在这种情况下，如果没有使用强制转换运算符，编译器将发出警告。警告是为了建议您更仔细地查看分配情况。精度的丢失可能是一个问题，也可能不是，这取决于应用程序中数据的使用。没有强制转换运算符，当代码执行时会进行隐式转换。

# 处理字符和字符串

主要类包括`String`、`StringBuffer`、`StringBuilder`和`Character`类。还有几个与字符串和字符操作相关的其他类和接口，列举如下，您应该知道。但并非所有这些类都将在此处详细说明。

+   `Character`：这涉及到字符数据的操作

+   `Charset`：这定义了 Unicode 字符和字节序列之间的映射

+   `CharSequence`：在这里，一个接口由`String`、`StringBuffer`和`StringBuilder`类实现，定义了公共方法

+   `StringTokenizer`：这用于对文本进行标记化

+   `StreamTokenizer`：这用于对文本进行标记化

+   `Collator`：这用于支持特定区域设置字符串的操作

### String、StringBuffer 和 StringBuilder 类

对于 Java 程序员，有几个与字符串相关的类可用。在本节中，我们将研究 Java 中用于操作此类数据的类和技术。

在 JDK 中用于字符串操作的三个主要类是`String`、`StringBuffer`和`StringBuilder`。`String`类是这些类中最广泛使用的。`StringBuffer`和`StringBuilder`类是在 Java 5 中引入的，以解决`String`类的效率问题。`String`类是不可变的，需要频繁更改字符串的应用程序将承受创建新的不可变对象的开销。`StringBuffer`和`StringBuilder`类是可变对象，当字符串需要频繁修改时可以更有效地使用。`StringBuffer`与`StringBuilder`的区别在于它的方法是同步的。

在类支持的方法方面，`StringBuffer`和`StringBuilder`的方法是相同的。它们只在方法是否同步上有所不同。

| 类 | 可变 | 同步 |
| --- | --- | --- |
| `String` | 否 | 否 |
| `StringBuffer` | 是 | 是 |
| `StringBuilder` | 是 | 否 |

当处理使用多个线程的应用程序时，同步方法是有用的。**线程**是一个独立执行的代码序列。它将与同一应用程序中的其他线程同时运行。并发线程不会造成问题，除非它们共享数据。当这种情况发生时，数据可能会变得损坏。同步方法的使用解决了这个问题，并防止数据由于线程的交互而变得损坏。

同步方法的使用包括一些开销。因此，如果字符串不被多个线程共享，则不需要`StringBuffer`类引入的开销。当不需要同步时，大多数情况下应该使用`StringBuilder`类。

### 注意

**使用字符串类的标准**

如果字符串不会改变，请使用`String`类：

+   由于它是不可变的，因此可以安全地在多个线程之间共享

+   线程只会读取它们，这通常是一个线程安全的操作。

如果字符串将要改变并且将在线程之间共享，则使用`StringBuffer`类：

+   这个类是专门为这种情况设计的

+   在这种情况下使用这个类将确保字符串被正确更新

+   主要缺点是方法可能执行得更慢

如果字符串要改变但不会在线程之间共享，请使用`StringBuilder`类：

+   它允许修改字符串，但不会产生同步的开销

+   这个类的方法将执行得和`StringBuffer`类一样快，甚至更快

### Unicode 字符

Java 使用 Unicode 标准来定义字符。然而，这个标准已经发展和改变，而 Java 已经适应了它的变化。最初，Unicode 标准将字符定义为一个 2 字节 16 位值，可以使用可打印字符或`U+0000`到`U+FFFF`来表示。无论可打印与否，十六进制数字都可以用来编码 Unicode 字符。

然而，2 字节编码对于所有语言来说都不够。因此，Unicode 标准的第 4 版引入了新的字符，位于`U+FFFF`以上，称为**UTF-16**（**16 位 Unicode 转换格式**）。为了支持新标准，Java 使用了**代理对**的概念——16 位字符对。这些对用于表示从`U+10000`到`U+10FFFF`的值。代理对的前导或高值范围从`U+D800`到`U+DBFF`。对的尾部或低值范围从`U+DC00`到`U+DFFF`。这些范围内的字符称为**补充字符**。这两个特殊范围用于将任何 Unicode 字符映射到代理对。从 JDK 5.0 开始，一个字符使用 UTF-16 表示。

## 字符类

`Character`类是`char`原始数据类型的包装类。该数据类型支持 Unicode 标准版本 4.0。字符被定义为固定宽度的 16 位数量。

### 字符类-方法

字符串类

| 方法 |
| --- |
| `String`类是 Java 中用于表示字符串的常见类。它是不可变的，这使得它是线程安全的。也就是说，多个线程可以访问同一个字符串，而不用担心破坏字符串。不可变还意味着它是固定大小的。 |
| 如果字符是数字，则返回 true |
| 如果字符是字母，则返回 true |
| 如果字符是字母或数字，则返回 true |
| 如果字符是小写字母，则返回 true |
| 如果字符是空格，则返回 true |
| 如果字符是大写字母，则返回 true |
| 返回字符的小写等价物 |
| 描述 |

## 返回字符的大写等价物

`Character`类具有处理字符的多种方法。许多`Character`方法都是重载的，可以接受`char`或 Unicode 代码点参数。代码点是用于字符的抽象，对于我们的目的是 Unicode 字符。以下表列出了您可能会遇到的几种`Character`方法：

`String`类被设计为不可变的一个原因是出于安全考虑。如果一个字符串用于标识受保护的资源，一旦为该资源授予权限，可能会修改字符串然后获取对用户没有权限的另一个资源的访问权限。通过使其不可变，可以避免这种漏洞。

虽然`String`类是不可变的，但它可能看起来是可变的。考虑以下示例：

```java
String s = "Constant";
s = s + " and unchangeable";
System.out.println(s);
```

输出这个序列的结果是字符串"Constant and unchangeable"。由于`s`被定义为`String`类型，因此由`s`标识符引用的对象不能改变。当进行第二个赋值语句时，将创建一个新对象，将`Constant`和`and unchangeable`组合在一起，生成一个新的字符串`Constant and unchangeable`。在这个过程中创建了三个`String`对象：

+   常量

+   不可改变

+   不可改变

标识符`s`现在引用新的字符串`Constant and unchangeable`。

虽然我们可以访问这些对象，但我们无法更改它们。我们可以访问和读取它们，但不能修改它们。

我们本可以使用`String`类的`concat`方法，但这并不那么直接：

```java
s = "Constant";
s = s.concat(" and unchangeable");
System.out.println(s);
```

以下代码演示了创建`String`对象的几种技术。第一个构造函数只会产生一个空字符串。除非应用程序需要在堆上找到一个空的不可变字符串，否则这对于立即价值不大。

```java
String firstString = new String();
String secondString = new String("The second string");
String thirdString = "The third string";
```

此外，还有两个使用`StringBuffer`和`StringBuilder`类的构造函数。从这些对象创建了新的`String`对象，如下代码序列所示：

```java
StringBuffer stringBuffer =new StringBuffer("A StringBuffer string");
StringBuilder stringBuilder =new StringBuilder("A StringBuilder string");
String stringBufferBasedString = new String(stringBuffer);
String stringBuilderBasedString = new String(stringBuilder);
```

### 注意

在内部，`String`类的字符串表示为`char`数组。

### 字符串比较

字符串比较并不像最初看起来那么直接。如果我们想要比较两个整数，我们可能会使用如下语句：

```java
if (count == max) {
  // Do something
}
```

然而，对于两个字符串的比较，比如`s1`和`s2`，以下通常会评估为`false`：

```java
String s1 = "street";
String s2;

s2 = new String("street");

if (s1 == s2) {
  // False
}
```

问题在于变量`s1`和`s2`可能引用内存中的不同对象。if 语句比较字符串引用变量而不是实际的字符串。由于它们引用不同的对象，比较返回`false`。这完全取决于编译器和运行时系统如何在内部处理字符串。

当使用`new`关键字时，内存是从堆中分配并分配给新对象。但是，在字符串文字的情况下，这个内存不是来自堆，而是来自文字池，更具体地说，是字符串内部池。在 Java 中，内部化的字符串被放置在 JVM 的永久代区域中。该区域还存储 Java 类声明和类静态变量等内容。

内部化字符串仅存储每个不同字符串的一个副本。这是为了改善某些字符串方法的执行并减少用于表示相同字符串的空间量。此区域中的字符串会受到垃圾回收的影响。

例如，如果我们创建两个字符串文字和一个使用`new`关键字的`String`对象：

```java
String firstLiteral = "Albacore Tuna";
String secondLiteral = "Albacore Tuna";
String firstObject = new String("Albacore Tuna");

if(firstLiteral == secondLiteral) {
  System.out.println(
     "firstLiteral and secondLiteral are the same object");
} else {
  System.out.println(
     "firstLiteral and secondLiteral are not the same object");
}
if(firstLiteral == firstObject) {
  System.out.println(
     "firstLiteral and firstObject are the same object");
} else {
  System.out.println(
     "firstLiteral and firstObject are not the same object");
}
```

输出如下：

```java
firstLiteral and secondLiteral are the same object
firstLiteral and firstObject are not the same object

```

`String`类的`intern`方法可用于对字符串进行内部化。对于所有常量字符串，内部化是自动执行的。在比较内部化的字符串时，可以使用等号运算符，而不必使用`equals`方法。这可以节省对字符串密集型应用程序的时间。很容易忘记对字符串进行内部化，因此在使用等号运算符时要小心。除此之外，`intern`方法可能是一个昂贵的方法。

### 注意

Java 还会对`String`类型之外的其他对象进行内部化。这些包括包装对象和小整数值。当使用原始类型的字符串连接运算符时，可能会产生包装对象。有关更多详细信息，请访问[`docs.oracle.com/javase/specs/jls/se7/jls7.pdf`](http://docs.oracle.com/javase/specs/jls/se7/jls7.pdf)，并参考 5.1.7 和 12.5 节。

要执行`String`比较，可以使用一系列`String`方法，包括但不限于以下内容：

| 方法 | 目的 |
| --- | --- |
| `equals` | 比较两个字符串，如果它们等效，则返回`true` |
| `equalsIgnoreCase` | 忽略字母大小写比较两个字符串，如果它们等效，则返回`true` |
| `startsWith` | 如果字符串以指定的字符序列开头，则返回`true` |
| `endsWith` | 如果字符串以指定的字符序列结尾，则返回`true` |
| `compareTo` | 如果第一个字符串在第二个字符串之前，则返回`-1`，如果它们相等，则返回`0`，如果第一个字符串在第二个字符串之后，则返回`1` |

### 注意

记住字符串从索引`0`开始。

以下是使用各种字符串比较的示例：

```java
String location = "Iceberg City";
if (location.equals("iceberg city"))
  System.out.println(location + " equals ' city'!");
else
  System.out.println(location +" does not equal 'iceberg city'");

if (location.equals("Iceberg City"))
  System.out.println(location + " equals 'Iceberg City'!");
else
  System.out.println(location +" does not equal 'Iceberg City'!");

if (location.endsWith("City"))
  System.out.println(location + " ends with 'City'!");
else
  System.out.println(location + " does not end with 'City'!");
```

输出如下所示：

```java
Iceberg City does not equal 'iceberg city'
Iceberg City equals 'Iceberg City'!
Iceberg City ends with 'City'!

```

在使用此方法时有几件事情需要考虑。首先，大写字母在小写字母之前。这是它们在 Unicode 中的排序结果。ASCII 也适用相同的排序。

一个字符串可以有多个内部表示。许多语言使用重音来区分或强调字符。例如，法国名字 Irène 使用重音，可以表示为`I` `r` `è` `n` `e`或序列`I` `r` `e` ```java `n` `e`. The second sequence combines the `e` and ```以形成字符`è`。如果使用`equals`方法比较这两种不同的内部表示，该方法将返回`false`。在这个例子中，`\u0300`将重音与字母`e`组合在一起。

String firstIrene = "Irène";

```java
String secondIrene = "Ire\u0300ne";

if (firstIrene.equals(secondIrene)) {
    System.out.println("The strings are equal.");
} else {
    System.out.println("The strings are not equal.");
}
```

此代码序列的输出如下：

```java
The strings are not equal.

```

`Collator`类可用于以特定于区域设置的方式操作字符串，消除了不同内部字符串表示的问题。

### 基本字符串方法

您可能会遇到几种`String`方法。这些在下表中有所说明：

| 方法 | 目的 |
| --- | --- |
| `length` | 返回字符串的长度。 |
| `charAt` | 返回字符串中给定索引的字符的位置。 |
| `substring` | 此方法是重载的，返回字符串的部分。 |
| `indexOf` | 返回字符或字符串的第一次出现的位置。 |
| `lastIndexOf` | 返回字符或字符串的最后一次出现的位置。 |

以下示例说明了这些方法的使用：

```java
String sample = "catalog";
System.out.println(sample.length());
System.out.println(sample.charAt(0));
System.out.println(sample.charAt(sample.length()-1));
System.out.println(sample.substring(0,3));
System.out.println(sample.substring(4));
```

执行此代码时，我们得到以下输出：

```java
7
c
g
cat
log

```

在许多应用程序中，搜索字符串以查找字符或字符序列是常见的需求。`indexOf`和`lastIndex`方法执行此类操作：

```java
String location = "Irene";
System.out.println(location.indexOf('I'));
System.out.println(location.lastIndexOf('e'));
System.out.println(location.indexOf('e'));
```

这些语句的结果如下：

```java
0
4
2

```

您可以将字符串中的位置视为字符之前的位置。这些位置或索引从`0`开始，如下图所示：

![基本字符串方法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_02_06.jpg)

### 字符串长度

字符串长度的计算可能比简单使用`length`方法所建议的要复杂一些。它取决于正在计数的内容以及字符串在内部的表示方式。

用于确定字符串长度的方法包括：

+   `length`：标准方法

+   `codePointCount`：与补充字符一起使用

+   字节数组的`length`方法：用于确定用于保存字符串的实际字节数

在存储字符串时，字符串的实际长度（以字节为单位）可能很重要。数据库表中分配的空间量可能需要比字符串中的字符数更长。

### 数字/字符串转换

将数字转换为字符串的过程很重要。我们可以使用两种方法。第一种方法使用静态方法，如下代码序列所示。`valueOf`方法将数字转换为字符串：

```java
String s1 = String.valueOf(304);
String s2 = String.valueOf(778.204);
```

`intValue`和`doubleValue`方法接受`valueOf`静态方法返回的对象，并分别返回整数或双精度数：

```java
int  num1 = Integer.valueOf("540").intValue();
double  num2 = Double.valueOf("3.0654").doubleValue();
```

第二种方法是使用各自的包装类的`parseInt`和`parseDouble`方法。它们的使用如下所示：

```java
num1 = Integer.parseInt("540");
num2 = Double.parseDouble("3.0654");
```

### 杂项字符串方法

有几种杂项方法可能会有用：

+   `replace`：这将字符串的一部分替换为另一个字符串

+   `toLowerCase`：将字符串中的所有字符转换为小写

+   `toUpperCase`：将字符串中的所有字符转换为大写

+   `trim`：删除前导和尾随空格

以下是这些方法的使用示例：

```java
String oldString = " The gray fox ";
String newString;

newString = oldString.replace(' ','.');
System.out.println(newString);

newString = oldString.toLowerCase();
System.out.println(newString);

newString = oldString.toUpperCase();
System.out.println(newString);

newString = oldString.trim();
System.out.println("[" + newString +"]" );
```

结果如下所示：

```java
.The.gray.fox.
 the gray fox
 THE GRAY FOX
[The gray fox]

```

## StringBuffer 和 StringBuilder 类

`StringBuffer`和`StringBuilder`类提供了`String`类的替代方法。与`String`类不同，它们是可变的。这在使程序更有效时有时是有帮助的。有几种常用的方法可用于操作`StringBuffer`或`StringBuilder`对象。以下示例中演示了其中几种。虽然示例使用`StringBuffer`类，但`StringBuilder`方法的工作方式相同。

经常需要将一个字符串附加到另一个字符串。可以使用`append`方法来实现这一点：

```java
StringBuffer buffer = new StringBuffer();
buffer.append("World class");
buffer.append(" buffering mechanism!");
```

以下是将字符串插入缓冲区的示例：

```java
buffer.insert(6,"C");
```

更详细的示例：

```java
StringBuffer buffer;
buffer = new StringBuffer();
buffer.append("World lass");
buffer.append(" buffering mechanism!");
buffer.insert(6,"C");
System.out.println(buffer.toString());
```

结果如下：

```java
World Class buffering mechanism!

```

# 摘要

在本章中，我们已经研究了 Java 如何处理数据。堆栈和堆的使用是重要的编程概念，可以很好地解释变量的作用域和生命周期等概念。介绍了对象和原始数据类型之间的区别以及变量的初始化。初始化过程将在第六章*类，构造函数和方法*中更详细地介绍。列出了 Java 中可用的运算符以及优先级和结合性规则。此外，还介绍了字符和字符串数据的操作。

在下一章中，我们将探讨 Java 中可用的决策结构以及它们如何有效地使用。这将建立在此处介绍的数据类型之上。

# 涵盖的认证目标

在本章中，我们涵盖了以下内容：

+   了解 Java 如何处理数据

+   调查标识符、Java 类和内存之间的关系

+   定义变量的范围

+   初始化标识符

+   使用运算符和操作数构建表达式

+   处理字符串

+   理解对象和原始数据类型之间的区别

# 测试你的知识

1.  当编译和运行以下代码时会发生什么？

```java
public class ScopeClass{
   private int i = 35;
   public static void main(String argv[]){
      int i = 45;
      ScopeClass s = new ScopeClass ();
      s.someMethod();
   }
   public static void someMethod(){
      System.out.println(i);
   }
}
```

a. 35 将被打印出来

b. 45 将被打印出来

c. 将生成编译时错误

d. 将抛出异常

1.  以下哪行将会编译而不会产生警告或错误？

a. `char d="d";`

b. `float f=3.1415;`

c. `int i=34;`

d. `byte b=257;`

e. `boolean isPresent=true;`

1.  给出以下声明：

```java
public class SomeClass{
   public int i;
   public static void main(String argv[]){
      SomeClass sc = new SomeClass();
      // Comment line
   }
}
```

如果它们替换注释行，以下哪些陈述是正确的？

a. `System.out.println(i);`

b. `System.out.println(sc.i);`

c. `System.out.println(SomeClass.i);`

d. `System.out.println((new SomeClass()).i);`

1.  给出以下声明：

```java
StringBuilder sb = new StringBuilder;
```

以下哪些是`sb`变量的有效用法？

a. `sb.append(34.5);`

b. `sb.deleteCharAt(34.5);`

c. `sb.toInteger` `(3);`

d. `sb.toString();`

1.  以下哪个将返回字符串 s 中包含“banana”的第一个字母`a`的位置？

a. `lastIndexOf(2,s);`

b. `s.indexOf('a');`

c. `s.charAt(` `2);`

d. `indexOf(s,'v');`

1.  给出以下代码，哪个表达式显示单词“Equal”？

```java
String s1="Java";
String s2="java";
if(expression) {
   System.out.println("Equal");
} else {
   System.out.println("Not equal");
}
```

a. `s1==s2`

b. `s1.matchCase(s2)`

c. `s1.equalsIgnoreCase(s2)`

d. `s1.equals(s2)`
