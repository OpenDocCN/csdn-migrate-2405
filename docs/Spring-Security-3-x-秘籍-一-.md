# Spring Security 3.x 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD`](https://zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 介绍

Spring Security 是 Spring 框架提供的安全层。Spring 框架是一个活跃的开源项目，使应用程序的进一步开发变得更加容易。它提供了各种层来处理项目设计和实施生命周期中面临的不同场景和挑战。

Spring 框架的 Spring Security 层与 Spring 框架的耦合度非常低，因此可以轻松地集成到其他应用程序中。

在本书中，我们将把 Spring Security 与其他框架集成，并通过编码示例进行演示。

# 本书涵盖的内容

第一章，*基本安全*，介绍了 J2ee 应用程序中安全性的基础知识。它向读者介绍了各种应用安全性的机制，以对用户进行身份验证和授权。它还解释了容器管理安全性。

第二章，*使用 Struts 2 的 Spring 安全性*，提供了在 Struts 2 应用程序中集成 Spring Security 的步骤。它演示了使用 Spring 框架提供的其他安全机制进行数据库身份验证和 LDAP 身份验证和授权。

第三章，*使用 JSF 的 Spring 安全性*，解释了在 JSF 应用程序中使用 Spring Security 的所有方面。它展示了如何使 JSF 应用程序使用监听器与 Spring Security 进行通信。

第四章，*使用 Grails 的 Spring 安全性*，演示了 grails 应用程序如何与 Spring Security 无缝集成。我们还展示了 Spring Security UI 如何提供屏幕来创建用户和角色。我们演示了在 GSP 页面中使用 Spring Security 标签。

第五章，*使用 GWT 的 Spring 安全性*，专注于 GWT 框架。GWT 框架与 GWT 集成，Spring Security 可用于对访问 GWT 应用程序的用户进行身份验证和授权。

第六章，*使用 Vaadin 的 Spring 安全性*，提出了将 Spring Security 与 Vaadin 框架集成的各种选项。我们创建了一个示例产品目录应用程序，以演示 Spring Security 与 Vaadin 框架的集成。

第七章，*使用 Wicket 的 Spring 安全性*，演示了将 wicket 框架与 Spring Security 集成。Wicket 本身具有内置的身份验证和授权框架，但挑战在于使 wicket 使用外部框架进行身份验证和授权。

第八章，*使用 ORM 和 NoSQL DB 的 Spring 安全性*，解释了在使用 Spring Security API 类进行身份验证和授权时，使用 Hibernate 和 MongoDB。

第九章，*使用 Spring Social 的 Spring 安全性*，介绍了 Spring Social，这是由 Spring Source 开发的一个框架，用于提供对社交网络站点的集成。Spring Social 使用 Spring Security 进行身份验证和授权。该章节演示了 Spring Social 和 Spring Security 如何通过演示 Facebook 登录应用程序进行集成。

第十章，*使用 Spring Web Services 的 Spring 安全性*，解释了保护 RESTFUL 和基于 SOAP 的 Web 服务的各种选项。

第十一章，*更多关于 Spring 安全性*，是一个杂项章节。它解释了如何将 Spring Security 与 Kaptcha API 集成，并提供多个输入身份验证。

# 您需要为本书准备什么

为了完成本书中的所有示例，您需要了解以下内容：

+   JBOSS 服务器

+   Netbeans

+   Maven

+   Java

+   Tomcat

+   Open LDAP

+   Apache DS

+   Eclipse IDE

# 这本书是为谁写的

这本书适用于所有基于 Spring 的应用程序开发人员，以及希望使用 Spring Security 将强大的安全机制实施到 Web 应用程序开发中的 Java Web 开发人员。

读者被假定具有 Java Web 应用程序开发的工作知识，对 Spring 框架有基本了解，并且对 Spring Security 框架架构的基本知识有一定了解。

对其他 Web 框架（如 Grails 等）的工作知识将是利用本书提供的全部食谱的额外优势，但这并非强制要求。

# 约定

在本书中，您将找到许多不同类型信息之间的区别的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```java
<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page language="java" %>
<html >
  <HEAD>
    <TITLE>PACKT Login Form</TITLE>
    <SCRIPT>
      function submitForm() {
        var frm = document. myform;
        if( frm.j_username.value == "" ) {
          alert("please enter your username, its empty");
          frm.j_username.focus();
          return ;
        }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```java
<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page language="java" %>
<html >
  <HEAD>
    <TITLE>PACKT Login Form</TITLE>
    <SCRIPT>
      function submitForm() {
        var frm = document. myform;
        if( frm.j_username.value == "" ) {
          alert("please enter your username, its empty");
          frm.j_username.focus();
          return ;
        }
```

任何命令行输入或输出都以以下形式编写：

```java
[INFO] Parameter: groupId, Value: com.packt
[INFO] Parameter: artifactId, Value: spring-security-wicket
[INFO] Parameter: version, Value: 1.0-SNAPSHOT

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为：“单击**提交**后，我们需要获得经过身份验证的会话。”

### 注意

警告或重要说明会以这样的框出现。

### 提示

提示和技巧会以这种形式出现。


# 第一章：基本安全

在本章中，我们将涵盖：

+   基于 JAAS 的 JSP 的安全身份验证

+   基于 JAAS 的 servlet 安全身份验证

+   基于 servlet 的基本容器身份验证

+   基于 servlet 的基于表单的身份验证

+   使用开放 LDAP 和 servlet 进行基于表单的身份验证

+   在 servlet 上进行哈希/摘要身份验证

+   JAX-WS 和 JAX-RS 的基本身份验证

+   启用和禁用文件列表

# 介绍

身份验证和授权已成为所有 Web 应用程序的重要组成部分。身份验证涉及检查谁正在访问应用程序。授权是检查用户访问权限的过程。在本机方法中，我们通常将用户的信息存储在数据库中，并在应用程序中编写代码。我们还为用户创建角色并进行映射。在这里，它与应用程序紧密耦合，因为当我们连接到新数据库或使用其他工具（如 LDAP 或 Kerbose）时，我们必须重写整个代码。但是有高级选项来处理身份验证和授权。 J2EE 容器通过配置 XML 文件提供了不同的用户身份验证方式。我们可以将身份验证分类为两种类型，即基于容器的身份验证和授权以及应用程序级别的身份验证和授权。

J2EE 容器提供接口和类来提供身份验证。在本章中，我们将看到如何使用 JAAS，基本身份验证和基于表单的身份验证来对用户进行身份验证。

在本书中，我们使用了 JAAS，因为它是身份验证的标准框架。 JAAS 基于**PAM**（可插入身份验证模块）框架工作。

身份验证和授权可以通过以下方式提供：

+   基本身份验证：在这种技术中，应用程序服务器提供带有用户名和密码文本框的登录表单，因此您无需自己创建登录页面。您还将知道调用者身份。

+   基于表单的身份验证：在这种技术中，容器处理身份验证，但登录表单由用户提供为 JSP 页面。

+   基于摘要的身份验证：在这种方法中，用户凭据使用特定算法进行哈希处理。

+   基于证书的身份验证：在这种技术中，客户端和服务器交换证书以验证其身份。获得 SSL 证书使网络上的数据传输安全。

# 基于 JAAS 的 JSP 的安全身份验证

部署描述符是所有 Web 应用程序的主要配置文件。容器在启动任何应用程序之前首先查找部署描述符。

部署描述符是`WEB-INF`文件夹中的 XML 文件`web.xml`。

如果查看`web.xml`文件的 XSD，可以看到与安全相关的模式。

可以使用以下 URL 访问模式：[`java.sun.com/xml/ns/j2ee/web-app_2_4.xsd`](http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd)。

以下是 XSD 中可用的模式元素：

```java
<xsd:element name="security-constraint" type="j2ee:security-constraintType"/>
<xsd:element name="login-config" type="j2ee:login-configType"/>
<xsd:element name="security-role "type="j2ee:security-roleType"/>
```

## 准备就绪

您将需要以下内容来演示身份验证和授权：

+   JBoss 7

+   Eclipse Indigo 3.7

+   创建一个动态 Web 项目，命名为`Security Demo`

+   创建一个包，`com.servlets`

+   在`WebContent`文件夹中创建一个 XML 文件，`jboss-web.xml`

+   创建两个 JSP 页面，`login.jsp`和`logoff.jsp`

## 如何做...

执行以下步骤以实现 JSP 的基于 JAAS 的安全性：

1.  编辑`login.jsp`文件，使用输入字段`j_username`，`j_password`，并将其提交给`SecurityCheckerServlet`：

```java
<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page language="java" %>
<html >
  <HEAD>
    <TITLE>PACKT Login Form</TITLE>
    <SCRIPT>
      function submitForm() {
        var frm = document. myform;
        if( frm.j_username.value == "" ) {
          alert("please enter your username, its empty");
          frm.j_username.focus();
          return ;
        }

        if( frm.j_password.value == "" ) {
          alert("please enter the password,its empty");
          frm.j_password.focus();
          return ;
        }
        frm.submit();
      }
    </SCRIPT>
  </HEAD>
  <BODY>
    <FORM name="myform" action="SecurityCheckerServlet" METHOD=get>
    <TABLE width="100%" border="0" cellspacing="0" cellpadding="1" bgcolor="white">
    <TABLE width="100%" border="0" cellspacing="0" cellpadding="5">
    <TR align="center">
    <TD align="right" class="Prompt"></TD>
    <TD align="left">
      <INPUT type="text" name="j_username" maxlength=20>
    </TD>
    </TR>
    <TR align="center">
    <TD align="right" class="Prompt"> </TD>
    <TD align="left">
    <INPUT type="password"name="j_password" maxlength=20 >
    <BR>
    <TR align="center">
    <TD align="right" class="Prompt"> </TD>
    <TD align="left">
    <input type="submit" onclick="javascript:submitForm();" value="Login">
    </TD>
    </TR>
    </TABLE>
    </FORM>
  </BODY>
</html>
```

`j_username`和`j_password`是使用基于表单的身份验证的指示符。

1.  让我们修改`web.xml`文件以保护所有以`.jsp`结尾的文件。如果您尝试访问任何 JSP 文件，您将收到一个登录表单，该表单反过来调用`SecurityCheckerServlet`文件对用户进行身份验证。您还可以看到角色信息被显示。按照以下代码片段中所示更新`web.xml`文件。我们使用了`2.5 xsd`。以下代码需要放置在`web.xml`文件中的`webapp`标签之间：

```java
<display-name>jaas-jboss</display-name>
 <welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.htm</welcome-file>
    <welcome-file>index.jsp</welcome-file>
    <welcome-file>default.html</welcome-file>
    <welcome-file>default.htm</welcome-file>
    <welcome-file>default.jsp</welcome-file>
 </welcome-file-list>

 <security-constraint>
    <web-resource-collection>
     <web-resource-name>something</web-resource-name>
     <description>Declarative security tests</description>
     <url-pattern>*.jsp</url-pattern>
     <http-method>HEAD</http-method>
     <http-method>GET</http-method>
     <http-method>POST</http-method>
     <http-method>PUT</http-method>
     <http-method>DELETE</http-method>
    </web-resource-collection>
    <auth-constraint>
     <role-name>role1</role-name>
    </auth-constraint>
    <user-data-constraint>
     <description>no description</description>
     <transport-guarantee>NONE</transport-guarantee>
    </user-data-constraint>
 </security-constraint>
 <login-config>
    <auth-method>FORM</auth-method>
    <form-login-config>
     <form-login-page>/login.jsp</form-login-page>
     <form-error-page>/logoff.jsp</form-error-page>
    </form-login-config>
 </login-config>
 <security-role>
    <description>some role</description>
    <role-name>role1</role-name>
 </security-role>
 <security-role>
    <description>packt managers</description>
    <role-name>manager</role-name>
 </security-role>
 <servlet>
    <description></description>
    <display-name>SecurityCheckerServlet</display-name>
    <servlet-name>SecurityCheckerServlet</servlet-name>
    <servlet-class>com.servlets.SecurityCheckerServlet</servlet-class>
 </servlet>
 <servlet-mapping>
    <servlet-name>SecurityCheckerServlet</servlet-name>
    <url-pattern>/SecurityCheckerServlet</url-pattern>
 </servlet-mapping>
```

1.  JAAS 安全检查器和凭证处理程序：Servlet 是一个安全检查器。由于我们正在使用 JAAS，这是用于身份验证的标准框架，为了执行以下程序，您需要导入`org.jboss.security.SimplePrincipal`和`org.jboss.security.auth.callback.SecurityAssociationHandle`并添加所有必要的导入。在以下的`SecurityCheckerServlet`中，我们从 JSP 文件获取输入并将其传递给`CallbackHandler`。

然后我们将 Handler 对象传递给`LoginContext`类，该类具有`login()`方法来进行身份验证。在成功身份验证后，它将为用户创建`Subject`和`Principal`，并提供用户详细信息。我们使用迭代器接口来迭代`LoginContext`对象，以获取用于身份验证的用户详细信息。

在`SecurityCheckerServlet`类中：

```java
package com.servlets;
public class SecurityCheckerServlet extends HttpServlet {
  private static final long serialVersionUID = 1L;

    public SecurityCheckerServlet() {
      super();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
       char[] password = null;
       PrintWriter out=response.getWriter();
       try
       {

         SecurityAssociationHandler handler = new SecurityAssociationHandler();
         SimplePrincipal user = new SimplePrincipal(request.getParameter("j_username"));
         password=request.getParameter("j_password").toCharArray();
         handler.setSecurityInfo(user, password);
         System.out.println("password"+password);

         CallbackHandler myHandler = new UserCredentialHandler(request.getParameter("j_username"),request.getParameter("j_password"));
         LoginContext lc = new LoginContext("other", handler);
         lc.login();

         Subject subject = lc.getSubject();
         Set principals = subject.getPrincipals();

         List l=new ArrayList();
         Iterator it = lc.getSubject().getPrincipals().iterator();
         while (it.hasNext()) {
           System.out.println("Authenticated: " + it.next().toString() + "<br>");
           out.println("<b><html><body><font color='green'>Authenticated: " + request.getParameter("j_username")+"<br/>"+it.next().toString() + "<br/></font></b></body></html>");
              }
           it = lc.getSubject().getPublicCredentials(Properties.class).iterator();
           while (it.hasNext()) System.out.println(it.next().toString());

           lc.logout();
       }     catch (Exception e) {
             out.println("<b><font color='red'>failed authenticatation.</font>-</b>"+e);

       }
    }
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
   }

}
```

创建`UserCredentialHandler`文件：

```java
package com.servlets;
class UserCredentialHandler implements CallbackHandler {
  private String user, pass;

  UserCredentialHandler(String user, String pass) {
    super();
    this.user = user;
    this.pass = pass;
  }
  @Override
  public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      for (int i = 0; i < callbacks.length; i++) {
        if (callbacks[i] instanceof NameCallback) {
          NameCallback nc = (NameCallback) callbacks[i];
          nc.setName(user);
        } else if (callbacks[i] instanceof PasswordCallback) {
          PasswordCallback pc = (PasswordCallback) callbacks[i];
          pc.setPassword(pass.toCharArray());
        } else {
        throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
      }
    }
  }
 }
```

在`jboss-web.xml`文件中：

```java
<?xml version="1.0" encoding="UTF-8"?>
<jboss-web>
<security-domain>java:/jaas/other</security-domain>
</jboss-web>
```

`Other`是在`login-config.xml`文件中定义的应用程序策略的名称。

所有这些将被打包为`.war`文件。

1.  配置 JBoss 应用服务器。转到 JBoss 中的`jboss-5.1.0.GA\server\default\conf\login-config.xml`。如果您查看文件，您可以看到用于数据库 LDAP 的各种配置以及使用属性文件的简单配置，我已在以下代码片段中使用：

```java
<application-policy name="other">
  <!-- A simple server login module, which can be used when the number of users is relatively small. It uses two properties files:
  users.properties, which holds users (key) and their password (value).
  roles.properties, which holds users (key) and a comma-separated list of
  their roles (value).
  The unauthenticatedIdentity property defines the name of the principal
  that will be used when a null username and password are presented as is
  the case for an unauthenticated web client or MDB. If you want to allow such users to be authenticated add the property, e.g.,
    unauthenticatedIdentity="nobody"
  -->
  <authentication>
  <login-module code="org.jboss.security.auth.spi.UsersRolesLoginModule"
    flag="required"/>
    <module-option name="usersProperties">users.properties</module-option>
    <module-option name="rolesProperties">roles.properties</module-option>
    <module-option name="unauthenticatedIdentity">nobody</module-option> 
  </authentication>
</application-policy>
```

1.  在相同的文件夹中创建`users.properties`文件。以下是带有用户名映射角色的`Users.properties`文件。

User.properties

```java
anjana=anjana123
```

roles.properties

```java
anjana=role1
```

1.  重新启动服务器。

### 提示

**下载示例代码**

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册以直接通过电子邮件接收文件。

## 它是如何工作的...

JAAS 由一组接口组成，用于处理身份验证过程。它们是：

+   `CallbackHandler`和`Callback`接口

+   `LoginModule`接口

+   `LoginContext`

`CallbackHandler`接口获取用户凭据。它处理凭据并将它们传递给`LoginModule`，后者对用户进行身份验证。

JAAS 是特定于容器的。每个容器都将有自己的实现，这里我们使用 JBoss 应用服务器来演示 JAAS。

在我的先前的示例中，我已经明确调用了 JASS 接口。

`UserCredentialHandler`实现了`CallbackHandler`接口。

因此，`CallbackHandler`是用户凭据和`LoginModule`的存储空间对用户进行身份验证。

`LoginContext`将`CallbackHandler`接口与`LoginModule`连接起来。它将用户凭据传递给`LoginModule`接口进行身份验证：

```java
CallbackHandler myHandler = new UserCredentialHandler(request.getParameter("j_username"),request.getParameter("j_password"));
  LoginContext lc = new LoginContext("other", handler);
  lc.login();
```

`web.xml`文件定义了安全机制，并指向我们应用程序中的受保护资源。

以下屏幕截图显示了一个身份验证失败的窗口：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_01_new.jpg)

以下屏幕截图显示了一个成功的身份验证窗口：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_02.jpg)

## 参见

+   *基于 servlet 的 JAAS 安全身份验证*的方法

+   *基于容器的 servlet 基本身份验证*的方法

+   *基于表单的 servlet 身份验证*的方法

+   *基于表单的 LDAP 和 servlet 身份验证*的方法

+   *在 servlet 上进行哈希/摘要身份验证*的方法

+   *JAX-WS 和 JAX-RS 的基本身份验证*的方法

+   *启用和禁用文件列表*的方法

# 基于 JAAS 的 servlet 安全身份验证

基于 JAAS 的 servlet 安全身份验证是对 JSP 的基于 JAAS 的安全身份验证的扩展。在本节中，我们演示了我们甚至可以在 servlet 上应用安全性。

## 准备工作

+   在 Eclipse 中创建一个新的**Web 项目**

+   创建一个名为`com.packt.security.servlets`的包

+   创建一个名为`ProtectedServlets`的 Servlet

## 如何做...

以下是 servlet 的基于 JAAS 的安全性步骤：

1.  创建一个名为`ProtectedServlets`的 servlet：

```java
public class ProtectedServlets extends HttpServlet {
  private static final long serialVersionUID = 1L;

  public ProtectedServlets() {
    super();

  }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    PrintWriter out=response.getWriter();
    try
    {
      out.println("Hello User");
      out.println("Authtype:"+request.getAuthType());
      out.println("User Principal:"+request.getUserPrincipal());
      out.println("User role:"+request.isUserInRole("role1"));
    }
    catch (Exception e) {
      out.println("<b><font color='red'>failed authenticatation</font>-</b>"+e);

    }
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    // TODO Auto-generated method stub
  }

}
```

1.  现在，编辑`web.xml`文件以保护 servlet：

```java
<web-resource-collection>
<web-resource-name>Servlet Protection</web-resource-name>
<description>Declarative security tests</description>
<url-pattern>/ProtectedServlets</url-pattern>
<http-method>HEAD</http-method>
<http-method>GET</http-method>
<http-method>POST</http-method>
<http-method>PUT</http-method>
<http-method>DELETE</http-method>
</web-resource-collection>
```

## 它是如何工作的...

重新启动服务器并访问 URL：`http://localhost:8080/jaas-jboss/ProtectedServlets`。

您将获得一个登录表单，该表单将对用户进行身份验证。Servlet 是受保护的资源，任何访问该 servlet 的人都将被要求登录。身份验证由 JAAS API 处理，该 API 是特定于应用服务器的。每个应用服务器都将有自己的安全实现。

## 另请参阅

+   *基于容器的 servlet 基本身份验证*食谱

+   *servlet 上的基于表单的身份验证*食谱

+   *使用开放 LDAP 和 servlet 进行基于表单的身份验证*食谱

+   *在 servlet 上进行哈希/摘要身份验证*食谱

+   *JAX-WS 和 JAX-RS 的基本身份验证*食谱

+   *启用和禁用文件列表*食谱

# 基于容器的 servlet 基本身份验证

在我们之前的示例中，我们使用了 JAAS 提供的接口来通过`loginform.jsp`进行身份验证。先前的应用程序具有自定义的登录表单设计，身份验证由应用服务器提供的 JAAS API 处理。

## 准备工作

+   创建一个简单的 Web 应用程序项目

+   创建一个 servlet 类

+   编辑`web.xml`文件以进行基本身份验证

+   添加约束以限制用户访问 servlet

## 如何做...

现在，我们将看到基本身份验证。容器提供登录表单并对用户进行身份验证，验证成功后将用户重定向到 servlet。这里不涉及登录表单。

在`web.xml`文件中进行以下更改：

```java
<login-config>
   <auth-method>BASIC</auth-method>
<form-login-config>  
```

将`.war`文件导出到 JBoss，重新启动服务器，并访问 servlet。

## 它是如何工作的...

在先前的示例中，容器通过读取`web.xml`文件决定了对 servlet 进行身份验证的机制。这里的`<auth-method>`标签已将`BASIC`定义为身份验证的模式。当我们访问受保护的资源时，应该会弹出一个登录对话框。

以下截图显示了实现的工作流程：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_03.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_04.jpg)

## 另请参阅

+   *servlet 上的基于表单的身份验证*食谱

+   *使用开放 LDAP 和 servlet 进行基于表单的身份验证*食谱

+   *在 servlet 上进行哈希/摘要身份验证*食谱

+   *JAX-WS 和 JAX-RS 的基本身份验证*食谱

+   *启用和禁用文件列表*食谱

# servlet 上的基于表单的身份验证

在前几节中，我们演示了 servlet 和 JSP 上的基本身份验证。现在让我们在 servlet 上使用基于表单的身份验证。

## 准备工作

让我们在 servlet 上应用基于表单的身份验证。您将需要一个简单的 Web 应用程序，其中包括一个 servlet、一个 Web 容器来处理身份验证，以及告诉容器要进行身份验证的`web.xml`文件。

## 如何做...

让我们看一些在 servlet 上实现基于表单的身份验证的简单步骤：

1.  创建一个名为`Containerform.jsp`的 JSP 文件：

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<form method="POST" action="j_security_check">
Username:<input type="text" name="j_username">
password:<input type="password" name="j_password">
<input type=submit>
</form>
</body>
</html>
```

您在先前的代码中观察到了什么？

`action=j_security_check`是默认的 URL，被 Web 容器识别。它告诉容器它有用户凭据需要进行身份验证。

1.  现在，编辑`web.xml`文件：

```java
<login-config>
  <auth-method>FORM</auth-method>
  <form-login-config>
    <form-login-page>/Containerform.jsp</form-login-page>
    <form-error-page>/logoff.jsp</form-error-page>
  </form-login-config>
</login-config>
```

构建项目并将`.war`文件导出到 JBoss。

## 它是如何工作的...

先前的示例演示了基于表单的身份验证。J2EE 容器读取`web.xml`文件，`<auth-method>`标签具有设置为`form`属性。然后它进一步寻找需要显示以进行基于表单的身份验证的`login.jsp`文件。`<form-error-page>`和`<form-login-page>`具有登录文件名和在身份验证失败时需要显示的错误页面。当用户尝试访问受保护的资源时，J2EE 容器将请求重定向到登录页面。用户凭据提交给`j_security_check`操作。容器识别此操作并进行身份验证和授权；成功后，用户被重定向到受保护的资源，失败时会显示错误页面。

以下是工作流程的屏幕截图，显示用户的登录页面，并在成功验证时显示用户信息：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_05.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_06.jpg)

## 参见

+   *使用 open LDAP 和 servlet 进行基于表单的身份验证*配方

+   *在 servlet 上进行哈希/摘要身份验证*配方

+   *JAX-WS 和 JAX-RS 的基本身份验证*配方

+   *启用和禁用文件列表*配方

# 使用 open LDAP 和 servlet 进行基于表单的身份验证

在本节中，我们将看到如何通过检索存储在 open LDAP 和 JAAS 中的用户信息来对用户进行身份验证。Open LDAP，顾名思义，是轻量级用户目录协议的免费版本，允许我们创建组并向其中添加用户。

## 准备工作

下载 open LDAP，创建角色、组和用户。

在 JBoss 应用服务器中，编辑`login-config.xml`文件。

## 如何做...

执行以下步骤配置应用服务器从 Open LDAP 检索用户：

1.  在`login-config.xml`文件中提供 LDAP 端口的 URL、凭据和需要搜索的域，以找到应用程序提供的用户名和密码：

```java
<application-policy name="example">
 <authentication>
 <login-module code="org.jboss.security.auth.spi.LdapExtLoginModule" flag="required" >
 <module-option name="java.naming.factory.initial">com.sun.jndi.ldap.LdapCtxFactory</module-option>
 <module-option name="java.naming.provider.url">ldap://localhost:389</module-option>
 <module-option name="java.naming.security.authentication">simple</module-option>
 <module-option name="bindDN">cn=Manager,dc=maxcrc,dc=com</module-option>
 <module-option name="bindCredential">secret</module-option>
 <module-option name="baseCtxDN">ou=People,dc=maxcrc,dc=com</module-option>
 <module-option name="baseFilter">(uid={0})</module-option>

 <module-option name="rolesCtxDN">ou=Roles,dc=maxcrc,dc=com</module-option>
  <module-option name="rolesCtxDN">ou=Department,dc=maxcrc,dc=com</module-option>
 <module-option name="roleFilter">(member={1})</module-option>
 <module-option name="roleAttributeID">cn</module-option>
 <module-option name="searchScope">ONELEVEL_SCOPE</module-option>
 <module-option name="allowEmptyPasswords">true</module-option>
 </login-module>
</authentication>
</application-policy>
```

1.  在`jboss-web.xml`文件中，我们将为 JAAS 指定查找名称：

```java
jboss-web.xml
<?xml version="1.0" encoding="UTF-8"?>
<jboss-web>
<security-domain>java:/jaas/example</security-domain>
</jboss-web>
```

## 它是如何工作的...

在 JBoss 上构建和部署 WAR，重新启动服务器，并访问浏览器。

您将收到一个登录表单，并且 JBoss 根据提供的 open LDAP 凭据对用户进行身份验证。用户被检索并根据应用程序策略中提到的角色进行授权。容器为身份验证提供了内置的 API。模块`org.jboss.security.auth.spi.LdapExtLoginModule`处理 LDAP 身份验证过程。

## 参见

+   *在 servlet 上进行哈希/摘要身份验证*配方

+   *JAX-WS 和 JAX-RS 的基本身份验证*配方

+   *启用和禁用文件列表*配方

# 在 servlet 上进行哈希/摘要身份验证

在先前的身份验证机制中，客户端发送用户凭据，容器进行验证。

客户端不尝试加密密码。

因此，我们的应用程序仍然不安全，容易受到攻击。

本节是关于向服务器传递加密的用户凭据，并告诉服务器可以使用哪种加密算法来解密数据。

JBoss 是我选择来演示的应用服务器。

## 准备工作

+   修改`Login-config.xml`

+   创建`encrypt-users. properties`

+   创建`encrypt-roles. properties`

## 如何做....

1.  修改`web.xml`文件：

```java
<login-config>
    <auth-method>DIGEST</auth-method>
    <realm-name>PACKTSecurity</realm-name>
</login-config>
```

1.  现在，修改`jboss-web.xml`文件。领域名称用于哈希：

```java
<?xml version="1.0" encoding="UTF-8"?>
<!-- <jboss-web> -->
<!-- <security-domain>java:/jaas/other</security-domain> -->
<!-- </jboss-web> -->
<jboss-web>
<security-domain>java:/jaas/encryptme</security-domain>
</jboss-web>
```

1.  修改`login-config.xml`文件

```java
<application-policy name="encryptme">
    <!--this is used to demonstrate DIGEST Authentication
    -->
    <authentication>
      <login-module code="org.jboss.security.auth.spi.UsersRolesLoginModule"
        flag="required"/>
    <module-option name="usersProperties">encrypt-users.properties</module-option>
    <module-option name="rolesProperties">encrypt-roles.properties</module-option>
    <module-option name="hashAlgorithm">MD5</module-option>
    <module-option name="hashEncoding">rfc2617</module-option>
    <module-option name="hashUserPassword">false</module-option>
    <module-option name="hashStorePassword">true</module-option>
    <module-option name="passwordIsA1Hash">true</module-option>
   <module-option name="storeDigestCallback">
                org.jboss.security.auth.spi.RFC2617Digest
    </module-option>	
    </authentication>
  </application-policy>
```

1.  现在，我们需要告诉 JBoss 加密用户的密码。要做到这一点，执行以下步骤：

+   转到`E:\JBOSS5.1\jboss-5.1.0.GA\common\lib`

+   打开`jbosssx-server.jar`

+   转到安装 JBoss 的文件夹。我已经在我的`E:`上安装了 JBoss

+   现在在命令行上，写`cd E:\JBOSS5.1\jboss-5.1.0.GA>`

+   然后粘贴以下命令：`java -cp client/jboss-logging-spi.jar;common/lib/jbosssx-server.jar org.jboss.security.auth.spi.RFC2617Digest anjana "PACKTSecurity" role1`![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_07.jpg)

+   现在编辑`Encrypt-users. properties`：

```java
anjana=e3b6b01ec4b0bdd3fc1ff24d0ccabf1f
```

+   加密角色并更新`roles.properties`

## 它是如何工作的...

前面的示例演示了摘要身份验证机制。在 J2EE 容器中给定的密码使用 MD5 算法进行加密。容器对其进行解密，并根据解密后的密码验证用户凭据。身份验证机制是`digest`，容器弹出一个与基本身份验证机制类似的摘要机制登录对话框。

以下屏幕截图显示了工作流程：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_01_08.jpg)

它的行为类似于基本身份验证，但使用加密密码以及领域名称进行解密。

## 另请参阅

+   *JAX-WS 和 JAX-RS 的基本身份验证*配方

+   *启用和禁用文件列表*配方

# JAX-WS 和 JAX-RS 的基本身份验证

JAX-WS 和 JAX-RS 的身份验证配置保持不变。

我们需要在`<web-resource collection>`中给出 JAX-WS 或 JAX-RS URL。

`Auth_type`可以是基本的。容器将提供一个表单，供用户输入用户名和密码。

**由容器处理的身份验证**

我们将首先创建一个 Web 服务，然后让容器处理其安全性。

让我们创建一个将公开`service`方法的接口，然后声明一个`implementation`类。

让我们使用 Tomcat 6.0 来演示这一点。

## 准备工作

+   在 Eclipse-Indigo 中，创建一个动态 Web 项目

+   服务器：Tomcat 6

+   要添加到 Tomcat `lib`文件夹的 JAR 文件：[`jax-ws.java.net/2.2.7/`](https://jax-ws.java.net/2.2.7/)

+   下载项目并复制`lib`文件夹

## 如何做...

1.  创建一个`interface`和一个`implementation`类。为其添加`@WebService`注释。创建一个名为`com.packt.ws`的包。创建一个名为`EmployeeProfile`的接口和一个`implementation`类：

接口：

```java
package com.packt.ws;
import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;
@WebService
@SOAPBinding(style = Style.RPC)
public interface EmployeeProfile {
  @WebMethod
  String getSalary();
}
```

实施：

```java
package com.packt.ws;
import javax.jws.WebService;
import javax.jws.WebMethod;
import javax.jws.WebService;
@WebService(endpointInterface = "com.packt.ws.EmployeeProfile")
public class EmployeeProfileImpl implements EmployeeProfile {
         @Override
public String getSalary() {
    return "no salary for the month";
}
}
```

1.  还在`WEB-INF`下添加`sun-jaxws.xml`文件

```java
<?xml version="1.0" encoding="UTF-8"?>
<endpoints

  version="2.0">
  <endpoint
      name="EmployeeProfile"
      implementation="com.packt.EmployeeProfileImpl"
      url-pattern="/employee"/>
</endpoints>
```

1.  修改`web.xml`文件如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
  <display-name>JAX-WS-Authentication-Tomcat</display-name>
   <listener>
        <listener-class>
           com.sun.xml.ws.transport.http.servlet.WSServletContextListener
        </listener-class>
    </listener>
    <servlet>
        <servlet-name>employee</servlet-name>
        <servlet-class>
        com.sun.xml.ws.transport.http.servlet.WSServlet
        </servlet-class>
        <load-on-startup>1</load-on-startup>
    </servlet>
    <servlet-mapping>
        <servlet-name>employee</servlet-name>
        <url-pattern>/employee</url-pattern>
    </servlet-mapping>
   <security-role>
     <description>Normal operator user</description>
     <role-name>operator</role-name>
   	</security-role>

<security-constraint>
      <web-resource-collection>
        <web-resource-name>Operator Roles Security</web-resource-name>
        <url-pattern>/employee</url-pattern>
      </web-resource-collection>

      <auth-constraint>
        <role-name>operator</role-name>
      </auth-constraint>
      <user-data-constraint>
          <transport-guarantee>NONE</transport-guarantee>
      </user-data-constraint>
   </security-constraint>

<login-config>
      <auth-method>BASIC</auth-method>
   </login-config>

</web-app>
```

1.  验证 Web 服务。编辑`tomcat-users.xml`文件并将其添加到`server.xml`：

```java
<Realm className="org.apache.catalina.realm.UserDatabaseRealm"
             resourceName="UserDatabase"/>
```

## 它是如何工作的...

通过访问以下 URL，您应该会被提示登录。

每个 Web 服务 URL 都经过身份验证。

您将被提示输入登录页面（`http://localhost:8080/EmployeeProfile/employee`）

## 另请参阅

+   *启用和禁用文件列表*配方

# 启用和禁用文件列表

通常不建议在应用程序中启用目录列表。默认情况下，JBoss 上将禁用目录列表。

如果启用了，转到您的 JBoss 安装文件夹。

## 如何做...

以下步骤将帮助在应用程序服务器中禁用和启用文件列表：

1.  浏览到路径`\server\default\deployers\jbossweb.deployer`。

1.  在`WEB-INF`文件夹中打开`web.xml`。

1.  将列表设置为`false`。

```java
<servlet>
      <servlet-name>default</servlet-name>
      <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
      <init-param>
         <param-name>debug</param-name>
         <param-value>0</param-value>
      </init-param>
      <init-param>
         <param-name>listings</param-name>
         <param-value>false</param-value>
      </init-param>
      <load-on-startup>1</load-on-startup>
   </servlet>
```

## 另请参阅

+   *Spring Security with Struts2*配方


# 第二章：Struts 2 中的 Spring Security

在本章中，我们将涵盖：

+   将 Struts 2 与 Spring Security 集成

+   具有基本 Spring Security 的 Struts 2 应用程序

+   在 Struts 2 中使用基于摘要/哈希的 Spring Security

+   在 Struts 2 中使用 Spring Security 注销

+   使用 Struts 2 和 Spring Security 进行数据库身份验证

+   在 Struts 2 中使用 Spring Security 获取已登录用户信息

+   在 Struts 2 中显示自定义错误消息以处理身份验证失败

+   使用 ApacheDS 进行 Spring Security 和 Struts 2 应用程序的身份验证

# 介绍

我们在第一章中学习了安全的基础知识，*基本安全*，这有助于我们更好地理解 Spring Security，也了解了 Spring 框架中 Spring Security 组件的起源。

在本章中，让我们看看如何在基于 Struts 2 框架的 Web 应用程序中使用 Spring Security 来对用户进行身份验证。

Apache Struts 2 可以与 JSF 和 Spring 集成。它是一个非常灵活的基于 POJO Action 的 MVC 框架。POJO 本身扮演一个动作类的角色来满足请求。Struts 2 源自另一个称为 WebWork 的框架，它与 Servlet 过滤器一起工作，拦截请求和响应。

**探索 Spring 包**

您可以直接从 MAVEN 下载 JAR 文件，或者在您的 POM 文件中添加依赖项。

我们更喜欢使用最新的 JAR 文件 3.1.4，从[`mvnrepository.com/artifact/org.springframework.security/spring-security-core/`](http://mvnrepository.com/artifact/org.springframework.security/spring-security-core/)下载：

```java
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-core</artifactId>
    <version>3.1.4.RELEASE</version>
 </dependency> 
 <dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-web</artifactId>
    <version>3.1.4.RELEASE</version>
  </dependency> 
  <dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>3.1.4.RELEASE</version>
  </dependency>
```

**Spring Security 中的主要包**

+   `org.springframework.security.authentication`：这是我们感兴趣的领域

+   `org.springframework.security.crypto`：这用于加密和解密

+   `org.springframework.security.util`：这是 Spring Security API 中使用的通用实用程序类

+   `org.springframework.security.core`：这包含与身份验证和授权相关的安全核心类

+   `org.springframework.security.access`：这包含基于投票者的安全访问控制注释和决策接口

+   `org.springframework.security.provisioning`：这包含用户和组配置接口

**Spring Security 的关键特性**

+   支持 JAAS。

+   支持数据库。

+   支持 MongoDB 身份验证。

+   提供 OpenID 身份验证。

+   演示多租户。

+   提供基本身份验证。

+   提供摘要身份验证。

+   Spring Security 像一个独立的模块一样工作。身份验证代码由 Spring Security 框架独立处理。

+   支持与 ApacheDS 进行身份验证。

+   支持 Open LDAP 身份验证。

**身份验证机制**

1.  用户提交他们的凭据到系统中；也就是说，用户名和密码。

1.  `org.springframework.security.authentication.UsernamePasswordAuthenticationToken`接受凭据并将它们传递给`org.springframework.security.authentication.AuthenticationManager`进行验证。

1.  系统对用户进行身份验证。

1.  凭据流如下：`UsernamePasswordAuthenticationToken` | `AuthenticationManager` | `Authentication`。

1.  最后返回一个完全加载的身份验证实例。

1.  `SecurityContextHolder`接受身份验证实例。

1.  系统还会检查角色或组的授权。

1.  最后，根据用户的授权，允许用户访问系统。

# 将 Struts 2 与 Spring Security 集成

让我们首先设置一个 Struts 2 应用程序，并将 Spring Security 与其集成。

## 准备工作

+   Eclipse Indigo 或更高版本

+   JBoss 作为服务器

+   Struts 2 JARs：2.1.x

+   Spring-core JAR 文件 3.1.4。发布和 Spring-Security 3.1.4。发布

+   Struts 2 Spring 插件 jar

## 如何做...

在本节中，我们将学习如何使用基于表单的 Spring Security 设置 Struts 2 应用程序：

1.  在您的 Eclipse IDE 中，创建一个动态 Web 项目并命名为`Spring_Security_Struts2`。

1.  在`src/main/java`下创建一个源文件夹。

1.  在源文件夹`src/main/java`下创建一个`struts.xml`文件。

1.  要将 Struts 2 与 Spring 应用程序集成，需要在此处添加`application-context.xml`文件引用。

1.  在`web.xml`中添加 Struts 过滤器映射。还需要在`web.xml`文件中添加 Spring 监听器。监听器条目应位于 Struts 2 过滤器条目之上。

1.  `contextLoaderListener`将告诉`servletcontainer`有关`springcontextLoader`，并且它将跟踪事件。这还允许开发人员创建`BeanListeners`，以便跟踪 Bean 中的事件。

1.  在`web.xml`文件中，添加以下代码：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
<display-name>Struts2x</display-name>
<listener>  
<listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>  
</listener>
<!—to integrate spring with struts2->
<context-param>
<param-name>contextConfigLocation</param-name>
<param-value>/WEB-INF/applicationContext.xml</param-value>
</context-param>
<filter>
<filter-name>struts2</filter-name>
<filter-class>org.apache.struts2.dispatcher.FilterDispatcher</filter-class>
</filter>

<filter-mapping>
<filter-name>struts2</filter-name>
<url-pattern>/*</url-pattern>
</filter-mapping>

</web-app>
```

1.  要设置基于表单的安全性，我们需要创建`login.jsp`。表单操作为`j_spring_security_check`：

```java
<%@ taglib prefix="c" url="http://java.sun.com/jsp/jstl/core"%>
<html>
  <head>
  <title>Login Page</title>
  <style>
    .errorblock {
      color: #ff0000;
      background-color: #ffEEEE;
      border: 3px solid #ff0000;
      padding: 8px;
      margin: 16px;
    }
  </style>
  </head>
  <body onload='document.f.j_username.focus();'>
    <h3>Login with Username and Password (Custom Page)</h3>
    <% String error=request.getParameter("error");

    if(error!=null){
      %>

      <div class="errorblock">
      Your login attempt was not successful, try again.<br /> Caused :

      </div>

    <%} %>
    <form name='f' action="<c:url value='/j_spring_security_check'/>"
    method='POST'>

    <table>
      <tr>
        <td>User:</td>
        <td><input type='text' name='j_username' value=''>
        </td>
      </tr>
      <tr>
        <td>Password:</td>
        <td><input type='password' name='j_password' />
        </td>
      </tr>
      <tr>
        <td colspan='2'><input name="submit" type="submit"
        value="submit" />
        </td>
      </tr>
      <tr>
        <td colspan='2'><input name="reset" type="reset" />
        </td>
      </tr>
    </table>

    </form>
  </body>
</html>
```

1.  创建一个名为`secure/hello.jsp`的文件夹。

1.  将`login`操作与`login.jsp`进行映射。

1.  将`loginfailed`操作与`login.jsp?error=true`进行映射。

1.  将`welcome`操作与`secure/hello.jsp`进行映射，操作类为`HelloWorld`：

`struts.xml`：

```java
<!DOCTYPE struts PUBLIC
"-//Apache Software Foundation//DTD Struts Configuration 2.0//EN"
"http://struts.apache.org/dtds/struts-2.0.dtd">
<struts>
  <package name="default" namespace="/" extends="struts-default">
  <action name="helloWorld">
    <result>success.jsp</result>
  </action>

  <action name="login">
    <result>login.jsp</result>
  </action>

  <action name="loginfailed">
    <result>login.jsp?error=true</result>
  </action>

  <action name="welcome" >
    <result>secure/hello.jsp</result>
  </action>

  </package>
</struts>
```

1.  `login page` URL 与 Struts 2 操作`'/login'`进行了映射。

1.  安全性应用于 Struts 2 操作`'/welcome'`。

1.  用户将被提示登录。

1.  具有`role_user`的用户将被授权访问页面

`Applicationcontext-security.xml`：

```java
<beans:beans xmlns="http://www.springframework.org
/schema/security"
   xmlns:beans="http://www.springframework.org
/schema/beans" 

   xsi:schemaLocation="http://www.springframework.org
/schema/beans
   http://www.springframework.org/schema/beans/spring-
beans-3.0.xsd
   http://www.springframework.org/schema/security
   http://www.springframework.org/schema/security/spring-
security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">
        <!-- AspectJ pointcut expression that locates our "post" method and applies security that way
        <protect-pointcut expression="execution(* bigbank.*Service.post*(..))" access="ROLE_TELLER"/>
        -->
    </global-method-security>
   <http auto-config="true" use-expressions="true" >
          <intercept-url pattern="/welcome" 
access="hasRole('ROLE_USER')"/>
          <form-login login-page="/login" default-target-
url="/welcome" authentication-failure-
url="/loginfailed?error=true" />
          <logout/>
   </http>
    <authentication-manager>
     <authentication-provider>
       <user-service>
          <user name="anjana" password="packt123" authorities="ROLE_USER" />
       </user-service>
     </authentication-provider>
   </authentication-manager>

</beans:beans>
```

## 工作原理...

只需运行应用程序。您将获得一个链接来访问受保护的页面。点击链接后，将提示您登录。这实际上是基于表单的登录。

在提交后，操作被发送到 Spring 框架进行用户身份验证。

成功后，用户将看到经过身份验证的页面。

Struts 2 框架与 Spring 框架及其模块非常容易融合，只需进行非常小的修改。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_01.jpg)![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_02.jpg)![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_03.jpg)

## 另请参阅

+   *具有基本 Spring Security 的 Struts 2 应用程序*配方

+   *使用基于摘要/哈希的 Spring Security 与 Struts 2*配方

+   *在 Struts 2 中显示自定义身份验证失败消息*配方

+   *使用 Struts 2 和 Spring Security 进行数据库身份验证*配方

+   *使用 Spring Security 和 Struts 2 应用程序进行 ApacheDS 身份验证*配方

+   *使用 Spring Security 与 Struts 2 进行注销*配方

+   *在 Struts 2 中获取 Spring Security 中已登录用户信息*配方

# 具有基本 Spring Security 的 Struts 2 应用程序

在本节中，我们将演示如何在 Struts 2 中进行基本的 Spring Security 身份验证。我们将创建一个示例 Struts 2 应用程序，并向操作添加 Spring Security 功能，使其受到保护。只有经过身份验证的授权用户才能访问它。

## 准备工作

+   更新`Applicationcontext-security.xml`文件

+   在 Eclipse 中创建一个新的动态项目：`Struts2_Spring_BASIC_Security_Recipe2`

## 如何做...

执行以下步骤，将 Struts 2 应用程序与 Spring Security 集成以实现基本身份验证：

1.  修改`applicationcontext-security.xml`文件以支持基本安全性：

`Applicationcontext-security.xml`：

```java
<beans:beans 

   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
   http://www.springframework.org/schema/security
   http://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">
        <!-- AspectJ pointcut expression that locates our "post" method and applies security that way
        <protect-pointcut expression="execution(* bigbank.*Service.post*(..))" access="ROLE_TELLER"/>
        -->
    </global-method-security>

  <http>
   <intercept-url pattern="/welcome" access="ROLE_TELLER" />
   <http-basic />
  </http>
   <authentication-manager>
     <authentication-provider>
       <user-service>
         <user name="anjana" password="123456" authorities="ROLE_TELLER" />
       </user-service>
     </authentication-provider>
   </authentication-manager>
</beans:beans>
```

## 工作原理...

当用户运行 Struts 2 应用程序并尝试访问受保护的资源时，Spring Security 上下文将被初始化，并且 Spring 的登录对话框将中断 Struts 2 操作，该对话框将请求用户名和密码。验证成功后，用户将被重定向到 Struts 2 操作页面。

以下是应用程序的工作流程：

在浏览器上的 Struts 2 和 Spring 基本安全性：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_04.jpg)

## 另请参阅

+   *使用基于摘要/哈希的 Spring Security 与 Struts 2*配方

# 使用基于摘要/哈希的 Spring Security 与 Struts 2

使用基于表单或基本身份验证并不会使 Struts 2 应用程序变得安全，因为密码会以明文形式暴露给用户。Spring Security JAR 中有一个加密包。该包可以解密加密的密码，但我们需要告诉 Spring Security API 有关加密算法的信息。

## 准备工作

+   在 Eclipse 中创建一个动态 Web 项目

+   添加 Struts 2 JAR 包

+   添加与 Spring Security 相关的 JAR 包

+   `web.xml`，`struts2.xml`和 JSP 设置与先前的应用程序相同

## 如何做...

让我们加密密码：`packt123456`。

我们需要使用外部 JAR，`JACKSUM`，这意味着 Java 校验和。它支持 MD5 和 SHA1 加密。

下载`jacksum.zip`文件（[`www.jonelo.de/java/jacksum/#Download`](http://www.jonelo.de/java/jacksum/#Download)）并解压缩 ZIP 文件。

```java
packt>java -jar jacksum.jar -a sha -q"txt:packt123456"
```

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_05.jpg)

更新`applicationcontext-security.xml`文件：

```java
<beans:beans 

   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
   http://www.springframework.org/schema/security
   http://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">
        <!-- AspectJ pointcut expression that locates our "post" method and applies security that way
        <protect-pointcut expression="execution(* bigbank.*Service.post*(..))" access="ROLE_TELLER"/>
        -->
    </global-method-security>
  <http>
   <intercept-url pattern="/welcome" access="ROLE_TELLER" />
   <http-basic />
  </http>
   <authentication-manager>
      <authentication-provider>
   <password-encoder hash="sha" />
      <user-service>
         <user name="anjana" password="bde892ed4e131546a2f9997cc94d31e2c8f18b2a" 
          authorities="ROLE_TELLER" />
      </user-service>
   </authentication-provider>
   </authentication-manager>
</beans:beans>
```

## 它是如何工作的...

我们需要更新`Applicationcontext-security.xml`文件。注意，认证类型是基本的，但密码是使用算法进行哈希处理。我们希望 Spring Security 使用 SHA 算法对其进行解密并对用户进行身份验证。

Spring Security 在处理摘要身份验证方面非常灵活。您还可以看到没有基于容器的依赖关系。

可以在以下截图中看到来自浏览器的基本身份验证：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_06.jpg)

Spring 已通过解密密码对用户进行了身份验证：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_07.jpg)

## 另请参阅

+   *在 Struts 2 中显示自定义错误消息以处理身份验证失败*配方

+   *使用 Struts 2 和 Spring Security 进行身份验证数据库*配方

+   *使用 Spring Security 和 Struts 2 应用程序进行 ApacheDS 身份验证*配方

+   *在 Struts 2 中使用 Spring Security 注销*配方

+   *在 Struts 2 中使用 Spring Security 获取已登录用户信息*配方

# 在 Struts 2 中使用 Spring Security 注销

在本节中，让我们实现一个注销场景，已登录用户将从应用程序中注销。注销操作将由 Spring Security 框架处理。我们需要配置`struts.xml`文件以处理`j_spring_security_logout`操作。

## 准备工作

+   在 Eclipse 中创建一个动态 Web 项目

+   添加与 Struts 2 相关的 JAR 包

+   添加与 Spring Security 相关的 JAR 包

+   `web.xml`，`struts2.xml`和 JSP 设置与先前的应用程序相同

## 如何做...

1.  让我们更新安全页面`hello.jsp`：

```java
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@page import="java.security.Principal" %>
<html>
<body>
Hello .You are seeing a secured Page now.

   <a href="<c:url value="/j_spring_security_logout" />" > Logout</a>
 </body>
</html>
```

1.  让我们将`j_spring_security_logout`与`struts.xml`文件进行映射：

当用户点击**注销**时，用户将被注销并重定向到`index.jsp`。

```java
<!DOCTYPE struts PUBLIC
"-//Apache Software Foundation//DTD Struts Configuration 2.0//EN"
"http://struts.apache.org/dtds/struts-2.0.dtd">
<struts>
   <package name="default" namespace="/" extends="struts-default">
        <action name="helloWorld">
            <result>success.jsp</result>
        </action>

      <action name="login">
                <result>login.jsp</result>
         </action>

         <action name="loginfailed">
                <result>login.jsp?error=true</result>
         </action>

         <action name="welcome" >
         <result>secure/hello.jsp</result>
         </action>

   <action name="j_spring_security_logout">
   <result>index.jsp</result>
         </action>
    </package>
</struts>
```

1.  更新`applicationcontext-security.xml`文件：

```java
<beans:beans 

   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
   http://www.springframework.org/schema/security
   http://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">
    </global-method-security>
  <http>
   <intercept-url pattern="/welcome" access="ROLE_TELLER" />
   <logout logout-success-url="/helloWorld" />
   <http-basic />
  </http>
   <authentication-manager>
      <authentication-provider>
   <password-encoder hash="sha" />
      <user-service>
         <user name="anjana" password="bde892ed4e131546a2f9997cc94d31e2c8f18b2a" 
             authorities="ROLE_TELLER" />
      </user-service>
   </authentication-provider>
   </authentication-manager>
</beans:beans>
```

## 它是如何工作的...

Spring Security 还提供了处理注销的选项。当用户点击**注销**时，用户将被重定向到指定页面。

`j_spring_secuurity_logout`为 Struts 2 应用程序提供了注销选项。

Struts 2 应用程序具有其操作的地图和 URL。

注销选项通常在受保护的页面中提供。

## 还有更多...

到目前为止，我们已将身份验证信息存储在`.xml`文件中。我们还对密码进行了哈希处理。如何在外部系统上存储信息并获取它呢？让我们看看 Struts 2 如何在以下部分与此数据库身份验证一起工作。

## 另请参阅

+   *在 Struts 2 中显示自定义错误消息以处理身份验证失败*配方

+   *在 Struts 2 中使用 Spring Security 进行身份验证数据库*配方

+   *使用 Spring Security 和 Struts 2 应用程序进行 ApacheDS 身份验证*配方

+   *在 Struts 2 中使用 Spring Security 获取已登录用户信息*配方

# 使用 Struts 2 和 Spring Security 进行身份验证数据库

在本节中，让我们使用存储在数据库中的信息对登录到 Struts 2 应用程序的用户进行授权。Spring Security 需要在 Struts 2 应用程序中进行配置，以便它了解数据库的位置和需要执行的 SQL，以使用 Spring Security 对用户进行身份验证。

## 准备工作

+   在 Eclipse 中创建一个动态 Web 项目：`Struts2_Spring_DBAuthentication_Recipe4`

+   将`struts.xml`文件复制到`src/main/java`

+   将`db-beans.xml`文件添加到`WEB-INF`

+   从上一个配方中复制`webContent`文件夹

+   将以下 JAR 文件添加到`lib`文件夹中，或者如果使用 maven，则更新您的 POM 文件：

+   spring-jdbc-3.0.7.RELEASE

+   mysql-connector-java-5.1.17

+   commons-dbcp

+   commons-pool-1.5.4

## 如何做...

1.  要使用 Struts 2 和 Spring 进行数据库身份验证，我们需要创建一个`db-beans.xml`文件。`db-beans.xml`文件将包含数据库信息：

```java
<beans 

   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans-3.0.xsd">
    <bean id="MySqlDatasource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
   <property name="driverClassName" value="com.mysql.jdbc.Driver" />
   <property name="url" value="jdbc:mysql://localhost:3306/test1" />
   <property name="username" value="root" />
   <property name="password" value="prdc123" />
   </bean>
 </beans>
```

1.  在与`applicationcontext-security.xml`相同的位置添加`db-beans.xml`文件。更新`web.xml`文件以读取`db-beans.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
  <display-name>SpringStruts2Security</display-name>
 <context-param>
          <param-name>contextConfigLocation</param-name>
          <param-value>
                /WEB-INF/db-beans.xml,
                /WEB-INF/applicationContext-security.xml
          </param-value>
   </context-param>

  <filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>
                  org.springframework.web.filter.DelegatingFilterProxy
                </filter-class>
  </filter>
  <filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <filter>
    <filter-name>struts2</filter-name>
    <filter-class>org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter</filter-class>
  </filter>
  <listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>
  <filter-mapping>
    <filter-name>struts2</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <error-page>
          <error-code>403</error-code>
          <location>/secure/denied.jsp</location>
   </error-page>

  <welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>
</web-app>
```

1.  在数据库中运行以下 SQL 脚本：

```java
CREATE TABLE `users1` (  `USER_ID` INT(10) UNSIGNED NOT NULL,
  `USERNAME` VARCHAR(45) NOT NULL,
  `PASSWORD` VARCHAR(45) NOT NULL,
  `ENABLED` tinyint(1) NOT NULL,
  PRIMARY KEY (`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE TABLE `user_roles` (
  `USER_ROLE_ID` INT(10) UNSIGNED NOT NULL,
  `USER_ID` INT(10) UNSIGNED NOT NULL,
  `ROLE` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`USER_ROLE_ID`),
  KEY `FK_user_roles` (`USER_ID`),
  CONSTRAINT `FK_user_roles` FOREIGN KEY (`USER_ID`) REFERENCES `users` (`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO test1.users (USER_ID, USERNAME,PASSWORD, ENABLED)
VALUES (100, 'anjana', 'packt123456', TRUE);

INSERT INTO test1.user_roles (USER_ROLE_ID, USER_ID,AUTHORITY)
VALUES (1, 100, 'ROLE_TELLER');
```

1.  更新`applicationContext-security.xml`文件以读取数据库配置：

```java
<beans:beans 

   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
   http://www.springframework.org/schema/security
   http://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">
        <!-- AspectJ pointcut expression that locates our "post" method and applies security that way
        <protect-pointcut expression="execution(* bigbank.*Service.post*(..))" access="ROLE_TELLER"/>
        -->
    </global-method-security>

  <http>
   <intercept-url pattern="/welcome" access="ROLE_TELLER" />
   <logout logout-success-url="/helloWorld" />
   <http-basic />
  </http>

   <authentication-manager> 
      <authentication-provider> 
         <jdbc-user-service data-source-ref="MySqlDS" 

            users-by-username-query=" 
                select username,password, enabled   
               from users1 where username=?"  

            authorities-by-username-query=" 
               select u.username, ur.role from users1 u, user_roles ur  
         where u.user_id = ur.user_id and u.username =?  "  
         /> 
      </authentication-provider>
   </authentication-manager>
</beans:beans>
```

## 它是如何工作的...

Struts 2 框架提供了一个链接来访问受保护的页面。但是 Spring Security 框架会中断并提供身份验证对话框。身份验证由 Spring Security 框架通过查询数据库完成。身份验证管理器配置了数据源引用，该引用将加载用于基于查询对用户进行身份验证的安全框架的信息。

## 还有更多...

到目前为止，我们只是在 JSP 文件中应用了安全性，该文件在`struts2.xml`中没有操作映射。让我们看看如何将操作类与 JSP 映射，然后与 Spring Security 集成。理想情况下，它应该以相同的方式工作。让我们在操作类中获取已登录用户的信息并在浏览器上显示出来。

## 另请参阅

+   *在 Struts 2 中显示身份验证失败的自定义错误消息*示例

+   *使用 Spring Security 和 Struts 2 应用程序进行 ApacheDS 身份验证*示例

+   *在 Struts 2 中使用 Spring Security 获取已登录用户信息*示例

# 在 Struts 2 中使用 Spring Security 获取已登录用户信息

到目前为止，在我们的示例中，我们还没有使用任何 Struts 2 操作类。

让我们创建一个操作类并查看安全性如何与此操作类一起运行。我们将在此示例中使用基于表单的身份验证。

## 准备工作

到目前为止，在我们的示例中，我们还没有使用任何 Struts 2 操作类。

让我们创建一个操作类并查看安全性如何与此操作类一起运行。我们将在此示例中使用基于表单的身份验证：

+   创建一个动态 Web 项目：`Struts2_Spring_Security_Recipe5`

+   创建一个包：`com.packt.action`

+   从上一个示例中复制`struts.xml`文件到`src/main/java`

+   还要复制`WebContent`文件夹

+   我们需要向包中添加一个操作类

+   更新`struts.xml`文件

## 如何做...

1.  `HelloAction`文件如下：

```java
package com.packt.action;
public class HelloAction {
         public String execute(){
         return "SUCCESS";
   }
}
```

1.  使用`HelloAction`更新`Struts.xml`文件。因此，当用户经过身份验证时，它将将请求传递给操作类，该操作类将执行`execute()`方法，然后将重定向到`hello.jsp`：

```java
<!DOCTYPE struts PUBLIC
"-//Apache Software Foundation//DTD Struts Configuration 2.0//EN"
"http://struts.apache.org/dtds/struts-2.0.dtd">
<struts>
   <package name="default" namespace="/" extends="struts-default">
        <action name="helloWorld">
            <result>success.jsp</result>
        </action>

      <action name="login">
               <result>login.jsp</result>
         </action>

         <action name="loginfailed">
               <result>login.jsp?error=true</result>
         </action>

         <action name="welcome" class="com.packt.action.HelloAction">
         <result name="SUCCESS">secure/hello.jsp</result>
         </action>

    </package>
</struts>
```

1.  获取已登录用户：

我们可以在操作类中获取已登录的用户名，并在页面上显示它，或者在我们的应用程序中进一步使用它。

我们可以在我们的操作类中使用`request.getUserPrincipal`来获取已登录用户的信息。

1.  对于项目设置：

+   在 Eclipse 中创建一个动态 Web 项目：`Struts2_Spring_Security_Recipe6`

+   从上一个示例中复制`src/main/java`文件夹

+   从上一个示例中复制`Web content`文件夹

+   修改`HelloAction.java`文件

```java
package com.packt.action;
import javax.servlet.http.HttpServletRequest;
import org.apache.struts2.ServletActionContext;
public class HelloAction {
   private String name;
               public String execute(){
               HttpServletRequest request = ServletActionContext.getRequest();
               String logged_in_user=request.getUserPrincipal().getName();
               setName(logged_in_user);
               return "SUCCESS";
         }

         public String getName() {
               return name;
         }

         public void setName(String name) {
               this.name = name;
         }
}
```

+   修改`secure/Hello.jsp`文件：

```java
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@taglib uri="/struts-tags" prefix="s" %>
<%@page import="java.security.Principal" %>
<html>
  <body>
    Hello <h1><s:property value="name" /></h1>.You are seeing a secured Page now.
    <a href="<c:url value="/j_spring_security_logout" />" > Logout</a>
  </body>
</html>
```

## 它是如何工作的...

用户信息存储在 principal 中：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_08.jpg)

在浏览器上显示已登录用户：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_09.jpg)

## 还有更多...

显示用户信息后，我们可以在身份验证失败时向用户显示自定义错误消息。

## 另请参阅

+   *在 Struts 2 中显示身份验证失败的自定义错误消息*示例

+   *使用 Spring Security 和 Struts 2 应用程序进行 ApacheDS 身份验证*示例

# 在 Struts 2 中显示身份验证失败的自定义错误消息

在本节中，我们将在 Struts 2 应用程序中捕获 Spring Security 的身份验证失败消息，并查看如何将其显示给用户。

## 准备工作

+   在身份验证失败时重定向到失败操作

+   向用户显示自定义消息

## 如何做...

执行以下步骤以捕获 Spring Security 在 JSP 应用程序中的身份验证失败消息：

1.  在`applicationcontext.xml`文件中，我们可以将 URL 重定向到另一个操作：`Authentication-failure-url="/loginfailed? error=true"`。

```java
<http auto-config="true" use-expressions="true" >
         <intercept-url pattern="/welcome" access="hasRole('ROLE_TELLER')"/>
         <form-login login-page="/login" default-target-url="/welcome" authentication-failure-url="/loginfailed?error=true" />
         <logout/>
   </http>
```

1.  使用以下代码更新`login.jsp`页面：

```java
<% String error=request.getParameter("error");

 if(error!=null){
 %>

          <div class="errorblock">
                Your login attempt was not successful, try again.<br /> Caused :

          </div>

 <%} %>
```

## 它是如何工作的...

登录失败操作与`struts2.xml`中的`login.jsp`文件进行了映射。`application-context.xml`中添加了`authentication-failure-url`。当用户输入错误的凭据时，身份验证失败，用户将被重定向到带有错误消息的登录页面。

错误消息配置在 JSP 文件中完成。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_10.jpg)

## 另请参阅

+   使用 Spring Security 和 Struts 2 应用程序进行 ApacheDS 身份验证的食谱

# 使用 Spring Security 和 Struts 2 应用程序进行 ApacheDS 身份验证

在本节中，我们将在 Apache 目录服务器中存储用户凭据和角色信息。Spring Security 必须找到服务器并登录到服务器。它应该通过比较用户提交的凭据和 Apache 目录服务器中存在的凭据和角色信息来对用户进行身份验证。

## 准备就绪

+   在 Eclipse 中创建一个动态 Web 项目

+   `src/main/java`文件夹和`WebContent`文件夹保持不变

+   安装 Apache 目录工作室：1.5.3

+   安装 Apache 目录服务器：2.0

+   10389 是 apache-ds 端口

+   将与 LDAP 相关的安全 JAR 添加到`WebContent Lib`文件夹中。

+   spring-ldap-core-tiger-1.3.X 版本

+   spring-ldap-odm-1.3.X 版本

+   spring-security-ldap-1.3.X 版本

+   spring-ldap-ldif-batch-1.3.X 版本

+   spring-ldap-test-1.3.X 版本

+   spring-ldap-core-1.3.X 版本

+   spring-ldap-ldif-core-1.3.X 版本

## 如何做...

执行以下步骤设置 Apache 目录以使用 Spring Security 在 Struts 2 应用程序中对用户进行身份验证：

1.  在安装了上述先决条件之后配置 Apache DS 服务器。

1.  使用以下步骤创建一个分区：

+   打开`server.xml`文件：`C:\Program Files\Apache Directory Server\instances\default\conf\server.xml`。

+   添加 JDM 分区：`<jdbmPartition id="packt" suffix="o=packt"/>`。

+   您可以重新启动 Apache DS 服务器以查看更改。然后使用 Apache 目录工作室连接到 Apache DS。右键单击**DIT**。从**Scratch**创建**Entry**。选择**Organization**，选择**o**，在**Value**中输入`packt`。选择**Finish**并刷新**DIT**以查看更新。

1.  配置 Apache 目录工作室。

1.  连接到 Apache 目录服务器。

1.  Apache DS 运行在 10389 端口。

1.  创建两个组`ou=groups`和`ou=user`。![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_11.jpg)![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_12.jpg)![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_13.jpg)

1.  在这里，对象类是用于向`ou=groups`添加条目，因为这维护了角色：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_14.jpg)

1.  在这里，对象类是为了向`ou=people`添加条目：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_02_15.jpg)

1.  通过向`cn=admin`添加`UniqueMember`为用户分配角色。

`Spring-security-ldap.xml`：

```java
<beans:beans 

   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans-3.0.xsd
   http://www.springframework.org/schema/security
   http://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">
        <!-- AspectJ pointcut expression that locates our "post" method and applies security that way
        <protect-pointcut expression="execution(* bigbank.*Service.post*(..))" access="ROLE_TELLER"/>
        -->
    </global-method-security>
   <http auto-config="true" use-expressions="true" >
          <intercept-url pattern="/welcome" access="hasRole('ROLE_ADMIN')"/>
<!--            <intercept-url pattern="/admin" access="hasRole('ROLE_admin')"/> -->

         <form-login login-page="/login" default-target-url="/secure/common.jsp" authentication-failure-url="/loginfailed?error=true" />

<authentication-manager>
           <ldap-authentication-provider 
                            user-search-filter="(mail={0})" 
                            user-search-base="ou=people"
                            group-search-filter="(uniqueMember={0})"
                      group-search-base="ou=groups"
                      group-role-attribute="cn"
                      role-prefix="ROLE_">
           </ldap-authentication-provider>
   </authentication-manager>

   <ldap-server url="ldap://localhost:10389/o=sevenSeas" manager-dn="uid=admin,ou=system" manager-password="secret" />
</beans:beans>
```

## 它是如何工作的...

`Spring Security-ldap.xml`将包含有关服务器位置和域的详细信息。它应该连接以检索用户信息。域是`sevenSeas`。1039 是 LDAP 服务器的端口号。Spring Security 使用`ldap-server`标签提供 LDAP 信息。它还提供密码和将连接的域。Struts 2 请求将被 Spring Security 中断，并且对于身份验证，将从登录页面接收用户信息。Spring Security 需要 LDAP 来获取用户名；成功后，用户将获得对受保护资源的访问权限。

## 另请参阅

+   第三章, *使用 JSF 的 Spring 安全性*
