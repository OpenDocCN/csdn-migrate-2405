# Spring Security 3.x 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD`](https://zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：JSF 的 Spring Security

在本章中，我们将涵盖：

+   将 JSF 与 Spring Security 集成

+   JSF 与基于表单的 Spring Security

+   使用 JSF 和基于表单的 Spring Security 进行身份验证以显示已登录用户

+   使用 JSF 与基于摘要/哈希的 Spring Security

+   使用 Spring Security 在 JSF 中注销

+   使用 Spring Security 和 JSF 进行身份验证

+   使用 JSF 和 Spring Security 进行 ApacheDS 身份验证

+   JSF 和 Spring Security 的身份验证错误消息

# 介绍

有许多在 Apache Faces/JSF 中开发的应用程序。它不像 Struts 2 那样是一个面向动作的框架，而纯粹是为了视图层。要在 JSF 中实现 Spring Security，我们需要找出一些解决方法。让我们看看关于 JSF 和 Spring Security 的一些配方。

我使用了最新的稳定版本的 Spring Security 和 Spring-core。如果您想更新您的库，可以阅读以下部分。对于 Maven 用户，这一切都是关于更新依赖项，对于普通的 Eclipse 用户，这是将`.jar`文件添加到`lib`文件夹。

**在 Eclipse 上设置 JSF 应用程序**

1.  使用 Eclipse Java EE 开发人员工具并设置一个动态 Web 项目。

1.  给项目命名：`JSf_Spring_Security_Chapter_3_Recipe1`。

1.  选择动态 Web 模块版本 2.5。

1.  配置：JavaServer Faces v1.2 项目。

1.  在下一个**新动态 Web 项目**窗口中，单击**下载库**。

1.  选择 Apache MyFaces 库。

**Spring Security MAJOR/MINOR/PATCH 版本**

当我为我的应用程序设置安全性时，我遇到了很多与模式版本相关的错误。

Spring 源提供了关于要下载哪个版本的很好描述。它建议使用 PATCH 版本是最安全的，不会影响现有代码，因为它将使用向后兼容性。MINOR 版本带有设计更改，MAJOR 版本带有主要 API 更改。对于 JSF 配方，我一直在使用 3.1.4 安全版本，并且已经下载了与 Spring-3.1.4 相关的 JAR 文件。

您可以下载 spring-security-3.1.4.RELEASE-dist，其中包含所有最新的 JAR 文件。

JAR 文件：

+   `spring-security-config`执行命名空间解析，并将读取`spring-security.xml`文件

+   Spring Security web 与 Web 应用程序过滤器进行交互

+   Spring Security 核心

将这些 JAR 文件保存在您的 Web 应用程序的`WEB-INF/lib`文件夹中。

# 将 JSF 与 Spring Security 集成

让我们在 Eclipse 中创建一个简单的 Apache MyFaces 应用程序。还让我们将 Spring Security 集成到 JSF 中，然后演示基本身份验证。

## 准备工作

+   您将需要 Eclipse Indigo 或更高版本

+   创建一个动态 Web 项目 JSF

+   在您的 Eclipse IDE 中，创建一个动态 Web 项目：`JSf_Spring_Security_Chapter_3_Recipe1`

+   创建一个源文件夹：`src/main/java`

+   创建一个包：`com.packt.jsf.bean`

+   创建一个托管 Bean：`User.java`

+   使用 Tomcat 服务器部署应用程序

## 如何做...

执行以下步骤来实现 JSF 和 Spring Security 的基本身份验证机制：

1.  `User.java`是应用程序的托管 Bean。它有两个方法：`sayHello()`和`reset()`：

`User.java 类`：

```java
package com.packt.jsf.bean;
public class User {
   private String name;
   private boolean flag= true; 
   public String getName() {
         return this.name;
   }
   public void setName(String name) {
         this.name = name;
   }
    public String  sayHello(){
          flag= false;
          name="Hello "+ name;
         return this.name;

    }
    public String  reset(){
          flag= true;
          name=null;
         return "reset";

    }
   public boolean isFlag() {
         return flag;
   }

   public void setFlag(boolean flag) {
         this.flag = flag;
   }
}
```

1.  让我们创建一个基于`ApacheMyFaces`标签的 JSP 文件。它期望一个强制的`<f:view>`标签。按照惯例，创建一个与其 bean 名称相同的 JSP 文件。它有一个表单，接受名称，并在单击按钮时显示**“你好”**：

`User.jsp`：

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="f"  uri="http://java.sun.com/jsf/core"%>
<%@ taglib prefix="h"  uri="http://java.sun.com/jsf/html"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>User</title>
</head>
<body>
<f:view>
  <h:form>
    <h:panelGrid columns="2">
      <h:outputLabel value="Name"></h:outputLabel>
      <h:inputText  value="#{user.name}"></h:inputText>
    </h:panelGrid>
    <h:commandButton action="#{user.sayHello}" value="sayHello"></h:commandButton>
    <h:commandButton action="#{user.reset}" value="Reset"></h:commandButton>
     <h:messages layout="table"></h:messages>
  </h:form>

  <h:panelGroup rendered="#{user.flag!=true}">
  <h3> Result </h3>
  <h:outputLabel value="Welcome "></h:outputLabel>
  <h:outputLabel value="#{user.name}"></h:outputLabel>
  </h:panelGroup>
</f:view>
</body>
</html>
```

1.  使用托管 Bean 更新`faces-config.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<faces-config

    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-facesconfig_1_2.xsd"
    version="1.2">
    <application>

         <el-resolver>org.springframework.web.jsf.el.SpringBeanFacesELResolver</el-resolver>   
           <!-- 
           <variable-resolver>org.springframework.web.jsf.SpringBeanVariableResolver</variable-resolver>
           -->
   </application>
   <managed-bean>
          <managed-bean-name>user</managed-bean-name>
          <managed-bean-class>com.packt.jsf.bean.User</managed-bean-class>
          <managed-bean-scope>session</managed-bean-scope>
   </managed-bean>

</faces-config>
```

1.  `Spring-security.xml`文件保持不变，但我使用了最新的 jar- 3.1.4 安全 jar：

```java
<beans:beans    xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd 
 http://www.springframework.org/schema/security
 http://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">

    </global-method-security>
    <http auto-config="true" use-expressions="true" >
          <intercept-url pattern="/faces/User.jsp" access="hasRole('ROLE_DIRECTOR')"/>
          <http-basic />
    </http>
    <authentication-manager>
      <authentication-provider>
        <user-service>
          <user name="packt" password="123456" authorities="ROLE_DIRECTOR" />
        </user-service>
      </authentication-provider>
    </authentication-manager>
</beans:beans>
```

1.  `web.xml`文件应更新 Spring 过滤器和监听器。它还具有 MyFaces 的配置：

`Spring-security.xml`：

```java
<?xml version="1.0" encoding="UTF-8"?><web-app    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
  <display-name>JSf_Spring_Security_Chapter_3_Recipe1</display-name>
  <welcome-file-list>
    <welcome-file>index.jsp</welcome-file>
  </welcome-file-list>

  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>
          /WEB-INF/spring-security.xml

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
  <listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>
  <servlet>
    <servlet-name>Faces Servlet</servlet-name>
    <servlet-class>javax.faces.webapp.FacesServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>Faces Servlet</servlet-name>
    <url-pattern>/faces/*</url-pattern>
  </servlet-mapping>
  <context-param>
    <param-name>javax.servlet.jsp.jstl.fmt.localizationContext</param-name>
    <param-value>resources.application</param-value>
  </context-param>
  <context-param>
    <description>State saving method: 'client' or 'server' (=default). See JSF Specification 2.5.2</description>
    <param-name>javax.faces.STATE_SAVING_METHOD</param-name>
    <param-value>client</param-value>
  </context-param>
  <context-param>
    <description>
   This parameter tells MyFaces if javascript code should be allowed in
   the rendered HTML output.
   If javascript is allowed, command_link anchors will have javascript code
   that submits the corresponding form.
   If javascript is not allowed, the state saving info and nested parameters
   will be added as url parameters.
   Default is 'true'</description>
    <param-name>org.apache.myfaces.ALLOW_JAVASCRIPT</param-name>
    <param-value>true</param-value>
  </context-param>
  <context-param>
    <description>
   If true, rendered HTML code will be formatted, so that it is 'human-readable'
   i.e. additional line separators and whitespace will be written, that do not
   influence the HTML code.
   Default is 'true'</description>
    <param-name>org.apache.myfaces.PRETTY_HTML</param-name>
    <param-value>true</param-value>
  </context-param>
  <context-param>
    <param-name>org.apache.myfaces.DETECT_JAVASCRIPT</param-name>
    <param-value>false</param-value>
  </context-param>
  <context-param>
    <description>
   If true, a javascript function will be rendered that is able to restore the
   former vertical scroll on every request. Convenient feature if you have pages
   with long lists and you do not want the browser page to always jump to the top
   if you trigger a link or button action that stays on the same page.
   Default is 'false'
</description>
    <param-name>org.apache.myfaces.AUTO_SCROLL</param-name>
    <param-value>true</param-value>
  </context-param>
  <listener>
    <listener-class>org.apache.myfaces.webapp.StartupServletContextListener</listener-class>
  </listener>
</web-app>:beans>
```

## 它是如何工作的...

当用户尝试访问受保护的`user.jsp`页面时，Spring Security 会拦截 URL 并将用户重定向到登录页面。成功身份验证后，用户将被重定向到`spring-security.xml`文件中提到的成功`url`。以下屏幕截图显示了使用 JSF 和 Spring Security 实现基本身份验证的工作流程。

现在访问以下 URL：`http://localhost:8086/JSf_Spring_Security_Chapter_3_Recipe1/faces/User.jsp`。

您应该看到一个基本的身份验证对话框，要求您如下登录：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_01.jpg)

以下屏幕截图是 JSF 的安全页面，可以在成功身份验证后访问：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_02.jpg)

## 另请参阅

+   使用基于表单的 Spring Security 的 JSF

+   使用 Spring Security 显示已登录用户的*JSF 和基于表单的身份验证*食谱

+   使用基于摘要/哈希的 Spring Security 的*使用 JSF*食谱

+   使用 Spring Security 注销 JSF 的*Logging out with JSF using Spring Security*食谱

+   使用 Spring Security 和 JSF 进行数据库身份验证的*身份验证数据库*食谱

+   使用 JSF 和 Spring Security 进行 ApacheDS 身份验证的*ApacheDS 身份验证*食谱

+   使用 JSF 和 Spring Security 的*身份验证错误消息*食谱

# 使用基于表单的 Spring Security 的 JSF

在本节中，我们将使用 JSF 和 Spring Security 实现基于表单的身份验证。将 Apache MyFaces 与 Spring Security 集成并不像 Struts 2 集成那样简单。

它需要一个解决方法。ApacheMyfaces 无法理解`/j_spring_security`方法。解决方法是在我们的 Managed Bean 类中创建一个自定义登录方法。我们将使用 JSF 外部上下文类将认证请求传递给 Spring Security 框架。

## 准备工作

+   在 Eclipse IDE 中创建一个新项目：`JSF_Spring_Security_Chapter_3_Recipe2`

+   按照以下屏幕截图中显示的配置进行配置

+   创建一个包：`com.packt.jsf.beans`

## 如何做...

执行以下步骤将 JSF 与 Spring Security 集成以实现基于表单的身份验证：

1.  在 Eclipse 中创建一个 Web 项目：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_03.jpg)

1.  创建一个 Credential Manager Bean：

此 bean 具有基于表单的身份验证 bean 的所有属性和自定义登录方法（）;

将设置`j_username`和`j_password`值，并在安全页面中显示用户。

`doSpringSecurityLogin()` bean：就像我们访问`ServletContext`并将其与请求分派器绑定一样，我们可以使用`ExternalContext`和请求分派器来执行`/j_spring_security_check`。

`phaseListener`实现旨在捕获身份验证异常。

`CredentialManager.java`：

```java
public class CredentialManager implements PhaseListener{
   private String j_username;
   private String j_password;

    public String getJ_password() {
         return j_password;
   }
   public void setJ_password(String j_password) {
         this.j_password = j_password;
   }
   public String doSpringSecurityLogin() throws IOException, ServletException
       {
           ExternalContext context = FacesContext.getCurrentInstance().getExternalContext();
           RequestDispatcher dispatcher = ((ServletRequest) context.getRequest()).getRequestDispatcher("/j_spring_security_check");
           dispatcher.forward((ServletRequest) context.getRequest(),(ServletResponse) context.getResponse());
           FacesContext.getCurrentInstance().responseComplete();
           return null;
       }
   public String getJ_username() {
         return j_username;
   }
   public void setJ_username(String j_username) {
         this.j_username = j_username;
   }
   @Override
   public void afterPhase(PhaseEvent arg0) {
         // TODO Auto-generated method stub

   }
   @Override
   public void beforePhase(PhaseEvent event) {
         Exception e = (Exception) FacesContext.getCurrentInstance().getExternalContext().getSessionMap().get(
          WebAttributes.AUTHENTICATION_EXCEPTION);

          if (e instanceof BadCredentialsException) {
              System.out.println("error block"+e);
               FacesContext.getCurrentInstance().getExternalContext().getSessionMap().put(
                   WebAttributes.AUTHENTICATION_EXCEPTION, null);
               FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Username or password not valid.", "Username or password not valid"));
           }
   }

   @Override
   public PhaseId getPhaseId() {
          return PhaseId.RENDER_RESPONSE;
   }
}
```

1.  让我们更新`Spring-security.xml`文件。`login-processing`-`url`映射到`j_security_check`：

```java
<beans:beans    xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd http://www.springframework.org/schema/securityhttp://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">

    </global-method-security>
   <http auto-config="true" use-expressions="true" >

          <intercept-url pattern="/faces/Supplier.jsp" access="hasRole('ROLE_USER')"/>  

         <form-login login-processing-url="/j_spring_security_check" login-page="/faces/login.jsp" default-target-url="/faces/Supplier.jsp" authentication-failure-url="/faces/login.jsp" />
         <logout/>
   </http>

   <authentication-manager>
     <authentication-provider>
       <user-service>
         <user name="anjana" password="anju123456" authorities="ROLE_USER"/>
       </user-service>
     </authentication-provider>
   </authentication-manager>
</beans: beans>
```

1.  将 Managed Bean 添加到`faces-config.xml`文件中：

```java
<?xml version="1.0" encoding="UTF-8"?>

<faces-config

    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-facesconfig_1_2.xsd"
    version="1.2">
    <lifecycle>
         <phase-listener>com.packt.jsf.beans.CredentialManager</phase-listener>
   </lifecycle>
    <application>

          <el-resolver>org.springframework.web.jsf.el.SpringBeanFacesELResolver</el-resolver>	
          <!-- 
          <variable-resolver>org.springframework.web.jsf.SpringBeanVariableResolver</variable-resolver>
           -->
   </application>

         <managed-bean>
         <managed-bean-name>credentialmanager</managed-bean-name>
         <managed-bean-class>com.packt.jsf.beans.CredentialManager</managed-bean-class>
         <managed-bean-scope>session</managed-bean-scope>
   </managed-bean>

</faces-config>
```

1.  现在是 Apache MyFaces 的`login.jsp`文件。

`login.jsp`文件应该包含以下内容：

`prependID=false`

它应该提交到`ManagedBean`中定义的自定义登录方法

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="f" uri="http://java.sun.com/jsf/core"%>
<%@ taglib prefix="h" uri="http://java.sun.com/jsf/html"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Spring Security Login</title>
</head>
<body>
<f:view>
<h:form prependId="false">
<h:panelGrid columns="2">
<h:outputLabel value="j_username"></h:outputLabel>
<h:inputText   id="j_username" required="true" value="#{credentialmanager.j_username}"></h:inputText>
<h:outputLabel value="j_password"></h:outputLabel>
<h:inputSecret  id ="j_password" required="true" value="#{credentialmanager.j_password}"></h:inputSecret>
</h:panelGrid>
<h:commandButton action="#{credentialmanager.doSpringSecurityLogin}" value="SpringSecurityLogin"/>
 </h:form>
</f:view>
</body>
</html>
```

## 它是如何工作的...

访问以下 URL：`localhost:8086/JSF_Spring_Security_Chapter_3_Recipe2/faces/Supplier.jsp`。

当用户访问 URL 时，他们将被重定向到登录页面。然后用户输入其凭据并单击**提交**。使用`FacesContext`对象使用`PhaseListener`实现来实例化`ExternalContext`对象。将`context`对象传递给请求对象，其中包含`'j_spring_security_check'` URL。Spring Security 将进行身份验证和授权。身份验证失败时，将抛出异常。

## 另请参阅

+   使用 Spring Security 显示已登录用户的*JSF 和基于表单的身份验证*食谱

+   使用基于摘要/哈希的 Spring Security 的*使用 JSF*食谱

+   使用 Spring Security 注销 JSF 的*Logging out with JSF using Spring Security*食谱

+   使用 Spring Security 进行数据库身份验证的*身份验证数据库*食谱

+   使用 JSF 和 Spring Security 进行 ApacheDS 身份验证的*ApacheDS 身份验证*食谱

+   *使用 JSF 和 Spring Security 进行身份验证错误消息*配方

# 使用 Spring Security 和 JSF 进行基于表单的认证以显示已登录用户

在上一个配方中，我们演示了使用 Spring Security 和 JSF `phaseListener`实现基于表单的认证。在本节中，我们将显示已登录的用户。

## 准备工作

您必须在`Supplier.jsp`文件中进行一些小的更改。

## 如何做...

执行以下步骤在浏览器上显示已登录用户的详细信息：

1.  要显示已登录的用户，请访问受保护页面中的托管 bean 对象。

1.  在`Supplier.jsp`文件中，编辑以下内容：

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="f" uri="http://java.sun.com/jsf/core"%>
<%@ taglib prefix="h" uri="http://java.sun.com/jsf/html"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<f:view>
<h:panelGroup>
  <h3> Result </h3>
  <h:outputLabel value="Welcome "></h:outputLabel>
  <h:outputLabel value="#{credentialmanager.j_username}"></h:outputLabel>
  </h:panelGroup>
</f:view>
</body>
</html>
```

## 它是如何工作的...

当用户被重定向到登录页面时，faces 上下文对象将用户信息提交给 Spring Security。成功后，用户 POJO 的 getter 和 setter 设置用户信息，用于在 JSP 页面上显示用户信息。

以下截图显示了使用 JSF 和 Spring Security 进行基于表单的认证，在浏览器中显示用户信息的工作流程：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_04.jpg)

成功认证后，用户将被引导到以下页面：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_05.jpg)

## 另请参阅

+   *使用基于摘要/哈希的 Spring Security 的 JSF*配方

+   *使用 JSF 和 Spring Security 进行注销*配方

+   *使用 Spring Security 和 JSF 进行身份验证数据库*配方

+   *使用 JSF 和 Spring Security 进行 ApacheDS 认证*配方

+   *使用 JSF 和 Spring Security 进行身份验证错误消息*配方

# 使用基于摘要/哈希的 Spring Security 进行 JSF

在本节中，我们将使用 JSF 和 Spring Security 实现摘要认证。用户的密码使用其中一种加密算法进行哈希处理，并在`.xml`文件中进行配置。用于哈希密码的算法也在配置文件中提到。

## 准备工作

Spring 摘要认证在 JSF 中也可以正常工作。我们需要使用`jacksum.jar`对密码进行哈希处理。在配置文件中提供哈希密码。还在配置文件中提到用于哈希处理的算法。

## 如何做...

执行以下步骤来实现 JSF 和 Spring Security 的摘要认证机制：

1.  让我们加密密码：`packt123456`。

1.  我们需要使用一个外部的 jar 包，Jacksum，这意味着 Java 校验和。

1.  它支持 MD5 和 SHA1 加密。

1.  下载`jacksum.zip`文件并解压缩 ZIP 文件夹。

```java
packt>java -jar jacksum.jar -a sha -q"txt:packt123456"
```

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_06.jpg)

1.  让我们创建一个新项目来演示这一点，我们将使用基本认证。在 Eclipse 中创建一个动态 Web 项目，并将其命名为`JSF_Spring_Security_DIGEST_Recipe3`。

1.  `web.xml`，`face-config.xml`和 JSP 设置与`JSF_Spring_Security_Chapter3_Recipe1`相同。我们需要更新`Spring-security.xml`文件以使用 SHA 加密和解密进行认证：

`Spring-security.xml`：

```java
<beans:beans    xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd http://www.springframework.org/schema/securityhttp://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">

    </global-method-security>
   <http auto-config="true" use-expressions="true" >
         <intercept-url pattern="/faces/User.jsp" access="hasRole('ROLE_DIRECTOR')"/>
         <http-basic />
   </http>

   <authentication-manager>
      <authentication-provider>
 <password-encoder hash="sha" />
 <user-service>
 <user name="anjana" password="bde892ed4e131546a2f9997cc94d31e2c8f18b2a" 
 authorities="ROLE_DIRECTOR" />
 </user-service>
 </authentication-provider>
 </authentication-manager>
</beans:beans>
```

## 它是如何工作的...

当您运行应用程序时，将提示您输入对话框。

输入用户名和密码后，Spring 框架将解密密码并将其与用户输入的详细信息进行比较。当它们匹配时，它会标记一个认证成功的消息，这将使上下文对象将用户重定向到成功的 URL。

以下截图显示了 JSF 和 Spring 进行摘要认证的工作流程。

这是一个基本的表单，但认证机制是摘要的。

Spring 通过解密密码对用户进行了身份验证：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_07.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_08.jpg)

## 另请参阅

+   *使用 JSF 和 Spring Security 进行注销*配方

+   *使用 Spring Security 和 JSF 进行身份验证数据库*配方

+   *使用 JSF 和 Spring Security 进行 ApacheDS 认证*配方

+   *使用 JSF 和 Spring Security 进行身份验证错误消息*配方

# 使用 JSF 和 Spring Security 进行注销

在本节中，我们将使用 Spring Security 在 JSF 应用程序中实现注销场景。

## 准备工作

+   实现`PhaseListener`类

+   在 JSF 页面上添加一个`commandButton`

## 如何做...

执行以下步骤来实现 JSF 应用程序中的 Spring Security 注销：

1.  在 Eclipse 中创建一个**新的动态 Web 项目**：![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_09.jpg)

1.  我们将再次创建一个`CredentialManager` bean。它将有另一个自定义的注销方法。 `Login.jsp`与上一个示例相同。不要忘记将其复制到新项目中。我们将在这里使用基于表单的身份验证：

```java
package com.packt.jsf.beans;

import java.io.IOException;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.PhaseEvent;
import javax.faces.event.PhaseId;
import javax.faces.event.PhaseListener;
import org.springframework.security.authentication.BadCredentialsException;
import javax.faces.application.FacesMessage;

import org.springframework.security.web.WebAttributes;

public class CredentialManager implements PhaseListener{
   /**
    * 
    */
   private static final long serialVersionUID = 1L;
   private String j_username;
   private String j_password;

    public String getJ_password() {
         return j_password;
   }
   public void setJ_password(String j_password) {
         this.j_password = j_password;
   }
   public String doSpringSecurityLogin() throws IOException, ServletException
       {
           ExternalContext context = FacesContext.getCurrentInstance().getExternalContext();
           RequestDispatcher dispatcher = ((ServletRequest) context.getRequest()).getRequestDispatcher("/j_spring_security_check");
           dispatcher.forward((ServletRequest) context.getRequest(),(ServletResponse) context.getResponse());
           FacesContext.getCurrentInstance().responseComplete();
           return null;
       }
   public String doSpringSecurityLogout() throws IOException, ServletException
 {
 ExternalContext context = FacesContext.getCurrentInstance().getExternalContext();
 RequestDispatcher dispatcher = ((ServletRequest) context.getRequest()).getRequestDispatcher("/j_spring_security_logout");
 dispatcher.forward((ServletRequest) context.getRequest(),(ServletResponse) context.getResponse());
 FacesContext.getCurrentInstance().responseComplete();
 return null;
 }
   public String getJ_username() {
         return j_username;
   }
   public void setJ_username(String j_username) {
         this.j_username = j_username;
   }
   public void afterPhase(PhaseEvent arg0) {
         // TODO Auto-generated method stub

   }
   public void beforePhase(PhaseEvent arg0) {
         Exception e = (Exception) FacesContext.getCurrentInstance().getExternalContext().getSessionMap().get(
            WebAttributes.AUTHENTICATION_EXCEPTION);

          if (e instanceof BadCredentialsException) {
              System.out.println("error block"+e);
               FacesContext.getCurrentInstance().getExternalContext().getSessionMap().put(
                   WebAttributes.AUTHENTICATION_EXCEPTION, null);
               FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Username or password not valid.", "Username or password not valid"));
           }
   }
   public PhaseId getPhaseId() {
          return PhaseId.RENDER_RESPONSE;
   }

}
```

1.  让我们在我们的安全页面上提供一个**注销**按钮：

`Supplier.jsp`：

```java
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="f"  uri="http://java.sun.com/jsf/core"%>
<%@ taglib prefix="h"  uri="http://java.sun.com/jsf/html"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<f:view>
  <h:form prependId="false">
<h:panelGroup>
  <h:outputLabel value="Welcome "></h:outputLabel>
  <h:outputLabel value="#{credentialmanager.j_username}"></h:outputLabel>
  </h:panelGroup>

 <h:commandButton action="#{credentialmanager.doSpringSecurityLogout}" value="SpringSecurityLogout" />
  </h:form>
</f:view>
</body>
</html>
```

1.  更新`Spring-security.xml`文件：

```java
<beans:beans    xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd 
 http://www.springframework.org/schema/securityhttp://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">

    </global-method-security>
   <http auto-config="true" use-expressions="true" >

          <intercept-url pattern="/faces/Supplier.jsp" access="hasRole('ROLE_USER')"/>  
         <form-login login-processing-url="/j_spring_security_check" login-page="/faces/login.jsp" default-target-url="/faces/Supplier.jsp" authentication-failure-url="/faces/login.jsp" />
         <logout  logout-success-url="/faces/login.jsp" />
   </http>

   <authentication-manager>
     <authentication-provider>
       <user-service>
         <user name="anjana" password="123456" authorities="ROLE_USER"/>
       </user-service>
     </authentication-provider>
   </authentication-manager>
</beans:beans>
```

## 它是如何工作的...

`CredentialManager`类实现了`phaseListener`接口。`doSpringSecurityLogout`方法通过使用`ExternalContext`创建一个上下文对象来处理 Spring 注销。然后，上下文提交注销请求，即`"/j_spring_security_logout"`到 Spring Security 框架，该框架注销用户。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_10.jpg)

单击注销后，用户将被重定向到登录页面。

## 另请参阅

+   *使用 Spring Security 和 JSF 进行数据库认证*食谱

+   *使用 JSF 和 Spring Security 进行 ApacheDS 身份验证*食谱

+   *使用 JSF 和 Spring Security 进行身份验证错误消息*食谱

# 使用 Spring Security 和 JSF 进行数据库认证

在本节中，我们将使用数据库来验证 JSF 应用程序中的用户身份验证。我们已经参考了注销示例，并且已经使用数据库进行了身份验证。

## 准备工作

+   在 Eclipse 中创建一个动态 Web 项目：`JSF_Spring_DBAuthentication_Recipe6`

+   所有文件和文件夹与注销应用程序相同

+   更新`security.xml`文件和`web.xml`文件

+   将以下 JAR 文件添加到`lib`文件夹中，或者如果您使用 Maven，则更新您的 POM 文件：

+   spring-jdbc-3.1.4RELEASE

+   mysql-connector-java-5.1.17-bin

+   commons-dbcp

+   commons-pool-1.5.4

## 如何做...

以下步骤将帮助我们通过从数据库中检索数据来验证用户信息：

1.  更新`Spring-security.xml`文件以读取数据库配置：

`applicationContext-security.xml`：

```java
<beans: beans    xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd http://www.springframework.org/schema/securityhttp://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">

    </global-method-security>
   <http auto-config="true" use-expressions="true" >

           <intercept-url pattern="/faces/Supplier.jsp" access="hasRole('ROLE_USER')"/>  
         <form-login login-processing-url="/j_spring_security_check" login-page="/faces/login.jsp" default-target-url="/faces/Supplier.jsp" authentication-failure-url="/faces/login.jsp" />
         <logout  logout-success-url="/faces/login.jsp" />

   </http>

   <authentication-manager> 
      <authentication-provider> 
          <jdbc-user-service data-source-ref="MySqlDS" 
            users-by-username-query=" 
              select username,password, enabled   
              from users1 where username=?"  

            authorities-by-username-query=" 
               select u.username, ur.role from users1 u, user_roles ur  
         where u.user_id = ur.user_id and u.username =?  " /> 
      </authentication-provider>
         </authentication-manager> 
</beans: beans>
```

## 它是如何工作的...

数据源引用在`Sping-security.xml`文件中给出。当用户点击**登录**时，Spring Security 过滤器将调用与数据库身份验证相关的类，这些类将读取`db-beans.xml`文件以建立连接。`<jdbc-user-service>`标签通过执行查询并根据用户在浏览器中提交的参数从数据库中检索用户信息来实现数据库身份验证。

## 另请参阅

+   *使用 JSF 和 Spring Security 进行 ApacheDS 身份验证*食谱

+   *使用 JSF 和 Spring Security 进行身份验证错误消息*食谱

# 使用 JSF 和 Spring Security 进行 ApacheDS 身份验证

在本节中，我们将使用 ApacheDS 和 Spring Security 在 JSF 应用程序中对用户进行身份验证。

## 准备工作

ApacheDS 身份验证类似于 Struts 2 ApacheDS 身份验证：

+   在 Eclipse 中创建一个动态 Web 项目：`JSF_Spring_ApacheDSAuthentication_Recipe7`

+   所有文件和文件夹与注销应用程序相同

+   更新`security.xml`文件

+   将`spring-security-ldap.jar`添加到您的`web-inf/lib`文件夹

## 如何做...

执行以下步骤来配置 Spring 和 JSF 应用程序的 LDAP：

1.  更新`Spring-security.xml`文件以读取 LDAP 配置：

```java
<beans:beans    xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.0.xsd http://www.springframework.org/schema/securityhttp://www.springframework.org/schema/security/spring-security-3.1.xsd">

 <global-method-security pre-post-annotations="enabled">

    </global-method-security>
   <http auto-config="true" use-expressions="true" >

           <intercept-url pattern="/faces/Supplier.jsp" access="hasRole('ROLE_USER')"/>  
         <form-login login-processing-url="/j_spring_security_check" login-page="/faces/login.jsp" default-target-url="/faces/Supplier.jsp" authentication-failure-url="/faces/login.jsp" />
         <logout  logout-success-url="/faces/login.jsp" />
               </http>
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

   <ldap-server url="ldap://localhost:389/o=example" manager-dn="uid=admin,ou=system" manager-password="secret" /></beans:beans>
```

## 它是如何工作的...

JSF 过滤器用于委托。Spring 过滤器用于身份验证。我们使用 ldap-authentication-provider 来设置 LDAP 参数到 Spring Security 引擎。当应用程序收到身份验证和授权请求时，spring-security-ldap 提供程序设置 LDAP 参数并使用 ldap-server-url 参数连接到 LDAP。然后检索用户详细信息并将其提供给 Spring 身份验证管理器和过滤器来处理身份验证的响应。

## 另请参阅

+   *JSF 和 Spring Security 的身份验证错误消息*配方

# JSF 和 Spring Security 的身份验证错误消息

在本节中，我们将看到如何捕获身份验证错误消息并在浏览器上向用户显示。如前面的示例中所示的`credentialmanager` bean 将捕获身份验证失败的异常。我们将看到如何在 JSP 中捕获它。

## 准备工作

`credentialmanager` bean 已捕获了错误凭据异常。

我们需要将其显示给用户。这可以通过在我们的 JSP 文件中使用`<h: messages>`标签来实现。这应该放在 grid 标记内。在托管 bean 中实现`phaselistener`的目的是捕获消息并将其显示给用户。这是更新后的`login.jsp`。

## 如何做...

执行以下步骤来捕获 JSP 中的身份验证失败消息：

+   编辑`login.jsp`文件：

```java
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="f"  uri="http://java.sun.com/jsf/core"%>
<%@ taglib prefix="h"  uri="http://java.sun.com/jsf/html"%>

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<f:view>
<h:form prependId="false">
                <h:panelGrid columns="2">

                 <h:outputLabel value="j_username"></h:outputLabel>
            <h:inputText    id="j_username" required="true" value="#{credentialmanager.j_username}"></h:inputText>
               <h:outputLabel value="j_password"></h:outputLabel>
            <h:inputSecret    id ="j_password" required="true" value="#{credentialmanager.j_password}"></h:inputSecret>
             <h:outputLabel value="_spring_security_remember_me"></h:outputLabel>
               <h:selectBooleanCheckbox
                      id="_spring_security_remember_me" />

              </h:panelGrid>
              <h:commandButton action="#{credentialmanager.doSpringSecurityLogin}" value="SpringSecurityLogin" />
 <h:messages />

         </h:form>
         </f:view>
</body>
</html>
```

## 它是如何工作的...

`credentialmanager`中的`beforePhase()`方法捕获了身份验证异常消息。异常被添加到`FacesMessage`，在 JSP 文件中捕获。

```java
FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,"Username or password not valid.", "Username or password not valid"));
```

以下截图显示了实现：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_11.jpg)

以下截图显示了身份验证失败时的屏幕：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_12.jpg)

以下截图显示了当在用户名和密码字段中输入空凭据时的屏幕：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_03_13.jpg)

## 另请参阅

+   第四章, *与 Grails 一起使用 Spring Security*


# 第四章：Spring Security with Grails

在本章中，我们将涵盖：

+   使用 Groovy Grails 设置 Spring Security 身份验证

+   使用 Grails 保护 Grails 控制器的 Spring Security

+   使用 Groovy Grails 注销场景的 Spring Security

+   使用 Groovy Grails 基本身份验证的 Spring Security

+   使用 Groovy Grails 摘要身份验证的 Spring Security

+   Spring Security with Groovy Grails 多重身份验证

+   使用 Groovy Grails LDAP 身份验证的 Spring Security

# 介绍

Grails 是一个基于插件的框架，它只需要在命令提示符上输入一些直观的命令即可工作。

在本章中，我们将看到如何轻松地将 Spring Security 与 Groovy on Grails 集成，编码量较少。

# 使用 Groovy Grails 设置 Spring Security 身份验证

在这个食谱中，我们首先将设置 Groovy 和 Grails。然后我们将展示如何将 Spring Security 与 Grails 集成。

## 准备工作

+   从[`groovy.codehaus.org/Download`](http://groovy.codehaus.org/Download)获取 Groovy 安装

+   从[`groovy.codehaus.org/Download`](http://groovy.codehaus.org/Download)下载并解压 Grails 2.3 到一个文件夹

+   设置环境变量：`GRAILS_HOME`

+   检查`Groovy_HOME`

+   通过输入`grails-version`来检查 Grails 安装

## 如何做...

以下步骤用于将 Spring Security 与 Groovy Grails 集成：

1.  创建一个目录：`Grails 项目`。

```java
cd Grails_Project
grails create-app myfirstapp
cd myfirstapp
grails create-controller MyFirstController

```

这将创建一个控制器，该控制器将在控制器包内可用。

1.  您可以打开生成的控制器文件并查看它。它将具有 Grails 自动生成的包名称`myfirstapp`。

```java
package myfirstapp
class MyFirstController {
    def index() { }
}
```

1.  更新生成的控制器文件。

```java
package myfirstapp
class MyFirstController {
  def index() { 
    render "Hello PACKT"
  }
}
```

1.  通过访问此 URL`http://localhost:8080/myfirstapp/`来测试 Grails 设置。

```java
cd myfirstapp

```

1.  为 Grails 下载安全 jar 文件。

```java
grails install-plugin spring-security-core
grails  s2-quickstart org.packt SecuredUser SecuredRole

```

如果安装程序不支持您的 Grails 版本，您可以向`BuildConfig.groovy`文件添加依赖项：

```java
plugins {

    compile ':spring-security-core:2.0-RC2'

}
```

1.  更新`Bootstrap.groovy`文件：

```java
import org.packt.SecuredUser;
import org.packt.SecuredRole;
import org.packt.SecuredUserSecuredRole
class BootStrap {

  def springSecurityService

    def init = { servletContext ->

    if(!SecuredUser.count()){
      /*The default password is 'password'*/
      def password = 'password'
      def user = new SecuredUser(username : 'anjana', password:'anjana123',enabled:true,accountExpired : false , accountLocked : false ,passwordExpired : false).save(flush: true, insert: true)
      def role = new SecuredUser(authority : 'ROLE_USER').save(flush: true, insert: true)
      /*create the first user role map*/
      SecuredUserSecuredRole.create user , role , true
    }

    }
    def destroy = {
    }
}
```

在前面的文件中，我们已经用用户名`anjana`和密码`anjana123`填充了用户。

只需这样做，我们就可以验证用户。

您可以看到我们没有更新任何 XML 文件。我们只是安装了插件并修改了文件。

## 工作原理...

让我们看看运行 Grails 时会得到什么样的输出：`grails run-app`。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_01.jpg)

更新`i18n`文件夹中的`Messages.properties`文件：

```java
springSecurity.login.header=Spring Security login
springSecurity.login.username.label=UserName
springSecurity.login.password.label=Password
springSecurity.login.remember.me.label=remember me
springSecurity.login.button=Login
springSecurity.errors.login.fail=Authentication failed
```

单击`http://localhost:8080/myfirstapp/login/auth`上的**LoginController**链接。

您应该能够看到登录屏幕，该屏幕是在安装安全插件时由 Grails 框架生成的。页面位于视图文件夹中。现在您可以使用用户名和密码`anjana`，`anjana123`登录。您将被重定向到 Grails 主页。身份验证失败时，您将收到身份验证失败消息。

当您单击**LogoutController**链接时，您将注销。当您再次单击控制器时，将要求您重新登录。

以下是应用程序的工作流程：

这是 Grails 登录屏幕——单击**登录**按钮，在输入用户名和密码后，将提交凭据到 Spring Security 框架：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_02.jpg)

在身份验证失败时，用户将被重定向到登录屏幕，并显示**身份验证失败**消息。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_03.jpg)

## 另请参阅

+   *Spring Security with Grails 保护 Grails 控制器*食谱

+   *Spring Security with Groovy Grails 注销场景*食谱

+   *Spring Security with Groovy Grails 基本身份验证*食谱

+   *Spring Security with Groovy Grails 摘要身份验证*食谱

+   *Spring Security with Groovy Grails 多级身份验证*食谱

+   *Spring Security with Groovy Grails LDAP 身份验证*食谱

# 使用 Grails 的 Spring Security 来保护 Grails 控制器

让我们将 Spring Security 应用于 Grails 控制器。场景是用户将访问 Grails 应用程序，并将提供一个登录链接。成功验证后，用户将提供可以访问的链接。这些链接只对已登录用户可见。

## 准备工作

为了演示目的，我们将创建以下内容：

+   一个简单的 Grails 控制器：`myfirstapp`

+   一个将使用 Spring Security 保护的`MyFirstController`控制器

+   修改`index.gsp`

## 操作步骤...

以下步骤用于将 Spring Security 与 Grails 集成以保护 Grails 控制器：

1.  转到`myfirstapp\grails-app\views`。

1.  您将看到`index.gsp`文件，将其重命名为`index.gsp_backup`。我已经从`index.gsp_backup`中复制了样式。

1.  创建一个新的`index.gsp`文件，编辑文件如下：

```java
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <h1>Welcome to Grails</h1>
    <sec:ifLoggedIn>Access the <g:link controller='myFirst' action=''>Secured Controller</g:link><br/>
        <g:link controller='logout' action=''>Spring Logout</g:link>
    </sec:ifLoggedIn>

    <sec:ifNotLoggedIn>
    <h2>You are seeing a common page.You can click on login.After login success you will be provided with the links which you can access.</h2>
    <g:link controller='login' action='auth'>Spring Login</g:link>
    </sec:ifNotLoggedIn>

  </body>
</html>
```

## 工作原理...

访问 URL：`http://localhost:8080/myfirstapp/`。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_04.jpg)

现在单击**Spring 登录**链接，您将被重定向到登录页面。Spring Security 处理身份验证机制，在成功登录后，用户将提供一个链接以访问受保护的控制器。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_05.jpg)

链接在`index.gsp`页面中提供，根据登录或注销状态显示和隐藏链接。这是使用`index.gsp`页面中的安全标签提供的。

单击**受保护的控制器**链接。您应该能够在浏览器上看到受保护控制器的输出消息。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_06.jpg)

## 另请参阅

+   *使用 Groovy Grails 注销场景的 Spring Security*配方

+   *使用 Groovy Grails 基本身份验证的 Spring Security*配方

+   *使用 Groovy Grails 摘要身份验证的 Spring Security*配方

+   *使用 Groovy Grails 多级身份验证的 Spring Security*配方

+   *使用 Groovy Grails LDAP 身份验证的 Spring Security*配方

# Groovy Grails Spring Security 身份验证注销场景

在这个配方中，让我们看看在 Grails 应用程序中使用 Spring Security 的注销实现。

## 准备工作

当我们在 Grails 中安装 Spring Security 插件时，`Login Controller`和`Logout Controller`类将自动创建。`Login Controller`将处理身份验证。`Logout Controller`将处理注销过程，它将重定向用户到公共页面。

## 操作步骤...

以下步骤用于在 Groovy on Grails 应用程序中实现注销操作：

1.  在`index.jsp`文件中，我们添加以下内容：

```java
<g:link controller='logout' action=''>Spring Logout</g:link>
```

1.  `Logout Controller`类将请求重定向到`j_spring_security`：

```java
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

class LogoutController {

  /**
   * Index action. Redirects to the Spring security logout uri.
   */
  def index = {
    // TODO put any pre-logout code here
    redirect uri: SpringSecurityUtils.securityConfig.logout.filterProcessesUrl // '/j_spring_security_logout'
  }
}
```

## 工作原理...

单击注销链接。用户将被重定向到主页。`SpringSecurityUtils.securityConfig.logout.filterProcessesUrl`默认设置为`/j_spring_security_logout`。因此，当用户单击注销时，他们将被重定向到`/j_spring_security_logout`操作。这将注销用户并且用户必须再次登录到 Grails 应用程序。

## 另请参阅

+   *使用 Groovy Grails 基本身份验证的 Spring Security*配方

+   *使用 Groovy Grails 摘要身份验证的 Spring Security*配方

+   *使用 Groovy Grails 多级身份验证的 Spring Security*配方

+   *使用 Groovy Grails LDAP 身份验证的 Spring Security*配方

# 使用 Groovy Grails 基本身份验证的 Spring Security

在这个配方中，我们将演示使用基本身份验证机制在 Grails 上使用 Groovy 的安全性。

## 准备工作

+   我们需要创建一个 Grails 应用程序：`grailsbasicauthexample`

+   将 Spring Security 插件安装到新应用程序中

+   创建`User`和`Role`类

+   编辑`Config.groovy`文件

+   编辑`BootStrap.groovy`文件

+   创建一个控制器：`GreetingsController`

## 操作步骤...

以下步骤用于演示在 Groovy on Grails 中使用 Spring Security 进行基本身份验证：

1.  在命令提示符中运行以下命令：

+   `Grails create-app grailsbasicauthexample`

+   `cd grailsbasicauthexample`

+   `grails install-plugin spring-security-core`

+   `grails s2-quickstart com.packt SecuredUser SecuredRole`

1.  编辑 `config.groovy` 文件并设置以下值：

```java
grails.plugins.springsecurity.useBasicAuth = true
grails.plugins.springsecurity.basic.realmName = "HTTP Basic Auth Demo"
```

1.  编辑 `Bootstrap.groovy` 文件：

```java
import com.packt.*;
class BootStrap {
  def init = { servletContext ->
    def userRole = SecuredRole.findByAuthority("ROLE_USER") ?: new SecuredRole(authority: "ROLE_USER").save(flush: true)
    def user = SecuredUser.findByUsername("anjana") ?: new SecuredUser(username: "anjana", password: "anjana123", enabled: true).save(flush: true)
    SecuredUserSecuredRole.create(user, userRole, true)
  }
  def destroy = {
  }
}
```

1.  运行命令 `$grails create-controller Greetings` 并添加注解：

```java
package grailsbasicauthexample
import grails.plugins.springsecurity.Secured
class GreetingsController {
  @Secured(['ROLE_USER'])
  def index() { 
    render "Hello PACKT"
  }
}
```

## 它是如何工作的...

访问 URL：`http://localhost:8080/grailsbasicauthexample/`。

点击 **Greetings Controller** 链接。这是一个受 Spring Security 限制的安全链接。当用户点击链接时，基本认证机制会触发一个登录对话框。用户必须输入用户名/密码：`anjana`/`anjana123`，然后进行身份验证，用户将被重定向到一个授权页面，也就是，您将会看到 **Greetings Controller** 链接。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_07.jpg)

成功认证后，用户将获得对问候控制器的访问权限。

## 另请参阅

+   *Spring Security with Groovy Grails Digest authentication* 食谱

+   *Spring Security with Groovy Grails multilevel authentication* 食谱

+   *Spring Security with Groovy Grails LDAP authentication* 食谱

# Spring Security with Groovy Grails Digest authentication

在这个食谱中，让我们看看摘要认证机制，其中密码将被哈希。让我们将其与 Grails 应用程序集成，并查看它如何进行身份验证和授权。

## 准备工作

+   我们需要创建一个 Grails 应用程序：`grailsdigestauthexample`

+   将 Spring Security 插件安装到新应用程序中

+   创建 `User` 和 `Role` 类

+   编辑 `Config.groovy` 文件

+   编辑 `BootStrap.groovy` 文件

+   创建一个控制器：`SecuredPackt`

## 如何做…

以下步骤用于演示使用 Spring Security 在 Grails 上进行摘要认证：

1.  在命令提示符中运行以下命令：

```java
$grails create-app grailsdigestauthexample
$cd grailsdigestauthexample
$grails install-plug-in spring-security-core
$grails s2-quickstart com.packt SecuredUser SecuredRole
$grails create-controller SecuredPackt

```

1.  将以下内容添加到 `config.groovy` 文件并编辑 `Bootstrap.groovy` 文件：

```java
import com.packt.*;
class BootStrap {
  def init = { servletContext ->
    def userRole = SecuredRole.findByAuthority("ROLE_USER") ?: new SecuredRole(authority: "ROLE_USER").save(flush: true)
    def user = SecuredUser.findByUsername("anjana") ?: new SecuredUser(username: "anjana", password: "anjana123", enabled: true).save(flush: true)
    SecuredUserSecuredRole.create(user, userRole, true)
  }
  def destroy = {
  }
}
```

1.  编辑 `SecuredPacktController` 文件并添加注解：

```java
package grailsdigestauthexample
import grails.plugins.springsecurity.Secured
class SecuredPacktController {
  @Secured(['ROLE_USER'])
  def index() { 
  render "Hello PACKT"
  }
}
```

Grails 与 Spring Security 插件需要传递用户名作为盐值。

我们需要对生成的 `SecuredUser.groovy` 文件进行一些调整。

1.  更新 `SecuredUser.groovy` 文件，如下所示：

```java
package com.packt
class SecuredUser {
 transient passwordEncoder

  String username
  String password
  boolean enabled
  boolean accountExpired
  boolean accountLocked
  boolean passwordExpired

  static constraints = {
    username blank: false, unique: true
    password blank: false
  }

  static mapping = {
    password column: '`password`'
  }

  Set<SecuredRole> getAuthorities() {
    SecuredUserSecuredRole.findAllBySecuredUser(this).collect { it.securedRole } as Set
  }

  def beforeInsert() {
    encodePassword()
  }

  def beforeUpdate() {
    if (isDirty('password')) {
      encodePassword()
    }
  }

  protected void encodePassword() {
    password = passwordEncoder.encodePassword(password,       username)
  }
}
```

显示已登录用户：

```java
<!DOCTYPE html>
<html>
  <head>
    <meta name="layout" content="main"/>
    <title>Welcome to Grails</title>

  </head>
  <body>

    <div id="page-body" role="main">
      <h1>Welcome to Grails</h1>

        <sec:ifLoggedIn>
        Hello <sec:username/>
        Access the 
        <g:link controller='securedPackt' action=''>Secured Controller</g:link><br/>
        <g:link controller='logout' action=''>Spring Logout</g:link>
        </sec:ifLoggedIn>

        <sec:ifNotLoggedIn>
          <h2>You are seeing a common page.You can click on login. After login success you will be provided with the links which you can access.</h2>
        <g:link controller='securedPackt' action=''>Secured Controller</g:link><br/>

        </sec:ifNotLoggedIn>
    </div>
    </div>
  </body>
</html>
```

## 它是如何工作的...

当用户访问 URL `http://localhost:8080/grailsdigestauthexample/` 时，Spring Security 将提示用户一个登录对话框，要求输入用户名和密码。当用户输入用户名和密码时，Spring Security 对其进行身份验证，并将用户重定向到受保护的页面。

应用程序的工作流程如下：

`http://localhost:8080/grailsdigestauthexample/`

以下截图描述了尝试访问受保护资源时弹出的登录对话框：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_08.jpg)

它的工作方式类似于基本认证。

成功登录后，您将获得一个注销链接。用户现在已经可以访问受保护的控制器：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_09.jpg)

显示已登录用户：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_10.jpg)

## 另请参阅

+   *Spring Security with Groovy Grails multilevel authentication* 食谱

+   *Spring Security with Groovy Grails LDAP authentication* 食谱

# Spring Security with Groovy Grails multiple authentication

到目前为止，我们已经看到了单角色认证。让我们看看多角色的演示。该食谱使用了另一个名为 `spring-security-ui` 的插件。

它有许多控制器，为用户提供用户管理屏幕。

这样可以节省开发人员编写这些屏幕的时间。它还提供了带自动完成的搜索选项。

`spring-security-ui` 插件还需要安装其他插件，将在控制台提示。还有一种安装插件的替代方法，即可以直接在 `BuildConfig.groovy` 文件中给出依赖项。

```java
grails.project.dependency.resolution = {
  ...
  plugins {
    compile ":spring-security-ui:0.2""
  }
}
```

## 准备工作

我们需要执行以下操作以实现多级身份验证：

+   创建一个 Grails 应用

+   安装`spring-security-core`插件

+   安装`spring-security-ui`插件

+   使用`quickstart`命令创建`Role`和`User`领域类

+   创建`Sample`控制器

+   编辑`BootStrap.groovy`文件

+   编辑`SampleController`类以添加角色

+   更新`.gsp`文件

## 如何做…

实施多重身份验证的以下步骤使用 Groovy on Grails 和 Spring Security：

1.  转到 Grails 工作区并运行以下命令：

+   `grails create-app multilevelroledemo`

+   `cd multilevelroledemo`

+   `grails install-plugin spring-security-core`

+   使用`grails install-plugin spring-security-ui`命令安装插件

+   使用`grails s2-quickstart com.packt.security SecuredUser SecuredRole`命令

+   `grails create-controller Sample`

1.  编辑`SampleController`文件：

```java
package multilevelroledemo
import grails.plugins.springsecurity.Secured
class SampleController {

  def index = {}

  @Secured(['ROLE_USER'])
  def user = {
    render 'Secured for ROLE_USER'
  }

  @Secured(['ROLE_ADMIN'])
  def admin = {
    render 'Secured for ROLE_ADMIN'
  }

  @Secured(['ROLE_SUPERADMIN'])
  def superadmin = {
    render 'Secured for ROLE_SUPERADMIN'
  }
}
```

1.  编辑`BootStrap.groovy`文件。我已添加了多个角色。这些角色和用户将从生成的领域 groovy 文件中创建：

```java
import com.packt.security.SecuredRole
import com.packt.security.SecuredUser
import com.packt.security.SecuredUserSecuredRole
class BootStrap {
  def init = { servletContext ->
    def userRole = SecuredRole.findByAuthority("ROLE_USER") ?: new SecuredRole(authority: "ROLE_USER").save(flush: true)
    def user = SecuredUser.findByUsername("anjana") ?: new SecuredUser(username: "anjana", password: "anjana123", enabled: true).save(flush: true)
    SecuredUserSecuredRole.create(user, userRole, true)

    def userRole_admin = SecuredRole.findByAuthority("ROLE_ADMIN") ?: new SecuredRole(authority: "ROLE_ADMIN").save(flush: true)
    def user_admin = SecuredUser.findByUsername("raghu") ?: new SecuredUser(username: "raghu", password: "raghu123", enabled: true).save(flush: true)
    SecuredUserSecuredRole.create(user_admin, userRole_admin, true)

    def userRole_superadmin = SecuredRole.findByAuthority("ROLE_SUPERADMIN") ?: new SecuredRole(authority: "ROLE_SUPERADMIN").save(flush: true)
    def user_superadmin = SecuredUser.findByUsername("packt") ?: new SecuredUser(username: "packt", password: "packt123", enabled: true).save(flush: true)
    SecuredUserSecuredRole.create(user_superadmin, userRole_superadmin, true)
  }
  def destroy = {
  }
}
```

1.  修改`.gsp`文件。在`views/sample`中添加一个`index.gsp`文件：

```java
<head>
  <meta name='layout' content='main' />
  <title>Multi level  Roles in Grails</title>
</head>

<body>
  <div class='nav'>
    <span class='menuButton'><a class='home' href='${createLinkTo(dir:'')}'>Home</a></span>
  </div>
  <div class='body'>
    <g:link action='user'> ROLE_USER</g:link><br/>
    <g:link action='admin'>ROLE_ADMIN</g:link><br/>
    <g: link action='superadmin'> ROLE_SUPERADMIN</g:link><br/>
  </div>
</body>
```

1.  在`config`文件夹中添加`SecurityConfig.groovy`文件：

```java
security {
  active = true
  loginUserDomainClass = 'com.packt.security.SecuredUser'
  authorityDomainClass = 'com.packt.security.SecuredPackt'
  useRequestMapDomainClass = false
  useControllerAnnotations = true
}
```

## 它是如何工作的…

让我们看看它是如何工作的。我们还将看到`spring-security-ui`提供的控制器及其功能。

我们在这里有三个具有不同角色的用户。它们是在`Bootstrap.groovy`文件中使用领域类创建的：

+   `anjana`/`anjana123` 作为 `ROLE_USER`

+   `raghu`/`raghu123` 作为 `ROLE_ADMIN`

+   `packt`/`packt123` 作为 `ROLE_SUPERADMIN`

访问 URL：`http://localhost:8080/multilevelroledemo/`。

您将看到 Grails 主页以及控制器列表。

单击**spring.security.ui.usercontroller**链接。该控制器属于`spring-security-ui`插件。该控制器提供了用户管理屏幕。该控制器为用户提供了搜索功能。这是一个很棒的 UI，它甚至具有带有搜索过滤器的自动完成选项。您可以转到以下链接：

`http://localhost:8080/multilevelroledemo/user/search`

下面的截图显示了 Spring 用户管理控制台，您可以在其中看到搜索用户的选项：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_11.jpg)

让我们看一下搜索结果，如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_12.jpg)

现在让我们检查`spring-security-ui`插件中提供的角色控制器。该控制器提供了搜索角色的选项，并提供了角色与用户的映射。它还提供了更新角色的选项：

`http://localhost:8080/multilevelroledemo/role/roleSearch`

您还可以创建用户，该选项可在菜单中找到。访问以下链接创建用户：

`http://localhost:8080/multilevelroledemo/user/create`

让我们看看我们为应用程序创建的示例控制器：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_13.jpg)

以下 URL 显示了具有各种角色的示例控制器映射。这也是`spring-security-ui`插件提供的：

`http://localhost:8080/multilevelroledemo/securityInfo/mappings`

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_14.jpg)

让我们访问`http://localhost:8080/multilevelroledemo/sample/index`的示例控制器。

它显示了三个角色。单击链接，您将被提示登录。

使用适当的用户名和密码登录，您的角色信息将被显示。

`spring-security-ui`插件本身提供了登录和注销的选项，适用于整个应用程序。

我们只能使用注解，即`@Secured`注解来对用户进行身份验证和授权以执行某些操作。

我们还可以省略在`Bootstrap.groovy`中创建用户。

## 另请参阅

+   *Groovy Grails LDAP 身份验证的 Spring 安全*配方

# Groovy Grails LDAP 身份验证的 Spring 安全

让我们进一步探索使用 LDAP 身份验证的 Groovy on Grails 上的`spring-security`插件。在这个示例中，我在我的机器上安装了**Apache DS**和 Apache Studio。我将使用这个进行身份验证。

Burt Beckwith 在此方面写了非常好的博客。您可以在以下网址查看：[`burtbeckwith.com/blog/`](http://burtbeckwith.com/blog/)

## 准备工作

+   创建一个 Grails 应用程序：`grailssecurityldapexamplex`。

+   让我们创建一个控制器：`SampleController`。

+   安装以下插件：

+   `spring-security-core`

+   `spring-security-ldap`

+   编辑`Config.groovy`文件。

+   我们将在成功验证后显示角色和用户详细信息。在这个示例中，我们将根据电子邮件地址和密码对用户进行身份验证。

+   我们需要在`Config.groovy`中提供 Apache DS 详细信息和端口号。

+   我正在使用一个单独的分区`sevenseas`。您可以通过添加一个单独的`jdmpartition`来创建自己的域。

+   有两种角色：用户和管理员。角色与 Apache DS 中的用户映射。我在 Apache DS 中创建了两个“组织单位”：

+   **people**：这将有用户

+   **groups**：这将具有映射到它的用户的角色

+   我从 Apache DS 获取`username`，`role`和`email`。

## 如何做…

采取以下步骤来使用 Grails 实现`spring-security`与 LDAP 进行身份验证：

1.  安装以下命令以安装插件：

+   `create-app grailssecurityldapexample`

+   `cd grailssecurityldapexample`

+   `grails install-plugin spring-security-core`

+   `grails install-plugin spring-security-ldap`

+   `grails create-controller Sample`

1.  让我们首先更新`message.properties`文件以获得清晰的 UI：

```java
springSecurity.login.header=Spring Security login
springSecurity.login.username.label=UserName
springSecurity.login.password.label=Password
springSecurity.login.remember.me.label=remember me
springSecurity.login.button=Login
springSecurity.errors.login.fail=Authentication failed
```

然后在`Config.groovy`文件中配置 Apache DS 属性。

1.  此配置将告诉 Grails 根据其电子邮件 ID 对用户进行身份验证：

```java
grails.plugins.springsecurity.ldap.search.filter = '(mail={0})'
grails.plugins.springsecurity.ldap.context.server = 'ldap://localhost:10389/o=sevenSeas'
grails.plugins.springsecurity.ldap.context.managerDn = 'uid=admin,ou=system'
grails.plugins.springsecurity.ldap.context.managerPassword = 'secret'
grails.plugins.springsecurity.ldap.authorities.groupSearchBase ='ou=groups'
grails.plugins.springsecurity.ldap.authorities.groupSearchFilter = '(uniqueMember={0})'
grails.plugins.springsecurity.ldap.authorities.retrieveDatabaseRoles = false
grails.plugins.springsecurity.ldap.authorities.ignorePartialResultException= true
grails.plugins.springsecurity.ldap.search.base = 'ou=people'
grails.plugins.springsecurity.ldap.search.filter = '(mail={0})'
grails.plugins.springsecurity.ldap.search.attributesToReturn = ['cn', 'sn','mail']
grails.plugins.springsecurity.ldap.authenticator.attributesToReturn = ['cn', 'sn','mail']
```

1.  编辑控制器：

```java
package grailssecurityldapexample
class SampleController {
  def index() { 
    render "Hello PACKT"
    }
}
```

1.  编辑`resource.groovy`文件以进行 Bean 映射。

```java
beans = { 
ldapUserDetailsMapper(MyUserDetailsContextMapper) { 
}
}
```

1.  用以下代码替换`index.gsp`的现有`body`标记：

```java
<body>
  <a href="#page-body" class="skip"><g:message code="default.link.skip.label" default="Skip to content&hellip;"/></a>

  <div id="page-body" role="main">
      <h1>Welcome to Grails</h1>
      <sec:ifLoggedIn>
Your Details<br/>
      Name:<sec:loggedInUserInfo field="fullname"/> <br/>
      Email:<sec:loggedInUserInfo field="email"/> <br/>
      Role:<sec:loggedInUserInfo field="title"/> <br/>
      <g:link controller='sample' action=''>Sample Controller</g:link><br/>
      (<g:link controller="logout">Logout</g:link>)
     </sec:ifLoggedIn> 
     <sec:ifNotLoggedIn>
      <h2>You are seeing a common page. You can click on login. After login success you will be provided with the links which you can access.</h2>
      <g:link controller='login' action='auth'>Spring Login</g:link>
      </sec:ifNotLoggedIn>

    </div>
  </body>
```

1.  在`src/groovy`下创建`MyUserDetails.groovy`：

```java
import org.springframework.security.core.GrantedAuthority 
import org.springframework.security.core.userdetails.User

class MyUserDetails extends User {   
 String fullname 
 String email 
 String title 

MyUserDetails(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection authorities, String fullname,
String email, String title) {  
  super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities)
this.fullname = fullname 
this.email = email 
this.title = title 
}
}
```

1.  让我们为 LDAP 创建一个`ContextMapper`。

我们在这里获取 LDAP 属性：

```java
import org.springframework.ldap.core.DirContextAdapter
import org.springframework.ldap.core.DirContextOperations
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper
class MyUserDetailsContextMapper implements UserDetailsContextMapper {
    UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection authorities) {
      String fullname = ctx.originalAttrs.attrs['cn'].values[0]
      String email = ctx.originalAttrs.attrs['mail'].values[0].toString().toLowerCase() 
      def title = ctx.originalAttrs.attrs['sn']
      def userDetails = new MyUserDetails(username, '', true, true, true, true,authorities, fullname,email,  title == null ? '' : title.values[0])
      return userDetails
    }
    void mapUserToContext(UserDetails user,
		DirContextAdapter ctx) {
			throw new IllegalStateException("Only retrieving
				data from LDAP is currently supported")
    }

}
```

执行以下命令以启动应用程序：

```java
grails run-app

```

## 它是如何工作的…

当用户访问 URL：`http://localhost:8080/grailssecurityldapexample/`时，他们将看到一个带有链接的常规页面。在登录表单中输入用户名和密码。单击**提交**，Grails 将 URL 提交给 Spring Security。Spring Security 连接提供的 LDAP 详细信息并查询 LDAP 以获取用户名。成功后，用户将被重定向到成功的 URL。

访问 URL：`http://localhost:8080/grailssecurityldapexample/`。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_15.jpg)

单击**Spring 登录**链接，输入用户名：`admin@test.com`和密码：`123456`。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_16.jpg)

单击**注销**。

单击**Spring 登录**链接，输入用户名：`test@test.com`和密码：`pass`。Grails 应用程序将凭据提交给 Spring Security 框架，后者查询 LDAP 并检索用户详细信息，并在安全页面上显示它：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_04_17.jpg)

## 另请参阅

+   第六章，*使用 Vaadin 的 Spring 安全性*

+   第五章，*使用 GWT 的 Spring 安全性*


# 第五章：使用 GWT 的 Spring Security

在本章中，我们将涵盖：

+   使用 Spring Security Beans 进行 GWT 身份验证的 Spring Security

+   使用 GWT 和 Spring Security 进行基于表单的身份验证

+   使用 GWT 和 Spring Security 进行基本身份验证

+   使用 GWT 和 Spring Security 进行摘要身份验证

+   使用 GWT 和 Spring Security 进行数据库身份验证

+   使用 GWT 和 Spring Security 进行 LDAP 身份验证

# 介绍

**Google Web 开发工具包**（**GWT**）提供了一个用于开发 Java Web 应用程序的标准框架。GWT 旨在创建丰富的互联网应用程序，并且如果您想要实现跨浏览器兼容性，它将是一个很好的选择。现代浏览器，例如 Mozilla 和 Chrome，提供了可以安装在所有浏览器上的 GWT 插件。不同的 IDE 包括 Eclipse、NetBeans 和许多其他 IDE 都提供了各种插件。这些插件提高了开发速度。Eclipse 的 GWT 插件带有一个内部 Jetty 服务器，应用程序会自动部署在上面。GWT 还减少了对 javascript 开发人员的依赖，因为 GWT 代码通过 GWT 编译器转换为所有浏览器兼容的 javascript 和 HTML。

在本章中，我们将演示使用各种方法集成 GWT 的 Spring Security。首先，让我们进行基本设置。这就是下载插件并创建一个示例 GWT 项目。

# 使用 Spring Security Beans 进行 GWT 身份验证的 Spring Security

到目前为止，在我们之前的所有演示中，我们一直在`applicationContext.xml`文件中提供配置。在下面的示例中，我们将采用不同的方法。在这种方法中，我们将看到如何使用 Spring Security API 中可用的身份验证提供程序接口和身份验证接口来进行身份验证。

默认情况下，GWT 插件将创建一个问候应用程序，该应用程序将通过接受用户名来向用户问候。我们的目标是在此基础上应用安全性。我们希望在启动时提示用户输入 Spring Security 登录页面，然后将用户带入应用程序。

## 准备就绪

+   从[`dl.google.com/eclipse/plugin/3.7`](http://dl.google.com/eclipse/plugin/3.7)下载 Eclipse Indigo。

+   如果您使用不同的插件，请访问：[`developers.google.com/eclipse/docs/download`](https://developers.google.com/eclipse/docs/download)。

+   在 Eclipse 中创建一个 GWT Web 项目-这将生成一个默认的 GWT 应用程序，用于向用户问候。

+   在任何 GWT 应用程序中，您可以看到以下模块：

+   **配置模块**：这将有`gwt.xml`文件

+   **客户端**：这将有两个接口-异步接口和另一个接口，它扩展了*RemoteService*接口

+   **服务器**：将具有实现客户端接口并扩展远程服务 Servlet 的`Implementation`类

+   **共享**：这将有用于数据验证的类

+   **测试**：您可以在这里添加您的 junit 测试用例

+   **War**：这将有`web-inf`文件夹

+   在内部服务器上运行应用程序。您将获得一个 URL。

+   在 Mozilla Firefox 浏览器中打开 URL；您将收到一个提示，要下载 GWT 插件并安装它。

+   您将被提示输入用户名，输入后，您将收到一个对话框，其中将显示用户详细信息。

+   我们的目标是在应用程序启动时应用安全性，也就是说，我们希望识别访问 GWT 应用程序的用户。

+   创建一个`applicationContext.xml`文件。必须将其命名为`applicationContext`，否则我们将在控制台中收到错误消息。

+   使用 spring 监听器编辑`web.xml`文件。

+   确保`war/web-inf/lib`文件夹中有以下 JAR 文件：

+   `gwt-servlet`

+   `spring-security-config-3.1.4.Release`

+   `spring-security-core-3.1.4.Release`

+   `spring-security-web-3.1.4.Release`

+   `org.spring-framework.core-3.1.4.Release`

+   `org.spring-framework.context.support-3.1.4.Release`

+   `org.springframework.context-3.1.4.Release`

+   `org.springframework.expression-3.1.4.Release`

+   `org.springframework.aop-3.1.4.Release`

+   `org.springframework.aspects-3.1.4.Release`

+   `org.springframework.asm-3.1.4.Release`

+   `org.springframework.web-3.1.4.Release`

+   `org.springframework.web.servelet-3.1.4.Release`

+   `org.springframework.instrument-3.1.4.Release`

+   `org.springframework.instrument-tomcat-3.1.4.Release`

## 如何做...

1.  使用 Spring 监听器和 Spring 过滤器更新`Web.xml`文件：

```java
<filter>
  <filter-name>springSecurityFilterChain</filter-name>
  <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
  <filter-name>springSecurityFilterChain</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>

<listener>
  <listener-class>
  org.springframework.web.context.ContextLoaderListener
  </listener-class>
</listener>
```

您可以观察到我们没有像在以前的应用程序中那样配置`<context-param>`。Spring 将自动寻找`applicationContext.xml`文件。

1.  编辑`applicationContext.xml`文件：

```java
<http auto-config="true">
  <intercept-url pattern="/xyz/**" access="ROLE_AUTHOR"/>
  <intercept-url pattern="/xyz/**" access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**/*.html" access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**" 
    access="IS_AUTHENTICATED_ANONYMOUSLY" />
</http>
<beans:bean id="packtAuthenticationListener" 
  class="com.demo.xyz.server.PacktAuthenticationListener"/>
<beans:bean id="packtGWTAuthenticator" 
  class="com.demo.xyz.server.PacktGWTAuthenticator" />    
<authentication-manager alias="authenticationManager">
  <authentication-provider ref="packtGWTAuthenticator"/>
</authentication-manager>
</beans:beans>
```

这个配置也会给出下一步的提示。您可以观察到我们没有配置任何`<login-page>`或其 URL。我们只给出了需要安全的 URL。`<authentication-provider>`与自定义类映射。

我们还配置了两个 Bean，即监听器和认证者。

Spring 的上下文 API 允许我们创建监听器来跟踪应用程序中的事件。如果您回忆一下，我们还在我们的 JSF 应用程序中使用了监听器阶段监听器来跟踪与安全相关的事件和错误。

`PacktGWTAuthenticator`实现了认证提供程序接口。

1.  使用 Spring 认证提供程序创建一个认证者：

```java
Package com.demo.xyz.server
public class PacktGWTAuthenticator implements AuthenticationProvider{
  static Users users=new Users();
  private static Map<String, String> usersMap =users.loadUsers();

  @Override
  public Authentication authenticate
    (Authentication authentication) 
  throws AuthenticationException {

    String mylogin_name = (String) authentication.getPrincipal();
    String mypassword = (String)authentication.getCredentials();
    //check username
    if (usersMap.get(mylogin_name)==null)
    throw new UsernameNotFoundException
      (mylogin_name+"credential not found in the UsersMap");
//get password
    String password = usersMap.get(mylogin_name);

    if (!password.equals(mypassword))
      throw new BadCredentialsException("Incorrect password-
        or credential not found in the UsersMap");

      Authentication packtauthenticator =  new 
        PacktGWTAuthentication("ROLE_AUTHOR", authentication);
      packtauthenticator .setAuthenticated(true);

      return packtauthenticator;

    }

    @Override
    public boolean supports(Class<? extends Object>
       authentication) {
    return UsernamePasswordAuthenticationToken.class
      .isAssignableFrom(authentication);
  }
}
```

在这里，`authenticate()`和`supports()`是认证提供程序接口方法。用户类将加载用户。

1.  创建一个`User`类来加载用户：

```java
package com.demo.xyz.server;
import java.util.HashMap;
import java.util.Map;
public class Users {
  public Map<String, String> getUsersMap() {
    return usersMap;
  }

  public void setUsersMap(Map<String, String> usersMap) {

    this.usersMap = usersMap;
  }

  private Map<String, String> usersMap = new HashMap
    <String, String>();

  public Map<String, String> loadUsers(){
    usersMap.put("rashmi", "rashmi123");
    usersMap.put("shami", "shami123");
    usersMap.put("ravi", "ravi123");
    usersMap.put("ratty", "ratty123");
    return usersMap;
  }

}
```

上述类有一些 getter 和 setter。还有一个加载用户的方法。

1.  实现 Spring 认证类以获取用户信息：

```java
public class PacktGWTAuthentication implements Authentication{

  private static final long serialVersionUID = -3091441742758356129L;

  private boolean authenticated;

  private GrantedAuthority grantedAuthority;
  private Authentication authentication;

  public PacktGWTAuthentication(String role, Authentication authentication) {
    this.grantedAuthority = new GrantedAuthorityImpl(role);
    this.authentication = authentication;
  }

  @Override
  public Object getCredentials() {
    return authentication.getCredentials();
  }

  @Override
  public Object getDetails() {
    return authentication.getDetails();
  }

  @Override
  public Object getPrincipal() {
    return authentication.getPrincipal();
  }

  @Override
  public boolean isAuthenticated() {
    return authenticated;
  }

  @Override
  public void setAuthenticated(boolean authenticated)throws IllegalArgumentException {
    this.authenticated = authenticated;
  }

  @Override
  public String getName() {
    return this.getClass().getSimpleName();
  }
  @Override
  public Collection<GrantedAuthority> getAuthorities() {
    Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
    authorities.add(granted Authority);
    return authorities;
  }

}
```

认证接口处理用户详细信息、主体和凭据。认证提供程序使用此类传递角色信息。

1.  实现在 GWT 客户端包中声明的接口：

```java
package com.demo.xyz.server;
public class PacktAuthenticatorServiceImpl extends RemoteServiceServlet  implements PacktAuthenticatorService {

  @Override
  public String authenticateServer() {
  Authentication authentication =SecurityContextHolder.getContext().getAuthentication();
  if (authentication==null){
    System.out.println("looks like you have not logged in.");
    return null;
  }
  else {
    System.out.println(authentication.getPrincipal().toString());
    System.out.println(authentication.getName().toString());
    System.out.println(authentication.getDetails().toString());
    return (String) authentication.getPrincipal();
    }

  }

}
```

在这个类中找到`authenticate Server`方法的实现。这将打印调试语句以检查用户是否已登录。如果已登录，那么我们将必须获取主体和用户详细信息。

1.  使用 Spring 监听器跟踪事件：

```java
package com.demo.xyz.server;
public class PacktAuthenticationListener implements 
  ApplicationListener<AbstractAuthenticationEvent>{
  @Override
  public void onApplicationEvent
    (AbstractAuthenticationEvent event) {

    final StringBuilder mybuilder = new StringBuilder();
    mybuilder.append("AN AUHTHENTICATION EVENT ");
    mybuilder.append(event.getClass().getSimpleName());
    mybuilder.append("*** ");
    mybuilder.append(event.getAuthentication().getName());
    mybuilder.append("$$$DETAILS OF THE EVENT: ");
    mybuilder.append(event.getAuthentication().getDetails());

    if (event instanceof 
      AbstractAuthenticationFailureEvent) {
      mybuilder.append("$$$ EXCEPTION HAS OCCURED: ");
      mybuilder.append(((AbstractAuthenticationFailureEvent)
       event).getException().getMessage());
    }
    System.out.println(mybuilder.toString());
  }
}
```

该类实现了 Springs 应用程序监听器，类型为`AbstractAuthenticationEvent`。我们捕获认证事件并在控制台中打印出来；您也可以使用记录器来跟踪此类事件。

1.  在`ModuleLoad()`上更新 GWT 类：

```java
package com.demo.xyz.client;

/**
 * Entry point classes define <code>onModuleLoad()</code>.
 */
public class Xyz implements EntryPoint {
/**
 * The message displayed to the user when the server cannot be reached or
 * returns an error.
 */
private static final String SERVER_ERROR = 
  "An error occurred while "+ "attempting to contact
   the server. Please check your network "
  + "connection and try again.";

/**
 * Create a remote service proxy to talk to the server-side Greeting service.
 */
private final GreetingServiceAsync greetingService = 
  GWT.create(GreetingService.class);
private final PacktAuthenticatorServiceAsync 
  packtAuthenticatorService = 
  GWT.create(PacktAuthenticatorService.class);
/**
 * This is the entry point method.
 */
public void onModuleLoad() {
  final Button sendButton = new Button("Send");
  final TextBox nameField = new TextBox();
  nameField.setText("GWT User");
  final Label errorLabel = new Label();
  sendButton.addStyleName("sendButton");
  RootPanel.get("nameFieldContainer").add(nameField);
  RootPanel.get("sendButtonContainer").add(sendButton);
  RootPanel.get("errorLabelContainer").add(errorLabel);

// Focus the cursor on the name field when the app loads
  nameField.setFocus(true);
  nameField.selectAll();

  // Create the popup dialog box
  final DialogBox dialogBox = new DialogBox();
  dialogBox.setText("Remote Procedure Call");
  dialogBox.setAnimationEnabled(true);
  final Button closeButton = new Button("Close");
// We can set the id of a widget by accessing its Element
  closeButton.getElement().setId("closeButton");
  final Label textToServerLabel = new Label();
  final HTML serverResponseLabel = new HTML();
  VerticalPanel dialogVPanel = new VerticalPanel();
  dialogVPanel.addStyleName("dialogVPanel");
  dialogVPanel.add(new HTML
    ("<b>Sending name to the server:</b>"));
  dialogVPanel.add(textToServerLabel);
  dialogVPanel.add(new HTML("<br><b>Server replies:</b>"));
  dialogVPanel.add(serverResponseLabel);
  dialogVPanel.setHorizontalAlignment
    (VerticalPanel.ALIGN_RIGHT);
dialogVPanel.add(closeButton);
dialogBox.setWidget(dialogVPanel);

  // Add a handler to close the DialogBox
  closeButton.addClickHandler(new ClickHandler() {
    public void onClick(ClickEvent event) {
      dialogBox.hide();
      sendButton.setEnabled(true);
      sendButton.setFocus(true);
    }
  });

  // Create a handler for the sendButton and nameField
  class MyHandler implements ClickHandler, KeyUpHandler {

  public void onClick(ClickEvent event) {
    sendNameToServer();
  }

  public void onKeyUp(KeyUpEvent event) {
    if (event.getNativeKeyCode() == KeyCodes.KEY_ENTER) {
      sendNameToServer();
    }
  }

  /**
   * Send the name from the nameField to the server and wait for a response.
   */
  private void sendNameToServer() {
  // First, we validate the input.
  errorLabel.setText("");
  String textToServer = nameField.getText();
  if (!FieldVerifier.isValidName(textToServer)) {
    errorLabel.setText("Please enter at least four 
      characters");
    return;
    }

// Then, we send the input to the server.
    sendButton.setEnabled(false);
    textToServerLabel.setText(textToServer);
    serverResponseLabel.setText("");
    greetingService.greetServer(textToServer,
    new AsyncCallback<String>() {
      public void onFailure(Throwable caught) {
        // Show the RPC error message to the user dialogBox
        setText("Remote Procedure Call - Failure");
        serverResponseLabel.addStyleName
          ("serverResponseLabelError");
        serverResponseLabel.setHTML(SERVER_ERROR);
        dialogBox.center();
        closeButton.setFocus(true);
      }

      public void onSuccess(String result) {
        dialogBox.setText("Remote Procedure Call");
        serverResponseLabel.removeStyleName
          ("serverResponseLabelError");
        serverResponseLabel.setHTML(result);
        dialogBox.center();
        closeButton.setFocus(true);
      }
    });
  }
}

// Add a handler to send the name to the server
MyHandler handler = new MyHandler();
sendButton.addClickHandler(handler);
nameField.addKeyUpHandler(handler);
packtAuthenticatorService.authenticateServer(new AsyncCallback<String>() {
  public void onFailure(Throwable caught) {
    dialogBox.setText("Remote Procedure Call - Failure");
  }
  public void onSuccess(String result) {
    nameField.setText(result);
  }
}
);
}
}
```

在`onModuleLoad`方法的末尾添加此代码。这类似于在加载时注册我们的服务。

1.  编辑`PacktAuthenticationService`类：

```java
package com.demo.xyz.client;

/**
* Entry point classes define <code>onModuleLoad()</code>.
*/
public class Xyz implements EntryPoint {
  /**
   * The message displayed to the user when the server cannot be reached or
   * returns an error.
   */
  private static final String SERVER_ERROR = 
    "An error occurred while "+ "attempting to contact
     the server. Please check your network "
    + "connection and try again.";

  /**
   * Create a remote service proxy to talk to the server-side Greeting service.
   */
  private final GreetingServiceAsync greetingService
     = GWT.create(GreetingService.class);
  private final PacktAuthenticatorServiceAsync 
    packtAuthenticatorService = 
    GWT.create(PacktAuthenticatorService.class);
  /**
   * This is the entry point method.
   */
  public void onModuleLoad() {
    final Button sendButton = new Button("Send");
    final TextBox nameField = new TextBox();
    nameField.setText("GWT User");
    final Label errorLabel = new Label();

    // We can add style names to widgets
    sendButton.addStyleName("sendButton");

    // Add the nameField and sendButton to the RootPanel
    // Use RootPanel.get() to get the entire body element
    RootPanel.get("nameFieldContainer").add(nameField);
    RootPanel.get("sendButtonContainer").add(sendButton);
    RootPanel.get("errorLabelContainer").add(errorLabel);

    // Focus the cursor on the name field when the app loads nameField.setFocus(true);
    nameField.selectAll();

    // Create the popup dialog box
    final DialogBox dialogBox = new DialogBox();
    dialogBox.setText("Remote Procedure Call");
    dialogBox.setAnimationEnabled(true);
    final Button closeButton = new Button("Close");
    //We can set the id of a widget by accessing its Element
    closeButton.getElement().setId("closeButton");
    final Label textToServerLabel = new Label();
    final HTML serverResponseLabel = new HTML();
    VerticalPanel dialogVPanel = new VerticalPanel();
    dialogVPanel.addStyleName("dialogVPanel");
    dialogVPanel.add(new HTML
      ("<b>Sending name to the server:</b>"));
    dialogVPanel.add(textToServerLabel);
    dialogVPanel.add(new HTML("<br><b>Server replies:</b>"));
    dialogVPanel.add(serverResponseLabel);
    dialogVPanel.setHorizontalAlignment
      (VerticalPanel.ALIGN_RIGHT);
    dialogVPanel.add(closeButton);
    dialogBox.setWidget(dialogVPanel);

    // Add a handler to close the DialogBox
    closeButton.addClickHandler(new ClickHandler() {
      public void onClick(ClickEvent event) {
        dialogBox.hide();
        sendButton.setEnabled(true);
        sendButton.setFocus(true);
      }
    });

    // Create a handler for the sendButton and nameField
    class MyHandler implements ClickHandler, KeyUpHandler {
      /**
       * Fired when the user clicks on the sendButton.
       */
      public void onClick(ClickEvent event) {
        sendNameToServer();
      }

      /**
       * Fired when the user types in the nameField.
       */
      public void onKeyUp(KeyUpEvent event) {
        if (event.getNativeKeyCode() == KeyCodes.KEY_ENTER) {
          sendNameToServer();
        }
      }

        /**
         * Send the name from the nameField to the server and wait for a response.
         */
        private void sendNameToServer() {
        // First, we validate the input.
        errorLabel.setText("");
        String textToServer = nameField.getText();
        if (!FieldVerifier.isValidName(textToServer)) {
          errorLabel.setText("Please enter at least
             four characters");
          return;
        }

        // Then, we send the input to the server.
        sendButton.setEnabled(false);
        textToServerLabel.setText(textToServer);
        serverResponseLabel.setText("");
        greetingService.greetServer(textToServer,
        new AsyncCallback<String>() {
          public void onFailure(Throwable caught) {
            // Show the RPC error message to the user
          dialogBox.setText("Remote Procedure Call
             - Failure");
          serverResponseLabel.addStyleName
            ("serverResponseLabelError");
          serverResponseLabel.setHTML(SERVER_ERROR);
          dialogBox.center();
          closeButton.setFocus(true);
        }

        public void onSuccess(String result) {
        dialogBox.setText("Remote Procedure Call");
        serverResponseLabel.removeStyleName
          ("serverResponseLabelError");
        serverResponseLabel.setHTML(result);
        dialogBox.center();
        closeButton.setFocus(true);
      }
    });
  }
}

// Add a handler to send the name to the server
MyHandler handler = new MyHandler();
sendButton.addClickHandler(handler);
nameField.addKeyUpHandler(handler);
packtAuthenticatorService.authenticateServer(new AsyncCallback<String>() {
  public void onFailure(Throwable caught) {
  dialogBox.setText("Remote Procedure Call - Failure");
}
public void onSuccess(String result) {
  nameField.setText(result);
}
}
);
}
}
```

## 它是如何工作的...

现在访问以下 URL：

`http://127.0.0.1:8888/Xyz.html?gwt.codesvr=127.0.0.1:9997`

用户将被重定向到 Spring Security 内部登录页面。当用户输入**用户**和**密码**并点击提交时，`PacktGWTAuthenticator`类从`Users`类中加载用户，并比较输入。如果映射具有与用户提供的相同的凭据，授权将被启动，并且成功后，用户将被引导到 GWT 应用程序。该示例已经显式使用了 Spring Security 的`Authentication Provider`和`Authenticator Bean`类，通过实现接口和`application-context.xml`调用`PacktGWTAuthenticator`和`PacktGWTAuthentication implementation`类来进行认证和授权。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_05_01.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_05_02.jpg)

成功登录时将看到先前的图像。

Eclipse 控制台中生成的监听器输出：

```java
PacktGWTAuthentication
org.springframework.security.web.authentication.WebAuthenticationDetails@fffdaa08: RemoteIpAddress: 127.0.0.1; SessionId: 1cdb5kk395o29

```

登录失败时显示以下图像：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_05_03.jpg)

## 另请参阅

+   *使用 GWT 和 Spring Security 进行基于表单的身份验证*食谱

+   *使用 GWT 和 Spring Security 进行基本身份验证*食谱

+   *使用 GWT 和 Spring Security 进行摘要身份验证*食谱

+   *使用 GWT 和 Spring Security 进行数据库身份验证*食谱

+   *使用 GWT 和 Spring Security 进行 LDAP 身份验证*食谱

# 使用 GWT 和 Spring Security 进行基于表单的身份验证

我们将演示 GWT 中的基于表单的身份验证。这与我们在以前的配方中所做的身份验证非常相似。我们将编辑`applicationContext.xml`。

## 准备工作

+   创建一个样本 GWT 项目。

+   在构建路径中添加与 spring 相关的 JAR 包。

+   添加与 Spring Security 相关的 JAR 包。

+   添加`applicationContext.xml`文件。

+   按照上一节所示编辑`web.xml`文件。

+   还要在`web-inf lib`文件夹中添加与 spring 相关的 JAR 包。

## 如何做...

编辑`applicationContext.xml`文件：

```java
<http auto-config="true" >
  <intercept-url pattern="/basicgwtauth/**"
     access="ROLE_AUTHOR"/>
        <intercept-url pattern="/basicgwtauth/**" access="ROLE_AUTHOR"/>
        <intercept-url pattern="/**/*.html" access="ROLE_AUTHOR"/>
        <intercept-url pattern="/**" access="IS_AUTHENTICATED_ANONYMOUSLY" />

</http>
<authentication-manager>
  <authentication-provider>
    <user-service>
      <user name="anjana" password="123456" 
      authorities="ROLE_AUTHOR" />
    </user-service>
  </authentication-provider>
</authentication-manager>
```

此配置调用内部 Spring Security 登录表单。其想法是展示另一种情景，在这种情况下我们不指定身份验证机制，而是 spring 默认使用其登录表单页面来对用户进行身份验证。

## 工作原理...

现在访问以下 URL：

`http://127.0.0.1:8888/Basicgwtauth.html?gwt.codesvr=127.0.0.1:9997`

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_05_01.jpg)

输入登录用户名和密码；您将被带到 GWT 页面。这也是一种机制，用于调用 spring 的内部登录 jsp 页面，如果开发人员不想创建自己定制的 jsp。它仍然读取提供的身份验证提供程序详细信息以对用户进行身份验证和授权。

以类似的方式，您也可以通过编辑身份验证管理器配置来使用数据库和 LDAP 进行身份验证。

## 另请参阅

+   使用 GWT 和 Spring Security 进行基本身份验证的配方

+   使用 GWT 和 Spring Security 进行摘要身份验证的配方

+   使用 GWT 和 Spring Security 进行数据库身份验证的配方

+   使用 GWT 和 Spring Security 进行 LDAP 身份验证的配方

# 使用 GWT 和 Spring Security 进行基本身份验证

我们将演示 GWT 中的基本身份验证。这与我们稍后将要做的基本身份验证非常相似。我们将编辑`applicationContext.xml`。

## 准备工作

+   创建一个样本 GWT 项目

+   在构建路径中添加与 spring 相关的 JAR 包

+   添加与 Spring Security 相关的 JAR 包

+   添加`applicationContext.xml`文件

+   按照上一节所示编辑`web.xml`文件

+   还要在`web-inf lib`文件夹中添加与 spring 相关的 JAR 包

## 如何做...

编辑`applicationContext.xml`文件：

```java
<http auto-config="true" >
  <intercept-url pattern="/basicgwtauth/**"
     access="ROLE_AUTHOR"/>
  <intercept-url pattern="/basicgwtauth/**"
     access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**/*.html" access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**"
     access="IS_AUTHENTICATED_ANONYMOUSLY" />
  <http-basic />
</http>
<authentication-manager>
  <authentication-provider>
    <user-service>
      <user name="anjana" password="123456" 
        authorities="ROLE_AUTHOR" />
    </user-service>
  </authentication-provider>
</authentication-manager>
```

在这里，我们将指定基本的身份验证机制。

## 工作原理..

现在访问 URL：

`http://127.0.0.1:8888/Basicgwtauth.html?gwt.codesvr=127.0.0.1:9997`

Spring Security 将阻止用户访问 GWT 应用程序。安全机制将从`application-context.xml`文件中读取。对于此应用程序，安全机制是基本的。Spring Security 将弹出一个对话框，要求输入用户名和密码。用户输入的登录用户名和密码将被验证和授权，用户将被带到 GWT 页面。

![工作原理..](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_05_04.jpg)

输入登录用户名和密码，您将被带到 GWT 页面。

## 另请参阅

+   使用 GWT 和 Spring Security 进行摘要身份验证的配方

+   使用 GWT 和 Spring Security 进行数据库身份验证的配方

+   使用 GWT 和 Spring Security 进行 LDAP 身份验证的配方

# 使用 GWT 和 Spring Security 进行摘要身份验证

我们现在将演示 GWT 中的摘要身份验证。这与我们在以前的配方中所做的基本身份验证非常相似。我们将编辑`applicationContext.xml`。我们将对密码进行哈希处理。设置保持不变，唯一的变化是`applicationcontext.xml`。

## 准备工作

+   创建一个样本 GWT 项目

+   在构建路径中添加与 spring 相关的 JAR 包

+   添加与 Spring Security 相关的 JAR 包

+   添加`applicationContext.xml`文件

+   按照上一节所示编辑`web.xml`文件

+   还要在`web-inf lib`文件夹中添加与 spring 相关的 JAR 包

## 如何做...

编辑`applicationContext.xml`文件：

```java
<http auto-config="true" >
  <intercept-url pattern="/basicgwtauth/**" access="
     ROLE_EDITOR "/>
  <intercept-url pattern="/basicgwtauth/**" access="
     ROLE_EDITOR "/>
  <intercept-url pattern="/**/*.html" access=
    " ROLE_EDITOR "/>
  <intercept-url pattern="/**" access
    ="IS_AUTHENTICATED_ANONYMOUSLY" />
  <http-basic />
</http>
<authentication-manager>
  <authentication-provider>
    <password-encoder hash="sha" />
    <user-service>
      <user name="anjana" 
        password="bde892ed4e131546a2f9997cc94d31e2c8f18b2a" 
      authorities="ROLE_EDITOR" />
    </user-service>
  </authentication-provider>
</authentication-manager>
```

在这里，我们指定身份验证机制为基本，并在此处给出了哈希密码。要对密码进行哈希处理，请使用`jacksum jar`。这已经在第二章中进行了演示，“Spring Security with Sturts2”。

## 它是如何工作的...

现在访问以下 URL：

`http://127.0.0.1:8888/Basicgwtauth.html?gwt.codesvr=127.0.0.1:9997`

用户应通过访问此 URL 重定向到 GWT 应用程序。但是 Spring 框架会中断此操作，以检查用户是否有权查看应用程序。它会弹出一个登录屏幕。输入登录用户名和密码，您将进入 GWT 页面。

根据配置文件中提到的算法对密码进行解码以进行身份验证。这里提到的算法是*Sha*。因此，密码将使用*Sha 算法*进行加密和解密。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_05_04.jpg)

输入登录用户名和密码，您将进入 GWT 页面。根据配置文件中提到的算法，将对密码进行解码以进行身份验证。

## 另请参阅

+   *使用 GWT 和 Spring Security 进行数据库身份验证*配方

+   *LDAP 身份验证与 GWT 和 Spring Security*配方

# GWT 和 Spring Security 的数据库身份验证

我们将演示 GWT 中的数据库身份验证。设置保持不变。在我们以前的所有示例中，我们都使用了`applicationContext.xml`，这是 Spring 框架很容易识别的，因为它具有默认文件名。在当前示例中，我们将为此提供一个新的文件名，并查看应用程序的响应。此外，我们需要添加`spring-jdbc.xml`。

## 准备就绪

+   创建一个示例 GWT 项目

+   在构建路径中添加与 spring 相关的 JAR 包

+   添加与 Spring Security 相关的 JAR 包

+   添加`spring-security.xml`文件

+   添加与 spring-jdbc 相关的 JAR 包

+   根据前一部分的示例编辑`web.xml`文件

+   还要在`web-inf lib`文件夹中添加与 spring 相关的 JAR 包

## 如何做...

编辑`spring-security.xml`文件：

```java
<http auto-config="true" >
  <intercept-url pattern="/springgwtdbsecurity/**"
     access="ROLE_AUTHOR"/>
  <intercept-url pattern="/springgwtdbsecurity/**"
     access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**/*.html" access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**"
     access="IS_AUTHENTICATED_ANONYMOUSLY" />
  <http-basic />
</http>
<authentication-manager alias="authenticationManager">
  <authentication-provider>
  <jdbc-user-service data-source-ref="dataSource"
  users-by-username-query="
  select username,password, enabled 
  from users where username=?" 

  authorities-by-username-query="
  select u.username, ur.authority from users u,
     user_roles ur 
        where u.user_id = ur.user_id and u.username =?"/>
  </authentication-provider>
</authentication-manager>
```

在`xml`文件的 beans 标记中添加上述内容。在这里，我们指定身份验证机制为基本，并且用户信息存储在数据库中。

编辑`spring-jdbc.xml`文件：

```java
<beans 

  xsi:schemaLocation="http://www.springframework.org/
    schema/beans
  http://www.springframework.org/schema/beans/
    spring-beans-3.0.xsd">

  <bean id="MySqlDatasource" class="org.springframework.
    jdbc.datasource.DriverManagerDataSource">
    <property name="driverClassName" value=
      "com.mysql.jdbc.Driver" />
    <property name="url" value=
      "jdbc:mysql://localhost:3306/packtdb" />
    <property name="username" value="root" />
  <property name="password" value="packt123" />
  </bean>
</beans>
```

我们正在提供数据库信息。

编辑`web.xml`文件：

```java
<context-param>
  <param-name>contextConfigLocation</param-name>
  <param-value>
    /WEB-INF/spring-security.xml,
    /WEB-INF/spring-jdbc.xml
  </param-value>
</context-param>

<listener>
  <listener-class>
    org.springframework.web.context.ContextLoaderListener
  </listener-class>
</listener>
```

我们必须配置`springsecurityFilterchain`，如前面的示例所示，在其中添加上述部分。

## 它是如何工作的...

现在访问以下 URL：

`http://127.0.0.1:8888/springgwtdbsecurity.html?gwt.codesvr=127.0.0.1:9997`

输入登录用户名和密码，您将进入 GWT 页面。将创建数据库连接并执行查询。用户输入的值将与检索到的值进行身份验证。通过这种方式，我们可以看到 GWT 与 Spring Security 无缝集成。

## 另请参阅

+   *LDAP 身份验证与 GWT 和 Spring Security*配方

# GWT 和 Spring Security 的 LDAP 身份验证

我们将演示 GWT 中的 LDAP 身份验证。设置保持不变：用户必须创建组和用户。

## 准备就绪

+   创建一个示例 GWT 项目

+   在构建路径中添加与 spring 相关的 JAR 包

+   添加与 Spring Security 相关的 JAR 包

+   添加`spring-security.xml`文件

+   添加与 spring-LDAP 相关的 JAR 包

+   根据前一部分显示的内容编辑`web.xml`文件

+   还要在`web-inf lib`文件夹中添加与 spring 相关的 JAR 包

## 如何做...

编辑`spring-security.xml`文件：

```java
<http auto-config="true" >
  <intercept-url pattern="/springgwtldapsecurity/**"
     access="ROLE_AUTHOR"/>
  <intercept-url pattern="/springgwtldapsecurity/**"
     access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**/*.html" access="ROLE_AUTHOR"/>
  <intercept-url pattern="/**"
     access="IS_AUTHENTICATED_ANONYMOUSLY" />
  <http-basic />
</http>
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

<ldap-server url="ldap://localhost:389/o=example"
   manager-dn="uid=admin,ou=system"
   manager-password="secret" />
```

将此代码添加到 xml 的`beans`标记中。在这里，我们指定身份验证机制为基本，并且用户信息存储在 LDAP 服务器中。

编辑`web.xml`文件：

```java
<context-param>
  <param-name>contextConfigLocation</param-name>
  <param-value>
    /WEB-INF/spring-security.xml
  </param-value>
</context-param>

<listener>
  <listener-class>
    org.springframework.web.context.ContextLoaderListener
  </listener-class>
</listener>
```

我们必须像前面的示例中那样配置`springsecurityFilterchain`。

## 它是如何工作的...

现在访问以下 URL：

`27.0.0.1:8888/springgwtldapsecurity.html?gwt.codesvr=127.0.0.1:9997`

输入登录用户名和密码，您将被带到 GWT 页面。Spring 将使用`<ldap-server>`标签中提供的详细信息来访问开放 LDAP。Spring Security LDAP 将与开放 LDAP 通信，并将用户输入的值与检索到的值进行身份验证。成功后，用户将被重定向到应用程序。通过这一点，我们可以看到 GWT 与 Spring Security 无缝集成。

## 还有更多...

谷歌上有一个活跃的项目`code-gwtsecurity`包，旨在将 Spring Security 与 GWT 应用程序集成。它通过 GWT 弹出窗口进行登录。在身份验证失败时，它会在 GWT 窗口上向用户显示错误消息。文件`Spring4GWT jar`通过拦截 RPC 中的错误消息来工作。

让我们看看在下一章中 Spring 如何与 Vaadin 集成。
