# Spring Security5 反应式应用实用指南（二）

> 原文：[`zh.annas-archive.org/md5/6DEAFFE8EE2C8DC4EDE2FE79BBA87B88`](https://zh.annas-archive.org/md5/6DEAFFE8EE2C8DC4EDE2FE79BBA87B88)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 CAS 和 JAAS 进行身份验证

本章将从上一章结束的地方继续，探讨 Spring Security 支持的其他身份验证机制，即 CAS 和 JAAS。同样，这也是一个完全动手编码的章节，我们将构建小型应用程序，其中大部分是从我们在第二章中构建的基础应用程序开始的，*深入 Spring Security*。这些身份验证机制在行业中广为人知，许多企业都将它们作为已建立的机制，用于对用户进行身份验证并允许访问他们的员工和消费者面向的许多应用程序。

每种身份验证机制都有一个项目，您可以在本书的 GitHub 页面上看到。但是，在本书中，我们只会涵盖样本代码的重要方面，以减少章节内的混乱。

在本章中，我们将涵盖以下主题：

+   CAS

+   Java 身份验证和授权服务

+   凯尔伯斯

+   自定义 AuthenticationEntryPoint

+   密码编码器

+   自定义过滤器

# CAS

<q>中央认证服务（CAS）是 Web 的单点登录/单点注销协议。它允许用户访问多个应用程序，同时只需向中央 CAS 服务器应用程序提供其凭据（如用户 ID 和密码）一次。</q>

<q>– CAS 协议规范</q>

CAS 是一个开源的、平台无关的、支持各种知名协议的中央**单点登录**（**SSO**）服务。Spring Security 对 CAS 有一流的支持，对于拥有中央 CAS 服务器的企业来说，实现非常简单。CAS 基于 Spring Framework，其架构非常简单，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/aed55c9b-b2b1-43d3-99ad-f9414a16474a.png)

图 1：CAS 架构（图表改编自 https://apereo.github.io）

**CAS 服务器**是一个基于 Java Servlet 的应用程序，构建在 Spring Framework（Spring MVC 和 Spring Web Flow）上。它对 CAS 启用的服务进行身份验证并授予访问权限。

用户成功登录后，将创建一个 SSO 会话，并且服务器将发出**票证授予票证**（**TGT**），并且该令牌将针对来自客户端的后续调用进行验证。

**CAS 客户端**是一个使用支持的协议（CAS、SAML、OAuth 等）与 CAS 通信的 CAS 启用应用程序。已经有许多语言支持 CAS，并且许多应用程序已经实现了这种方法。一些知名的应用程序是 Atlassian 产品（JIRA 和 Confluence）、Drupal 等。

以下图表显示了涉及 CAS 服务器和客户端的身份验证流程（序列图）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/b60a7c9a-1ea7-4707-ab9f-066eeaec965c.png)

图 2：CAS 身份验证流程

现在让我们看一个实际的动手示例。我们将创建一个 CAS 服务器，然后创建一个客户端，该客户端使用 CAS 服务器进行连接并进行身份验证。

# CAS 服务器设置

CAS 项目源代码可以在 GitHub 上找到，网址为[`github.com/apereo/cas`](https://github.com/apereo/cas)。实际上并不需要检出源代码，构建 CAS 服务器，然后部署它。WAR 覆盖是一种方法，我们不是下载源代码并构建，而是获取一个预构建的 CAS Web 应用程序，然后根据需要自定义某些行为以实现我们的用例。我们将使用这种方法来设置我们的 CAS 服务器。此外，我们将使用基于 Maven 的 WAR 覆盖，可以在 GitHub 上找到，网址为[`github.com/apereo/cas-overlay-template`](https://github.com/apereo/cas-overlay-template)。

# Git 克隆

启动您喜欢的命令提示符，并将 CAS 覆盖项目克隆到您想要的项目中。我将创建一个名为`cas-sample`的文件夹，在其中我将通过从`cas-sample`文件夹执行以下命令来在`server`文件夹中克隆服务器：

```java
git clone https://github.com/apereo/cas-overlay-template.git server
```

# 添加额外的依赖项

CAS 服务器不允许任何客户端连接。每个客户端都必须在所需的 CAS 服务器上注册。我们可以使用多种机制将客户端注册到服务器。我们将使用 JSON/YML 配置将客户端注册到服务器。继续并将以下依赖项添加到您刚刚克隆的服务器项目的`pom.xml`文件中：

```java
<dependency>
   <groupId>org.apereo.cas</groupId>
   <artifactId>cas-server-support-json-service-registry</artifactId>
   <version>${cas.version}</version>
</dependency>
<dependency>
   <groupId>org.apereo.cas</groupId>
   <artifactId>cas-server-support-yaml-service-registry</artifactId>
   <version>${cas.version}</version>
</dependency>
```

`pom.xml`文件中的大多数版本由父 POM 管理。

# 在项目中设置资源文件夹

在`server`项目中，创建一个名为`src/main/resources`的文件夹。将`server`文件夹中的`etc`文件夹复制到`src/main/resources`中：

```java
mkdir -p src/main/resources
cp -R etc src/main/resources
```

# 创建 application.properties 文件

创建一个名为`application.properties`的文件：

```java
touch src/main/resources/application.properties
```

现在在`application.properties`文件中填写以下细节：

```java
server.context-path=/cas
server.port=6443

server.ssl.key-store=classpath:/etc/cas/thekeystore
server.ssl.key-store-password=changeit
server.ssl.key-password=changeit

cas.server.name: https://localhost:6443
cas.server.prefix: https://localhost:6443/cas

cas.adminPagesSecurity.ip=127\.0\.0\.1

cas.authn.accept.users=casuser::password
```

上述文件设置了端口和 SSL 密钥库的值（在设置 CAS 服务器时非常重要），还设置了 CAS 服务器的`config`文件夹。显然，我们需要按照此文件中指示的方式创建一个密钥库。

请注意，覆盖项目中有一个文件，即`build.sh`文件，其中包含大部分这些细节。我们手动执行这些操作是为了更清楚地理解。

`application.properties`中的最后一行设置了一个测试用户，凭据为`casuser`/`password`，可用于登录 CAS 服务器进行各种演示目的。这种方法不建议在生产环境中使用。

# 创建本地 SSL 密钥库

在 shell 中导航到`cas-sample/server/src/main/resources/etc/cas`文件夹，并执行以下命令：

```java
keytool -genkey -keyalg RSA -alias thekeystore -keystore thekeystore -storepass password -validity 360 -keysize 2048
```

以下图显示了在命令提示符窗口中成功执行上述命令：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/ca9b9d48-46a3-4470-aac9-c83c8c497c6c.png)

图 3：SSL 密钥库的创建

重要的是要注意，为了使 SSL 握手正常工作，生成密钥库时大多数值都设置为 localhost。这是一个重要的步骤，需要严格遵循。

# 创建供客户端使用的.crt 文件

为了使客户端连接到 CAS 服务器，我们需要从生成的密钥库中创建一个`.crt`文件。在相同的文件夹（`cas-sample/server/src/main/resources/etc/cas`）中，运行以下命令：

```java
keytool -export -alias thekeystore -file thekeystore.crt -keystore thekeystore
```

当要求输入密码时，请提供相同的密码（我们已将密码设置为`password`）。执行上述命令将创建`thekeystore.crt`文件。

# 将.crt 文件导出到 Java 和 JRE cacert 密钥库

执行以下命令以查找您的 Java 安装目录：

```java
/usr/libexec/java_home
```

或者，直接执行以下命令将`.crt`文件添加到 Java cacerts：

```java
keytool -import -alias thekeystore -storepass password -file thekeystore.crt -keystore "$(/usr/libexec/java_home)\jre\lib\security\cacerts"
```

以下图显示了在命令提示符窗口中成功执行上述命令：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/7d6189e2-8121-45a1-84e2-d61464d841a4.png)

图 4：将.crt 文件导出到 Java 密钥库

在设置客户端时，请确保使用的 JDK 与我们已添加`.crt`文件的 JDK 相同。为了将证书添加到 Java 上，建议重新启动机器。

# 构建 CAS 服务器项目并运行它

在`cas-sample/cas-server`文件夹中，执行以下两个命令：

```java
./build.sh package
./build.sh run
```

如果一切顺利，如下图所示，您应该看到一条日志消息，其中显示 READY：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/60793f9a-7ac4-424f-8cb7-c3ed8951cf73.png)

图 5：CAS 服务器准备就绪日志

现在打开浏览器，导航到 URL `https://localhost:6443/cas`。这将导航您到 CAS 服务器的默认登录表单。输入默认凭据（`casuser`/`Mellon`）即可登录。大多数浏览器会显示连接不安全。将域名添加为异常情况，之后应用程序将正常工作：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/6bae5e52-91be-4143-9e0e-4dd08597257a.png)

图 6：默认 CAS 服务器登录表单

使用演示测试用户（`testcasuser`/`password`）登录，您应该已登录并导航到用户主页。

# 将客户端注册到 CAS 服务器

如前所述，每个客户端都必须在 CAS 服务器上注册，以允许参与 SSO。本节显示了如何将客户端注册到 CAS 服务器。

# JSON 服务配置

客户/服务可以通过多种方式注册到 CAS 服务器。我们将在这里使用 JSON 配置，并已在之前的步骤中将依赖项包含到我们的`pom.xml`文件中。除了 JSON 之外，还存在其他格式，如 YAML、Mongo、LDAP 等。

在`src/main/resources`文件夹中创建一个名为`clients`的新文件夹。在新创建的文件夹中创建一个新文件，内容如下：

```java
--- !<org.apereo.cas.services.RegexRegisteredService>
serviceId: "^(http?|https?)://.*"
name: "YAML"
id: 5000
description: "description"
attributeReleasePolicy: !<org.apereo.cas.services.ReturnAllAttributeReleasePolicy> {}
accessStrategy: !<org.apereo.cas.services.DefaultRegisteredServiceAccessStrategy>
 enabled: true
 ssoEnabled: true
```

将文件保存为`newYmlFile-5000.yml`。让我们详细了解一些重要属性：

+   `serviceId`：客户端想要连接到 CAS 服务器的 URL，以正则表达式模式表示。在我们的示例中，我们指的是运行在端口`9090`上的客户端 Spring Boot 应用程序，它连接到 CAS 服务器。

+   `id`：此配置的唯一标识符。

其他可配置属性在官方网站[`goo.gl/CGsDp1`](https://goo.gl/CGsDp1)上有文档记录。

# 附加的 application.properties 文件更改

在此步骤中，我们让 CAS 服务器了解 YML 配置的使用以及在服务器中查找这些 YML 的位置。将以下属性添加到`application.properties`文件中：

```java
cas.serviceRegistry.yaml.location=classpath:/clients
```

将 CAS 相关的配置属性分离到不同的属性文件中是一个好习惯。因此，继续创建一个`cas.properties`文件，并在其中包含 CAS 相关属性。

# CAS 客户端设置

我们将使用 Spring Initializr 来创建 CAS 客户端项目设置。我们之前使用了类似的方法。让我们再次看一下。

# 使用 Spring Initializr 引导 Spring 项目

访问[`start.spring.io/`](http://start.spring.io/)，并输入如下图所示的详细信息。确保选择正确的依赖项：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/dbf118e6-2bf0-48f2-ab88-21c044d2548f.png)

图 7：用于创建 secured-cas-client 项目的 Spring Initializr

单击“生成项目”按钮，将 ZIP 文件下载到您选择的文件夹中（我将把它保存在`cas-sample`文件夹中）。执行以下`unzip`命令。我在 macOS 上运行所有示例应用程序，因此我将使用适用于此平台的命令（如果有的话）：

```java
unzip -a spring-boot-cas-client.zip
```

# 在 pom.xml 中包含 CAS 库

通过添加以下依赖项修改项目的`pom.xml`：

```java
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-cas</artifactId>
</dependency>
```

# 更改 application.properties 文件

为了确保我们不使用任何其他常用端口，我们将设置客户端监听端口`9090`。在 CAS 服务器中，我们还配置了客户端将监听端口`9090`。将以下属性添加到`application.properties`文件中：

```java
server.port=9090
```

# 附加的 bean 配置

我们现在将设置各种 bean，CAS Spring Security 模块需要。

# ServiceProperties bean

通过设置此 bean 来告诉 CAS 这是您的 CAS 客户端/服务。打开`SpringBootCasClientApplication.java`并添加以下 bean 定义：

```java
@Bean
public ServiceProperties serviceProperties() {
ServiceProperties serviceProperties = new ServiceProperties();
    serviceProperties.setService("http://localhost:9090/login/cas");
    serviceProperties.setSendRenew(false);
    return serviceProperties;
}
```

配置的 URL`http://localhost:9090/login/cas`将在内部映射到`CasAuthenticationFilter`。参数`sendRenew`设置为`false`。设置为`false`时，这告诉登录服务每次都需要用户名/密码才能访问服务。它还允许用户在不必再次输入用户名/密码的情况下访问所有服务/客户端。注销时，用户将自动注销所有服务。

# AuthenticationEntryPoint bean

看一下以下代码。相当简单直接，不是吗？这是我们告诉的 CAS 服务器运行的位置。当用户尝试登录时，应用程序将被重定向到此 URL：

```java
@Bean
public AuthenticationEntryPoint authenticationEntryPoint() {
    CasAuthenticationEntryPoint casAuthEntryPoint = new CasAuthenticationEntryPoint();
    casAuthEntryPoint.setLoginUrl("https://localhost:6443/cas/login");
    casAuthEntryPoint.setServiceProperties(serviceProperties());
    return casAuthEntryPoint;
}
```

# TicketValidator bean

当客户端应用程序获得已经分配给特定用户的票证时，将使用此 bean 来验证其真实性：

```java
@Bean
public TicketValidator ticketValidator() {
    return new Cas30ServiceTicketValidator("https://localhost:6443/cas");
}
```

# CasAuthenticationProvider bean

将之前声明的所有 bean 绑定到认证提供者 bean。我们将从`UserDetailsService`中提供的静态列表中加载用户。在生产环境中，这将指向数据库：

```java
@Bean
public CasAuthenticationProvider casAuthenticationProvider() {
  CasAuthenticationProvider provider = new CasAuthenticationProvider();
  provider.setServiceProperties(serviceProperties());
  provider.setTicketValidator(ticketValidator());
  provider.setUserDetailsService((s) -> new User("casuser", "password",
        true, true, true, true,
        AuthorityUtils.createAuthorityList("ROLE_ADMIN")));
  provider.setKey("CAS_PROVIDER_PORT_9090");
  return provider;
}
```

现在我们准备设置非常重要的 Spring Security 配置。

# 设置 Spring Security

让我们将在上一步中完成的 bean 引用带入 Spring Security 配置文件中。创建一个名为`SpringSecurityConfig`的新的 Java 文件并添加成员变量。之后，创建一个带有`@Autowired`注解的构造函数如下：

```java
private AuthenticationProvider authenticationProvider;
private AuthenticationEntryPoint authenticationEntryPoint;

@Autowired
public SpringSecurityConfig(CasAuthenticationProvider casAuthenticationProvider,
                     AuthenticationEntryPoint authenticationEntryPoint) {
   this.authenticationProvider = casAuthenticationProvider;
   this.authenticationEntryPoint = authenticationEntryPoint;
}
```

当用户访问由 CAS 服务器保护的客户端应用程序时，配置的 bean`AuthenticationEntryPoint`将被触发，并且用户将被带到在此 bean 中配置的 CAS 服务器 URL。一旦用户输入凭证并提交页面，CAS 服务器将对用户进行身份验证并创建服务票证。现在，该票证被附加到 URL，并且用户将被带到请求的客户端应用程序。客户端应用程序使用`TicketValidator` bean 来验证 CAS 服务器的票证，并且如果有效，则允许用户访问请求的页面。

在配置 HTTP 安全性之前，我们需要重写一些重要的方法。第一个方法使用`AuthenticationManagerBuilder`，我们告诉它使用我们的`AuthenticationProvider`。请按照以下方式创建该方法：

```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(authenticationProvider);
}
```

我们现在重写另一个方法，指示`AuthenticationManager`将我们创建的`AuthenticationProvider`放入其中：

```java
@Override
protected AuthenticationManager authenticationManager() throws Exception {
    return new ProviderManager(Arrays.asList(authenticationProvider));
}
```

我们现在准备创建一个名为`CasAuthenticationFilter`的过滤器（作为一个 bean），它实际上拦截请求并进行 CAS 票证验证。

# 创建 CasAuthenticationFilter bean

创建`CasAuthenticationFilter` bean 非常简单，因为我们只需将我们创建的`serviceProperties`分配给`CasAuthenticationFilter`：

```java
@Bean
public CasAuthenticationFilter casAuthenticationFilter(ServiceProperties serviceProperties) throws Exception {
    CasAuthenticationFilter filter = new CasAuthenticationFilter();
    filter.setServiceProperties(serviceProperties);
    filter.setAuthenticationManager(authenticationManager());
    return filter;
}
```

# 设置控制器

这是我们 CAS 客户端项目设置的最终设置。我们将有一个包含指向受保护页面链接的未受保护页面。当访问受保护页面时，CAS SSO 启动，用户被导航到 CAS 认证页面。一旦使用凭证（`casuser`/`password`）登录，用户将被带到受保护页面，我们将显示经过身份验证的用户名。

我们将创建一个`ndexController`，它具有根文件夹路由（`/`）。这将把用户导航到`index.html`页面。

在一个新的包中创建`IndexController.java`（最好在 controllers 包中）：

```java
@Controller
public class IndexController {
    @GetMapping("/")
    public String index() {
        return "index";
    }
}
```

在`src/resources/templates`文件夹中创建`index.html`文件，内容如下：

```java
<!DOCTYPE html>
<html >
<head>
   <meta charset="UTF-8" />
   <title>Spring Security CAS Sample - Unsecured page</title>
</head>
<body>
<h1>Spring Security CAS Sample - Unsecured page</h1>
<br>
<a href="/secured">Go to Secured Page</a>
</body>
</html>
```

现在在相同的 controllers 包中创建一个名为`CasController.java`的新控制器。我们将映射所有受保护的页面，并在此控制器中设置各种请求映射。在控制器类中，复制以下代码片段：

```java
@Controller
@RequestMapping(value = "/secured")
public class CasController {

   @GetMapping
   public String secured(ModelMap modelMap) {
     Authentication auth = SecurityContextHolder.getContext().getAuthentication();
     if( auth != null && auth.getPrincipal() != null
         && auth.getPrincipal() instanceof UserDetails) {
       modelMap.put("authusername", ((UserDetails) auth.getPrincipal()).getUsername());
     }
     return "secured";
   }
}
```

创建一个名为`secured.html`的新 HTML 文件，内容如下。这是我们的受保护页面，将显示经过身份验证的用户名：

```java
<!DOCTYPE html>
<html >
<head>
   <meta charset="UTF-8" />
   <title>Spring Security CAS Sample - Secured page</title>
</head>
<body>
<h1>Spring Security CAS Sample - Secured page</h1>
<br>
<h3 th:text="${authusername} ? 'Hello authenticated user, ' + ${authusername} + '!' : 'Hello non-logged in user!'">Hello non-logged in user!</h3>
</body>
</html>
```

# 运行应用程序

启动 CAS 服务器（在`cas-server`中运行`./build.sh run`）。之后，通过执行`./mvnw spring-boot:run`启动 spring boot 项目（`secured-cas-client`）。将浏览器导航到`http://localhost:9090`。这将带用户到`index.html`，当他们点击链接（导航到`secured.html`页面）时，用户将被带到 CAS 认证页面。要进行认证，请输入 CAS 凭证，然后将票证设置为查询字符串，然后您将被带到受保护的页面。受保护的页面将使用 CAS 服务器验证票证，然后显示用户名。

通过这样，我们完成了使用 Spring Security 的 CAS 示例。在下一节中，类似于 CAS，我们将详细介绍如何使用 JAAS 认证来使用 Spring Security。

# Java 身份验证和授权服务

**Java 身份验证和授权服务**（**JAAS**）（[`docs.oracle.com/javase/6/docs/technotes/guides/security/jaas/JAASRefGuide.html`](https://docs.oracle.com/javase/6/docs/technotes/guides/security/jaas/JAASRefGuide.html)）实现了标准**可插拔身份验证模块**（**PAM**）框架的 Java 版本。它作为 J2SDK（1.3）的可选包（扩展）引入，然后集成到 J2SDK 1.4 中。

JAAS 是一个标准库，为您的应用程序提供以下功能：

+   通过提供凭证（用户名/密码-主体）来表示身份（主体）。

+   一个登录服务，将回调您的应用程序以从用户那里收集凭证，然后在成功身份验证后返回一个主体。

+   在成功身份验证后，向用户授予必要的授权的机制：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/0cdf1f55-cdf8-4ce3-a790-4a1a28c1f976.png)

图 8：JAAS 的工作原理

如前图所示，JAAS 具有大多数内置登录机制的预定义登录模块。可以根据应用程序要求导入或构建自定义登录模块。JAAS 允许应用程序独立于实际的身份验证机制。它是真正可插拔的，因为可以集成新的登录模块而无需更改应用程序代码。

JAAS 很简单，流程如下：

+   该应用程序实例化一个`LoginContext`对象，并调用适当的（由配置控制的）`LoginModule`，执行身份验证。

+   一旦身份验证成功，*主体*（运行代码的人）将通过`LoginModule`更新为*主体*和*凭证*。

+   在那之后，JAAS 启动授权过程（使用标准 Java SE 访问控制模型）。访问是基于以下内容授予的：

+   **代码源**：代码的来源地和签署代码的人

+   **用户**：运行代码的人（也称为**主体**）

现在我们对 JAAS 及其工作原理有了大致的了解，接下来我们将通过以下部分中的示例来查看使用 Spring Security 的 JAAS 的工作原理。

# 设置项目

我们要构建的示例应用程序与第三章开始时创建的应用程序非常相似，即使用 SAML、LDAP 和 OAuth/OIDC 进行身份验证。许多方面都是相似的，但在细微的方式上有所不同。每个步骤都将得到解释；但是，有时我们不会详细介绍，因为我们已经在之前的示例中看到了一些方面。

# 设置 Maven 项目

我们将使用 IntelliJ IDE 创建一个 Maven 项目。在您的`pom.xml`文件中添加以下依赖项和构建设置：

```java
<groupId>com.packtpub.book.ch04.springsecurity</groupId>
<artifactId>jetty-jaas-authentication</artifactId>
<version>1.0-SNAPSHOT</version>
<packaging>war</packaging>
<properties>
   <maven.compiler.source>1.8</maven.compiler.source>
   <maven.compiler.target>1.8</maven.compiler.target>
   <failOnMissingWebXml>false</failOnMissingWebXml>
</properties>
<dependencies>
   <!--Spring Security Dependencies-->
   <dependency>
       <groupId>org.springframework.security</groupId>
       <artifactId>spring-security-web</artifactId>
       <version>5.0.4.RELEASE</version>
   </dependency>
   <dependency>
       <groupId>org.springframework.security</groupId>
       <artifactId>spring-security-config</artifactId>
       <version>5.0.4.RELEASE</version>
   </dependency>
   <!--Spring Framework Dependencies-->
   <dependency>
       <groupId>org.springframework</groupId>
       <artifactId>spring-context</artifactId>
       <version>5.0.4.RELEASE</version>
   </dependency>
   <dependency>
       <groupId>org.springframework</groupId>
       <artifactId>spring-webmvc</artifactId>
       <version>5.0.4.RELEASE</version>
   </dependency>
   <!-- JSP, JSTL and Tag Libraries-->
   <dependency>
       <groupId>javax.servlet</groupId>
       <artifactId>javax.servlet-api</artifactId>
       <version>3.1.0</version>
       <scope>provided</scope>
   </dependency>
   <dependency>
       <groupId>javax.servlet</groupId>
       <artifactId>jstl</artifactId>
       <version>1.2</version>
       <scope>provided</scope>
   </dependency>
   <dependency>
       <groupId>javax.servlet.jsp</groupId>
       <artifactId>javax.servlet.jsp-api</artifactId>
       <version>2.3.1</version>
       <scope>provided</scope>
   </dependency>
   <dependency>
       <groupId>javax.servlet.jsp.jstl</groupId>
       <artifactId>javax.servlet.jsp.jstl-api</artifactId>
       <version>1.2.1</version>
   </dependency>
   <dependency>
       <groupId>taglibs</groupId>
       <artifactId>standard</artifactId>
       <version>1.1.2</version>
   </dependency>
   <!--SLF4J and logback-->
   <dependency>
       <groupId>org.slf4j</groupId>
       <artifactId>slf4j-api</artifactId>
       <version>1.7.25</version>
   </dependency>
   <dependency>
       <groupId>org.slf4j</groupId>
       <artifactId>jcl-over-slf4j</artifactId>
       <version>1.7.25</version>
   </dependency>
   <dependency>
       <groupId>ch.qos.logback</groupId>
       <artifactId>logback-core</artifactId>
       <version>1.2.3</version>
   </dependency>
   <dependency>
       <groupId>ch.qos.logback</groupId>
       <artifactId>logback-classic</artifactId>
       <version>1.2.3</version>
   </dependency>
</dependencies>

<build>
   <plugins>
       <plugin>
           <groupId>org.eclipse.jetty</groupId>
           <artifactId>jetty-maven-plugin</artifactId>
           <version>9.4.10.v20180503</version>
       </plugin>
   </plugins>
</build>
```

我们添加 Spring 框架、Spring 安全、JSP/JSTL 和日志框架（SLF4J 和 Logback）的依赖项。我们将使用嵌入式 jetty 服务器（查看构建部分）来运行我们的应用程序。

# 设置 LoginModule

`LoginModule`负责对用户进行身份验证。我们将创建自己的名为`JaasLoginModule`的`LoginModule`，然后实现`login`方法。作为示例应用程序，我们的登录逻辑非常简单。必须实现`LoginModule`接口，才能编写自定义的登录模块。

创建一个类`JaasLoginModule.java`（实现`LoginModule`），并实现所有方法。在这个类中，我们将专注于两个重要的方法。在`initialize`方法中，我们获取所有必要的信息，如用户名/密码/主体，这些信息存储为字段变量，以便在我们的主要`login`方法中使用：

```java
// Gather information and then use this in the login method
@Override
public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, 
            ?> sharedState, Map<String, ?> options) {
    this.subject = subject;

    NameCallback nameCallback = new NameCallback("Username:");
    PasswordCallback passwordCallback = new PasswordCallback("Password:", false);
    try {
        callbackHandler.handle(new Callback[] { nameCallback, passwordCallback });
    } catch (IOException e) {
        e.printStackTrace();
    } catch (UnsupportedCallbackException e) {
        e.printStackTrace();
    }
    username = nameCallback.getName();
    password = new String(passwordCallback.getPassword());
}
```

在`login`方法中，我们将使用`initialize`方法中存储的值进行登录。在我们的情况下，如果硬编码的用户名/密码有效，则在主体中设置主体：

```java
// Code where actual login happens. Implement any logic as required by your application
// In our sample we are just doing a hard-coded comparison of username and password
@Override
public boolean login() throws LoginException {
    if (username == null || (username.equalsIgnoreCase("")) ||
        password == null || (password.equalsIgnoreCase(""))) {
        throw new LoginException("Username and password is mandatory.");
    } else if (username.equalsIgnoreCase("admin") &&        
        password.equalsIgnoreCase("password")) {
        subject.getPrincipals().add(new JaasPrincipal(username));
        return true;
    } else if (username.equalsIgnoreCase("user") && 
        password.equalsIgnoreCase("password")) {
        subject.getPrincipals().add(new JaasPrincipal(username));
        return true;
    }
    return false;
}
```

# 设置自定义主体

我们通过实现`java.security.Principal`接口创建了我们自己的自定义主体类。这是一个非常简单的类，我们通过构造函数接收用户名，然后在`getName`方法中使用它返回：

```java
public class JaasPrincipal implements Principal, Serializable {
    private String username;
    public JaasPrincipal(String username) {
        this.username = username;
    }
    @Override
    public String getName() {
        return "Authenticated_"+this.username;
    }
}
```

# 设置自定义 AuthorityGranter

`AuthorityGranter`被委托为经过身份验证的用户提供相关角色。我们将通过实现`org.springframework.security.authentication.jaas.AuthorityGranter`来创建我们自己的自定义类：

```java
public class JaasAuthorityGranter implements AuthorityGranter {
    @Override
    public Set<String> grant(Principal principal) {
        if (principal.getName().equalsIgnoreCase("Authenticated_admin")) {
            return Collections.singleton("ROLE_ADMIN");
        } else if (principal.getName().equalsIgnoreCase("Authenticated_user")) {
            return Collections.singleton("ROLE_USER");
        }
        return Collections.singleton("ROLE_USER");
    }
}
```

作为一个示例实现，在这个类中，我们查看已登录用户的用户名并为其授予硬编码角色。在实际应用程序中，我们将在这里做一些更严肃的事情，实际上查询数据库，然后为已登录用户授予适当的角色。

# 配置文件

我们需要在示例中有许多配置文件（Java 配置），其中大部分已经在前面涵盖过。对于剩下的文件（尚未涵盖），我们要么快速浏览它们，要么在涵盖它们时进行详细讨论。

# 应用程序配置

我们在这里没有任何特定于应用程序的配置，但在您的应用程序中拥有这样的文件总是很好的。我们有`ApplicationConfig.java`作为我们的应用程序级 Java 配置（它里面没有任何内容）。

# Spring MVC 配置

如下所示，我们将创建 Spring MVC 特定的 Java 配置（`SpringMVCConfig.java`）：

```java
@Configuration
@EnableWebMvc
@ComponentScan( basePackages = "com.packtpub")
public class SpringMVCConfig implements WebMvcConfigurer {
    @Override
    public void configureViewResolvers(ViewResolverRegistry registry) {
        registry.jsp().prefix("/WEB-INF/views/").suffix(".jsp");
    }
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login");
    }
}
```

在这个配置中，设置视图的*前缀*和*后缀*。确保您的登录视图控制器被显式添加，因为我们的控制器中没有定义路由（我们稍后会看到控制器）。

# Spring Security 配置

这是一个非常重要的配置示例。

我们将创建一个`AuthenticationProvider`bean。我们将使用我们自定义的`LoginModule`，然后使用`org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider`来设置一些内容。然后将此身份验证提供程序设置为全局提供程序。任何请求都将通过此提供程序（`SpringSecurityConfig.java`）：

```java
@Bean
DefaultJaasAuthenticationProvider jaasAuthenticationProvider() {
   AppConfigurationEntry appConfig = new AppConfigurationEntry("com.packtpub.book.ch04.springsecurity.loginmodule.JaasLoginModule",
           AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, new HashMap());

   InMemoryConfiguration memoryConfig = new InMemoryConfiguration(new AppConfigurationEntry[] { appConfig });

   DefaultJaasAuthenticationProvider def = new DefaultJaasAuthenticationProvider();
   def.setConfiguration(memoryConfig);
   def.setAuthorityGranters(new AuthorityGranter[] {jaasAuthorityGranter});
   return def;
}

//We are configuring jaasAuthenticationProvider as our global AuthenticationProvider
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
   auth.authenticationProvider(jaasAuthenticationProvider());
}
```

下一个最重要的方法是`configure`方法，在其中我们将确保设置需要受保护的正确路径，并且我们还将设置一些重要的配置：

```java
// Setting up our HTTP security
@Override
protected void configure(HttpSecurity http) throws Exception {

   // Setting up security
   http.authorizeRequests()
           .regexMatchers("/admin/.*").hasRole("ADMIN")
           .anyRequest().authenticated().and().httpBasic();

   // Setting our login page and to make it public
   http.formLogin().loginPage("/login").permitAll();
   // Logout configuration
   http.logout().logoutSuccessUrl("/");
   // Exception handling, for access denied
   http.exceptionHandling().accessDeniedPage("/noaccess");
}
```

# 控制器

我们只有一个控制器，我们将在其中配置所有路由（`JaasController.java`）：

```java
@Controller
public class JaasController {
    @RequestMapping(value="/", method = RequestMethod.GET)
    public ModelAndView userPage() {
        ModelAndView modelAndView = new ModelAndView("user");
        return modelAndView;
    }
    @RequestMapping(value = "/admin/moresecured", method = RequestMethod.GET)
    public ModelAndView adminPage(HttpServletRequest request) {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("moresecured");
        return modelAndView;
    }
    @RequestMapping(value="/noaccess", method = RequestMethod.GET)
    public ModelAndView accessDenied() {
        ModelAndView modelAndView = new ModelAndView("noaccess");
        return modelAndView;
    }
}
```

# 设置页面

我们有一些琐碎的页面。我不想在这里粘贴代码，因为它相当容易理解：

+   `login.jsp`：我们自定义的登录页面，用于从最终用户那里收集用户名和密码。

+   `user.jsp`：在示例中设置为根的页面。登录后，用户将被导航到此页面。我们只是打印会话 ID 和用户名，以展示登录。

+   `moresecured.jsp`：这只是为了展示用户角色的重要性。只有具有`ADMIN`角色的用户才能访问此页面。

+   `noaccess.jsp`：当用户无法访问任何页面时，这个虚拟页面就会出现。

可以在书的 GitHub 页面的*jetty-jaas-authentication*项目中找到完整的示例项目。

# 运行应用程序

从项目的根目录执行以下命令：

```java
mvn jetty:run
```

打开浏览器，导航到`http://localhost:8080`。您将看到一个看起来很简陋的登录页面。输入用户名/密码（admin/password 或 user/password），然后您将被导航到根页面（`user.jsp`）。

这完成了我们使用 Spring Security 的 JAAS 示例。如上图所示，JAAS 可以用于使用其他协议进行身份验证。其中一个众所周知的机制是使用 Kerberos 协议进行身份验证。下一节简要介绍了 JAAS 如何用于实现基于 Kerberos 的身份验证的大致想法。

# Kerberos

JAAS 提供了许多内置类型的`LoginModule`，其中之一是`rb5LoginModule`，用于使用 Kerberos 协议对用户进行身份验证。因此，确实可以使用 JAAS 方法来轻松实现基于 Spring 的应用程序中的 Kerberos 身份验证。

让我们深入了解一些关于身份验证的重要细节。

# 自定义身份验证入口点

在将响应发送回客户端之前，可以使用自定义`AuthenticationEntryPoint`来设置必要的响应头、内容类型等。

`org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint`类是一个内置的`AuthenticationEntryPoint`实现，用于启动基本身份验证。可以通过实现`org.springframework.security.web.AuthenticationEntryPoint`接口来创建自定义入口点。以下是一个示例实现：

```java
@Component
public final class CustomAuthenticationEntryPoint implements 
        AuthenticationEntryPoint {
    @Override
    public void commence(final HttpServletRequest request, final 
            HttpServletResponse response, final AuthenticationException 
        authException) throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
```

当客户端在没有身份验证的情况下访问资源时，此入口点会启动并抛出 401 状态码（`未经授权`）。

在 Spring Security Java 配置文件中，确保`configure`方法定义了这个自定义`AuthenticationEntryPoint`，如下面的代码片段所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/public").permitAll()
        .anyRequest().authenticated()
        .and()
        .httpBasic()
        .authenticationEntryPoint(customAuthenticationEntryPoint);
}
```

# 多个 AuthenticationEntryPoint

Spring Security 确实允许您为应用程序配置多个`AuthenticationEntryPoint`，如果需要的话。

自 Spring Security 3.0.2 以来，`org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint`查看配置中声明的所有`AuthenticationEntryPoint`并执行它们。

自 Spring Security 5.x 以来，我们有`org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint`，它使用反应性数据类型，并为其执行带来了异步性质。

Spring Security 配置中的`defaultAuthenticationEntryPointFor()`方法也可以用于设置查看不同 URL 匹配的多个入口点（请参见以下代码片段）：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
    .authorizeRequests()
        .antMatchers("/public").permitAll()
        .anyRequest().authenticated()
        .and()
        .httpBasic()
    .defaultAuthenticationEntryPointFor(
        loginUrlAuthenticationEntryPointUser(),
        new AntPathRequestMatcher("/secured/user/**"))
    .defaultAuthenticationEntryPointFor(
        loginUrlAuthenticationEntryPointAdmin(),
        new AntPathRequestMatcher("/secured/admin/**"));
}
@Bean
public AuthenticationEntryPoint loginUrlAuthenticationEntryPointUser(){
    return new LoginUrlAuthenticationEntryPoint("/userAuth");
}      
@Bean
public AuthenticationEntryPoint loginUrlAuthenticationEntryPointAdmin(){
    return new LoginUrlAuthenticationEntryPoint("/adminAuth");
}
```

# PasswordEncoder

在 Spring Security 5 之前，该框架只允许应用程序中有一个`PasswordEncoder`，并且还有弱密码编码器，如 MD5 和 SHA。这些编码器也没有动态盐，而是更多的静态盐需要提供。通过 Spring Security 5，在这个领域发生了巨大的变化，新版本中的密码编码概念采用了委托，并允许在同一应用程序中进行多次密码编码。已编码的密码有一个前缀标识符，指示使用了什么算法（请参见以下示例）：

```java
{bcrypt}$2y$10$zsUaFDpkjg01.JVipZhtFeOHpC2/LCH3yx6aNJpTNDOA8zDqhzgR6
```

此方法允许根据需要在应用程序中使用多种编码。如果没有提到标识符，这意味着它使用默认编码器，即`StandardPasswordEncoder`。

一旦您决定密码编码，这可以在`AuthenticationManager`中使用。一个示例是以下代码片段：

```java
@Autowired
public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth
        .inMemoryAuthentication()
        .passwordEncoder(new StandardPasswordEncoder())    
        .withUser("user")
        .password("025baf3868bc8f785267d4aec1f02fa50809b7f715576198eda6466")
        .roles("USER");
}
```

如前所述，Spring Security 5 通过引入`DelegationPasswordEncoder`引入了委托方法。`DelegatingPasswordEncoder`已取代`PasswordEncoder`，并可以通过以下两种方法创建：

+   方法 1：

```java
PasswordEncoder passwordEncoder = 
    PasswordEncoderFactories.createDelegatingPasswordEncoder();
passwordEncoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
```

+   方法 2：

```java
String defaultEncode = "bcrypt";
Map encoders = new HashMap<>();
encoders.put(defaultEncode, new BCryptPasswordEncoder());
encoders.put("scrypt", new SCryptPasswordEncoder());
encoders.put("sha256", new StandardPasswordEncoder());

PasswordEncoder passwordEncoder =
    new DelegatingPasswordEncoder(defaultEncode, encoders);
```

`DelegatingPasswordEncoder`允许针对旧的编码方法验证密码，并在一段时间内升级密码，而无需任何麻烦。这种方法可以用于在用户进行身份验证时自动升级密码（从旧编码到新编码）。

# 盐

为了使暴力攻击更加困难，我们在编码时还可以提供一个随机字符串。这个随机字符串称为**盐**。盐文本包含在`PasswordEncoder`中，如下面的代码片段所示：

```java
auth
    .inMemoryAuthentication()
    .passwordEncoder(new StandardPasswordEncoder(“random-text-salt”));
```

# 自定义过滤器

正如前面所解释的，Spring Security 是基于 servlet 过滤器工作的。有许多内置的 servlet 过滤器几乎可以完成所有必要的功能。如果需要，Spring Security 确实提供了一种机制来编写自定义过滤器，并可以在过滤器链执行的正确位置插入。通过扩展`org.springframework.web.filter.GenericFilterBean`来创建自己的过滤器，如下面的代码片段所示：

```java
public class NewLogicFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        // Custom logic
        chain.doFilter(request, response);
    }
}
```

一旦您创建了自己的过滤器，请将其插入到 Spring Security 配置文件中的过滤器链中，如下所示：

```java
@Configuration
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .addFilterBefore(new NewLogicFilter(), 
                BasicAuthenticationFilter.class);
    }
}
```

您可以将新的过滤器放置在过滤器链中的任何位置，之前、之后或特定位置。如果您想要扩展现有的过滤器，也可以这样做。

# 摘要

在本章中，我们通过实际编码示例介绍了 Spring Security 支持的 CAS 和 JAAS 两种认证机制。同样，我们使用了作为第二章的一部分构建的示例应用程序作为基础，以解释其他认证机制的工作和实现。然后，我们介绍了 Spring Security 中的一些重要概念和可定制性。

在本章中，我们故意没有在编码示例中使用响应式编程。本章的目的是让您通过使用熟悉的 Spring Web MVC 应用程序框架来理解每个 CAS 和 JAAS 认证机制的核心概念。我们将在第五章中更详细地介绍响应式编程，即*与 Spring WebFlux 集成*。我们将在下一章中介绍 Spring WebFlux，并在适当的时候实现 Spring Security。在阅读[第五章](https://cdp.packtpub.com/hands_on_spring_security_5_for_reactive_applications/wp-admin/post.php?post=168&action=edit#post_29)的主要内容时，您将清楚地了解，使本章中的代码示例符合响应式是非常容易的。


# 第五章：与 Spring WebFlux 集成

Spring Framework 5 引入的新功能之一是引入了一个新的响应式 Web 应用程序框架，Spring WebFlux。WebFlux 与成熟的 Web 应用程序框架 Spring MVC 并存。该书旨在介绍 Spring Security 的响应式部分，其中 Spring WebFlux 是核心组件之一。

使您的应用程序具有响应式特性会为您的应用程序带来异步性。传统的 Java 应用程序使用线程来实现应用程序的并行和异步特性，但是对于 Web 应用程序来说，使用线程是不可伸缩和高效的。

本章首先介绍了 Spring MVC 和 Spring WebFlux 之间的核心区别，然后深入探讨了 Spring Security 模块以及如何将响应式方面引入其中。

在本章中，我们将涵盖以下主题：

+   Spring MVC 与 WebFlux

+   Spring 5 中的响应式支持

+   Spring WebFlux

+   Spring WebFlux 身份验证架构

+   Spring WebFlux 授权

+   示例项目

+   自定义

# Spring MVC 与 WebFlux

Spring WebFlux 作为 Spring 5 的一部分引入，为现有的 Spring MVC 带来了一个新的替代方案。Spring WebFlux 引入了非阻塞的事件循环式编程，以提供异步性。

事件循环是由 Node.js 引入并因此而出名。Node.js 能够使用单线程的 JavaScript 执行非阻塞操作，通过在可能的情况下将操作卸载到系统内核。内核是多线程的，能够执行这些卸载的操作，并在成功执行后通过回调通知 Node.js。有一个不断运行的进程来检查调用堆栈（其中堆叠了需要执行的操作），并以**先进先出**（**FIFO**）的方式继续执行进程。如果调用堆栈为空，它会查看*事件队列*中的操作。它会将它们拾起，然后将它们移动到调用堆栈中以供进一步执行。

以下图显示了两个 Web 应用程序框架中的内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/c30ee398-d5be-4f01-ad27-1e250e5b0aed.png)

图 1：Spring MVC 和 Spring WebFlux

如前图所示，Spring MVC 基于 Servlet API（在线程池上工作），而 Spring WebFlux 基于响应式流（它基于事件循环机制）。然而，这两个框架都支持常用的注解，如`@Controller`，并且也支持一些知名的服务器。

让我们在下图中并排看一下 Spring MVC 和 Spring WebFlux 的工作方式：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/bf631caa-8c2b-4e35-ab85-e1374c4005be.png)

图 2：Spring MVC 和 Spring WebFlux 的工作方式

正如您所看到的，这两个框架的工作方式的根本区别在于 Spring MVC 是阻塞的，而 Spring WebFlux 是非阻塞的。

在 Spring WebFlux 中，Servlet API 充当适配器层，使其能够支持诸如**Tomcat**和**Jetty**等 Servlet 容器以及**Undertow**和**Netty**等非 Servlet 运行时。

Spring MVC 包括同步 API（过滤器、Servlet 等）和阻塞 I/O（`InputStream`、`OutputStream`等），而 Spring WebFlux 包括异步 API（`WebFilter`、`WebHandler`等）和非阻塞 I/O（Reactor Mono 用于*0..1*元素和 Reactor Flux 用于*0..N*元素）。

Spring WebFlux 支持各种异步和响应式 API，即 Java 9 Flow API、RxJava、Reactor 和 Akka Streams。默认情况下，它使用 Spring 自己的响应式框架 Reactor，并且它的工作相当出色：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/f8ce06eb-8094-44e7-b218-18d92d1711fa.png)

图 3：Spring WebFlux 响应式 API 支持

如前所述，Spring WebFlux 是作为 Spring MVC 的一种替代方案引入的。这并不意味着 Spring MVC 已经被弃用。在 Spring MVC 中编写的应用程序可以继续在相同的堆栈上运行，无需迁移到 Spring WebFlux。如果需要，我们可以通过运行一个响应式客户端来调用远程服务，将响应式编码实践引入现有的 Spring MVC 应用程序中。

现在我们已经了解了 Spring 中两种 Web 应用程序框架的特点，下一节将介绍在构建应用程序时何时选择哪种框架。

# 何时选择何种方式？

响应式编程非常好，但这并不意味着我们必须为每个应用程序都采用响应式。同样，不是所有应用程序都适合 Spring WebFlux。通过查看需求以及这些框架如何解决需求来选择框架。如果应用程序在 Spring MVC 框架下运行良好，那么没有必要将其迁移到 Spring WebFlux。事实上，如前所述，如果需要，可以将响应式的优点带入 Spring MVC 中，而不会有太多麻烦。

此外，如果应用程序已经具有阻塞依赖项（JDBC、LDAP 等），那么最好坚持使用 Spring MVC，因为引入响应式概念会带来复杂性。即使引入了响应式概念，应用程序的许多部分仍处于阻塞模式，这将阻止充分利用这种编程范式。

如果应用程序涉及数据流（输入和输出），则采用 Spring WebFlux。如果可伸缩性和性能至关重要，也可以考虑这作为 Web 应用程序选择。由于其异步和非阻塞的本质，这些应用程序在性能上会比同步和阻塞的应用程序更高。由于是异步的，它们可以处理延迟，并且更具可伸缩性。

# Spring 5 中的响应式支持

Spring Framework 5 对响应式编程范式有着广泛的支持。许多模块都全力拥抱这一概念，并将其视为一流公民。以下图表总结了 Spring 5 对响应式的支持：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/cc2a49cf-86fc-4206-978d-46f156a7d0ca.png)

图 4：Spring 5 和响应式支持

Spring WebFlux 模块是建立在响应式编程范式之上的一个完整的 Web 应用程序框架（它使用 Reactor 和 RxJava）。在 Spring/Java 生态系统中，响应式编程的早期采用者包括 Spring Data、Spring Security 和 Thymeleaf。Spring Security 具有支持响应式编程的许多功能。

Spring Data 对 Redis、MongoDB、Couchbase 和 Cassandra 提供了响应式支持。它还支持从数据库中以`@Tailable`的形式发出的无限流（以流的形式逐个发出的记录）。JDBC 本质上是阻塞的，因此 Spring Data JPA 是阻塞的，无法变为响应式。

# Spring MVC 中的响应式

尽管 Spring MVC 在本质上是阻塞的，但是通过使用 Spring 5 提供的响应式编程能力，一些方面可以变得响应式。

在 Spring MVC 控制器中，可以使用响应式类型`Flux`和`Mono`，如下图所示。唯一的规则是只能将这些响应式类型用作控制器的返回值：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/a1f41618-09a4-408c-b922-567bdd742bd5.png)

图 5：Spring MVC 使用响应式类型变为非阻塞

Spring MVC 的注解，如`@Controller`，`@RequestMapping`等，在 Spring WebFlux 中也得到支持。因此，可以在一段时间内以缓慢的方式将 Spring MVC Web 应用程序转换为 Spring WebFlux。

# Spring WebFlux

在本节中，我们将更详细地介绍 Spring WebFlux。Spring WebFlux 有两种（编程模型）使用方式。它们如下：

+   **使用注解**：通过使用注解，如在 Spring MVC 中所做的那样

+   **使用函数式风格**：使用 Java Lambdas 进行路由和处理

以下代码展示了使用 Spring WebFlux 的基于注解的风格。我们将在本章的后续部分中逐步介绍整个代码示例。然而，本节旨在在深入探讨之前进行介绍：

```java
@RestController
@RequestMapping(value=”/api/movie”)
public class MovieAPI {
    @GetMapping(“/”)
    public Flux(Movie) getMovies() {
        //Logic of getting all movies
    }
    @GetMapping(“/{id}”)
    public Mono<Movie> getMovie(@PathVariable Long id) {
        //Logic for getting a specific movie
    }
    @PostMapping(“/post”)
    public Mono<ResponseEntity<String>> createMovie(@RequestBody Movie movie) {
        // Logic for creating movie
    }
}
```

Spring WebFlux 的函数式编程模型使用了两个基本组件：

+   `HandlerFunction`：负责处理 HTTP 请求。相当于我们在之前的代码片段中看到的`@Controller`处理方法。

+   `RouterFunction`：负责路由 HTTP 请求。相当于基于注解的`@RequestMapping`。

# HandlerFunction

`HandlerFunction`接受一个`ServerRequest`对象，并返回`Mono<ServerResponse>`。`ServerRequest`和`ServerResponse`对象都是不可变的，并且完全是响应式的，建立在 Reactor 之上。

`ServerRequest`将 body 公开为`Mono`或`Flux`。传统上，使用`BodyExtractor`来实现这一点。但是，它还具有实用方法，可以将这些对象公开为下面代码中所示的对象。`ServerRequest`还可以访问所有 HTTP 请求元素，如方法、URI 和查询字符串参数：

```java
Mono<String> helloWorld = request.body(BodyExtractors.toMono(String.class);
Mono<String> helloWorldUtil = request.bodyToMono(String.class);

Flux<Person> movie = request.body(BodyExtractors.toFlux(Movie.class);
Flux<Person> movieUtil = request.bodyToFlux(Movie.class);
```

`ServerResponse`对象让您访问各种 HTTP 响应。`ServerResponse`对象可以通过使用构建器创建，允许设置响应状态和响应头。它还允许您设置响应体：

```java
Mono<Movie> movie = ...
ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).body(movie);
```

`HandlerFunction`可以使用 Lambda 函数创建，如下面的代码，并返回状态为 200 OK 的`ServerResponse`，并且基于`String`的 body。

```java
HandlerFunction<ServerResponse> handlerFunction =
  request -> ServerResponse.ok().body(fromObject("Sample HandlerFunction"));
```

建议将所有的`HandlerFunction`对象分组到一个单独的类中，每个方法处理一个特定的功能，如下面的代码片段所示：

```java
public class MovieHandler {
    public Mono<ServerResponse> listMovies(ServerRequest request) {
        // Logic that returns all Movies objects
    }
    public Mono<ServerResponse> createMovie(ServerRequest request) {
        // Logic that returns creates Movie object in the request object
    }
    public Mono<ServerResponse> getMovie(ServerRequest request) {
        // Logic that returns one Movie object
    }
    //.. More methods as needed
}
```

# RouterFunction

传入的请求被`RouterFunction`拦截，并根据配置的路由导航到正确的`HandlerFunction`。如果匹配路由，则`RouterFunction`接受`ServerRequest`并返回`Mono<HandlerFunction>`。如果不匹配，则返回空的`Mono`。

`RouterFunction`如下面的代码片段所示创建：

```java
RouterFunctions.route(RequestPredicate, HandlerFunction)
```

`RequestPredicate`是一个实用类，具有大多数常见用例的预定义匹配模式，例如基于路径、内容类型、HTTP 方法等的匹配。`RouterFunction`的示例代码片段如下：

```java
RouterFunction<ServerResponse> routeFunctionSample =
    RouterFunctions.route(RequestPredicates.path("/sample-route"),
    request -> Response.ok().body(fromObject("Sample Route")));
```

可以通过调用以下方法组合多个`RouterFunction`对象：

```java
RouterFunction.and(RouterFunction)
```

还有一个方便的方法，如下所示，它是`RouterFunction.and()`和`RouterFunctions.route()`方法的组合：

```java
RouterFunction.andRoute(RequestPredicate, HandlerFunction)
```

前面`HandlerFunction`的`RouterFunction`如下：

```java
RouterFunction<ServerResponse> movieRoutes =
    route(GET("/movie/{id}").and(accept(APPLICATION_JSON)), handler::getMovie)
    .andRoute(GET("/movie").and(accept(APPLICATION_JSON)), handler::listMovies)
    .andRoute(POST("/movie").and(contentType(APPLICATION_JSON)), handler::createMovie);
```

# Spring WebFlux 服务器支持

Spring Webflux 支持多个服务器，如下所示：

+   Netty

+   Jetty

+   Tomcat

+   Undertow

+   Servlet 3.1+容器

Spring Boot 2+在选择 Spring WebFlux 作为 Web 应用程序框架时，默认使用 Netty。

创建的`RouterFunction`可以在之前列出的任何服务器上运行。为了做到这一点，需要将`RouterFunction`转换为`HttpHandler`，使用以下方法：

```java
RouterFunctions.toHttpHandler(RouterFunction)
```

如果要在 Netty 中运行先前创建的`RouterFunction`，可以使用以下代码片段：

```java
HttpHandler httpHandler = RouterFunctions.toHttpHandler(movieRoutes);
ReactorHttpHandlerAdapter reactorAdapter = new ReactorHttpHandlerAdapter(httpHandler);
HttpServer server = HttpServer.create(HOST, PORT);
server.newHandler(reactorAdapter).block();
```

当我们在本章的后续部分查看示例应用程序时，我们将查看其他 Spring WebFlux 支持的服务器的代码。

# 响应式 WebClient

Spring WebFlux 包括一个名为`WebClient`的响应式客户端，使我们能够以非阻塞的方式执行 HTTP 请求并使用响应式流。`WebClient`可以作为传统上更常用的`RestTemplate`的替代品。`WebClient`公开了响应式`ClientHttpRequest`和`ClientHttpResponse`对象。这些对象的 body 由响应式`Flux<DataBuffer>`组成，而不是传统的阻塞流实现（`InputStream`和`OutputStream`）。

创建`WebClient`的实例，执行请求，然后处理响应。以下是显示`WebClient`用法的代码片段：

```java
WebClient client = WebClient.create("http://any-domain.com");
Mono<Movie> movie = client.get()
        .url("/movie/{id}", 1L)
        .accept(APPLICATION_JSON)
        .exchange(request)
        .then(response -> response.bodyToMono(Movie.class));
```

`WebClient`可以在 Spring MVC 和 Spring WebFlux Web 应用程序中使用。`RestTemplate`的使用可以很容易地替换为`WebClient`，利用其提供的响应式优势。

在我们的示例项目中，我们将使用一个示例来介绍`WebClient`的概念和功能。

# 响应式 WebTestClient

与`WebClient`类似，Spring WebFlux 为您提供了一个非阻塞的响应式客户端`WebTestClient`，用于测试服务器上的响应式 API。它具有使在测试环境设置中轻松测试这些 API 的实用程序。`WebTestClient`可以连接到任何服务器，如前面详细介绍的那样，通过 HTTP 连接执行必要的测试。但是，该客户端具有在运行服务器时运行测试和在没有运行服务器时运行测试的能力。

`WebTestClient`还有许多实用工具，可以验证执行这些服务器端 API 产生的响应。它可以很容易地绑定到 WebFlux Web 应用程序，并模拟必要的请求和响应对象，以确定 API 的功能方面。`WebTestClient`可以根据需要修改标头，以模拟所需的测试环境。您可以通过使用`WebTestClient.bindToApplicationContext`方法获取整个应用程序的`WebTestClient`实例，或者可以将其限制为特定的控制器（使用`WebTextClient.bindToController`方法），`RouterFunction`（使用`WebTestClient.bindToRouterFunction`方法）等等。

我们将在随后的实践部分（*示例项目*部分，*测试（WebTestClient）*子部分下）看到`WebTestClient`的工作示例。

# 响应式 WebSocket

Spring WebFlux 包括基于 Java WebSocket API 的响应式`WebSocket`客户端和服务器支持。

在服务器上，创建`WebSocketHandlerAdapter`，然后将每个处理程序映射到 URL。由于我们的示例应用程序中不涉及`WebSocket`，让我们更详细地了解一下：

```java
public class MovieWebSocketHandler implements WebSocketHandler {
    @Override
    public Mono<Void> handle(WebSocketSession session) {
        // ...
    }
}
```

`handle()`方法接受`WebSocketSession`对象，并在会话处理完成时返回`Mono<Void>`。`WebSocketSession`使用`Flux<WebSocketMessage> receive()`和`Mono<Void> send(Publisher<WebSocketMessage>)`方法处理入站和出站消息。

在 Web 应用程序 Java 配置中，声明`WebSocketHandlerAdpater`的 bean，并创建另一个 bean 将 URL 映射到适当的`WebSocketHandler`，如下面的代码片段所示：

```java
@Configuration
static class WebApplicationConfig {
    @Bean
    public HandlerMapping webSockerHandlerMapping() {
        Map<String, WebSocketHandler> map = new HashMap<>();
        map.put("/movie", new MovieWebSocketHandler());

        SimpleUrlHandlerMapping mapping = new SimpleUrlHandlerMapping();
        mapping.setUrlMap(map);
        return mapping;
    }
    @Bean
    public WebSocketHandlerAdapter handlerAdapter() {
        return new WebSocketHandlerAdapter();
    }
}
```

Spring WebFlux 还提供了`WebSocketClient`，并为之前讨论的所有 Web 服务器提供了抽象，如 Netty、Jetty 等。使用适当的服务器抽象并创建客户端，如下面的代码片段所示：

```java
WebSocketClient client = new ReactorNettyWebSocketClient();
URI url = new URI("ws://localhost:8080/movie");
client.execute(url, session ->
        session.receive()
            .doOnNext(System.out::println)
            .then());
```

在客户端代码中，我们现在可以订阅`WebSocket`端点并监听消息并执行必要的操作（基本的`WebSocket`实现）。前端的这样一个客户端的代码片段如下：

```java
<script>
   var clientWebSocket = new WebSocket("ws://localhost:8080/movie");
   clientWebSocket.onopen = function() {
       // Logic as needed
   }
   clientWebSocket.onclose = function(error) {
       // Logic as needed
   }
   clientWebSocket.onerror = function(error) {
       // Logic as needed
   }
   clientWebSocket.onmessage = function(error) {
       // Logic as needed
   }
</script>
```

为了使本章专注而简洁，我们将不讨论 Spring Security 提供的`WebSocket`安全性。在本书的最后一章中，我们将快速介绍`WebSocket`安全性，使用一个示例。

# Spring WebFlux 身份验证架构

在涵盖了核心 Spring WebFlux 概念之后，我们现在将进入本章的重点；为您介绍 Spring WebFlux 基于响应式 Web 应用程序的 Spring Security。

如前所述，Spring MVC Web 应用程序中的 Spring Security 基于 ServletFilter，而 Spring WebFlux 中的 Spring Security 基于 WebFilter：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/d1a354e7-4c45-4822-a724-6ffdeff0f5d6.png)

图 6：Spring MVC 和 Spring WebFlux 身份验证方法

我们在之前的章节中详细了解了 Spring MVC web 应用中的 Spring Security。现在我们将看一下基于 Spring WebFlux 的 Web 应用的 Spring Security 认证的内部细节。下图显示了在 WebFlux 应用程序的认证过程中各种类的交互：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/fdb96ba6-52ca-4b7b-8b8f-1b0b76b71397.png)

图 7：Spring WebFlux 认证架构

上述图表相当不言自明，并且与您之前在 Spring MVC 中看到的非常相似。核心区别在于`ServletFilter`现在被`WebFilter`取代，并且我们在 Spring MVC 中有基于阻塞类的反应式类。然而，Spring Security 的核心概念仍然保持完整，`WebFilter`处理初始认证过程中的许多方面；核心认证由`ReactiveAuthenticationManager`和相关类处理。

# Spring WebFlux 授权

与认证类似，就授权而言，核心概念与我们之前在 Spring MVC 中看到的相似。但是，执行操作的类已经改变，并且是响应式和非阻塞的。下图显示了 Spring WebFlux 应用程序中与授权相关的主要类及其交互：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/4cf1b7bb-eb58-4a8c-8658-b59deb16087c.png)

图 8：Spring WebFlux 应用程序中与授权相关的类

正如我们现在都知道的那样，Spring WebFlux 安全性基于`WebFilter`工作，`AuthorizationWebFilter`拦截请求并使用`ReactiveAuthorizationManager`检查`Authentication`对象是否有权访问受保护的资源。`ReactiveAuthorizationManager`有两种方法，即`check`（检查`Authentication`对象是否被授予访问权限）和`verify`（检查`Authentication`对象是否被授予访问权限）。在任何异常情况下，`ExceptionTranslationWebFilter`负责通过遵循适当的路径来处理异常。

# 示例项目

足够的解释；现在是时候动手写实际的代码了。在本节中，我们将创建一个集成了 Spring Security 的电影目录网站。我们将贯穿始终地使用响应式概念，并使用基于表单的登录。我们将从硬编码的用户开始，然后看看如何查看持久用户存储来对用户进行认证。然后我们将更详细地进行测试，最后看看我们可以为 Spring Security 页面带来的一些自定义。最后，我们将涉及授权方面，并关闭示例应用程序。

# WebFlux 项目设置

我们将首先创建一个基本的基于 WebFlux 的 Web 应用程序，然后慢慢添加其他功能，包括安全性。整个代码都可以在我们书的 GitHub 页面上找到，在章节的文件夹下，即`spring-boot-webflux`。

我正在使用 IntelliJ 作为我的 IDE，由于我们使用了*Lombok 库*（注解`preprocessor`），请确保启用 Lombok 插件，以便为您的模型生成适当的样板代码。我们的项目非常简单，只执行电影管理的功能（电影 CRUD 操作）。

# Maven 设置

使用 Spring Initializr 生成 Spring WebFlux 项目非常容易。但是为了让我们掌握 WebFlux 应用程序的各个方面，我们将逐步构建。但是，我们将使用 Spring Boot 来运行我们的应用程序。

我们将创建一个 maven 项目，然后将添加以下主要依赖项（为了使代码更简洁，以下代码只显示了重要的依赖项）到我们的`pom.xml`中：

```java
<!--Spring Framework and Spring Boot-->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
<!--JSON-->
<dependency>
…
</dependency>
<!--Logging-->
<dependency>
…
</dependency>
<!--Testing-->
<dependency>
…
</dependency>
```

我们将为库和插件依赖项包括快照存储库。最后，我们将为我们的 Spring Boot 添加非常重要的 maven 插件，如下所示：

```java
<build>
  <plugins>
      <plugin>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
  </plugins>
</build>
```

# 配置类

尽管我们将尽可能使用默认配置，但我们仍将为各种组件编写单独的配置类。在我们的项目中，我们正在构建一个基本的 WebFlux 应用程序，因此我们只有一个配置类。

# SpringWebFluxConfig 类

Spring WebFlux Web 应用程序的主要配置类是通过这个类实现的：

```java
@Configuration
@EnableWebFlux
@ComponentScan
public class SpringWebFluxConfig {
  // ...
}
```

我们有一个空的类，只有一些非常重要的注释，如前面的代码所示。`@EnableWebFlux`使应用程序具有反应性，并使其成为 WebFlux。

# 存储库

我们将使用硬编码的电影作为我们的样本数据结构，并以一种反应性的方式编写方法，以公开我们存储库类中的方法。这些方法可以用于操作电影的数据结构。我们的存储库类是一个传统的类，但正确的数据结构，以`Mono`和`Flux`的形式，有助于为应用程序带来反应性的特性：

```java
@Repository
public class MovieRepositoryImpl implements MovieRepository {
    private Map<Long, Movie> movies = new HashMap<Long, Movie>();

    @PostConstruct
    public void initIt() throws Exception {
      movies.put(Long.valueOf(1), new Movie(Long.valueOf(1), "Moonlight",     
        "Drama"));
      movies.put(Long.valueOf(2), new Movie(Long.valueOf(2), "Dunkirk", 
        "Drama/Thriller"));
      movies.put(Long.valueOf(3), new Movie(Long.valueOf(3), "Get Out", 
        "Mystery/Thriller"));
      movies.put(Long.valueOf(4), new Movie(Long.valueOf(4), "The Shape of 
        Water", "Drama/Thriller"));
    }
    @Override
    public Mono<Movie> getMovieById(Long id) {
        return Mono.just(movies.get(id));
    }
    //...Other methods
}
```

该类只是从类中提取的片段，仅显示一个方法（`getMovieById`）。与往常一样，我们的类实现了一个接口（`MovieRepository`），并且这个引用将在应用程序的其他部分中使用（使用 Spring 的依赖注入功能）。

# 处理程序和路由器

如前所述，我们有两种方法，即**基于功能的**和**基于注释的**，用于实现 WebFlux 应用程序。基于注释的方法类似于 Spring MVC，因此我们将在我们的样本应用程序中使用基于功能的方法：

```java
@Component
public class MovieHandler {
    private final MovieRepository movieRepository;

    public MovieHandler(MovieRepository movieRepository) {
        this.movieRepository = movieRepository;
    }
    public Mono<ServerResponse> listMovies(ServerRequest request) {
        // fetch all Movies from repository
        Flux<Movie> movies = movieRepository.listMovies();
        // build response
        return 
            ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
            .body(movies, Movie.class);
    }
    //...Other methods
}
```

该类非常简单直接，使用存储库类进行数据结构查询和操作。每个方法都完成了功能，并最终返回`Mono<ServerResponse>`。基于功能的编程中 WebFlux 的另一个重要方面是路由配置类，如下所示：

```java
@Configuration
public class RouterConfig {

    @Bean
    public RouterFunction<ServerResponse> routerFunction1(MovieHandler 
        movieHandler) {
      return 
        route(GET("/").and(accept(MediaType.APPLICATION_JSON)), 
            movieHandler::listMovies)
        .andRoute(GET("/api/movie").and(accept(MediaType.APPLICATION_JSON)), 
            movieHandler::listMovies)
        .andRoute(GET("/api/movie/{id}").and(accept(MediaType.APPLICATION_JSON)), 
            movieHandler::getMovieById)
        .andRoute(POST("/api/movie").and(accept(MediaType.APPLICATION_JSON)), 
            movieHandler::saveMovie)
        .andRoute(PUT("/api/movie/{id}").and(accept(MediaType.APPLICATION_JSON)), 
            movieHandler::putMovie)
        .andRoute(DELETE("/api/movie/{id}")
            .and(accept(MediaType.APPLICATION_JSON)), movieHandler::deleteMovie);
    }
}
```

这是一个查看请求并将其路由到适当处理程序方法的类。在您的应用程序中，您可以拥有任意数量的路由器配置文件。

# 引导应用程序

我们的样本应用程序使用 Spring Boot。Spring WebFlux 默认在 Spring Boot 中运行 Reactor Netty 服务器。我们的 Spring Boot 类非常基本，如下所示：

```java
@SpringBootApplication
public class Run {
  public static void main(String[] args) {
      SpringApplication.run(Run.class, args);
  }
}
```

您可以在除 Spring Boot 之外的任何其他服务器上运行应用程序，这是非常容易实现的。我们有一个名为`spring-boot-tomcat-webflux`的单独项目，它在 Spring Boot 上运行，但不是在 Reactor Netty 上运行，而是在 Tomcat 服务器上运行。

除了`pom.xml`之外，代码的任何部分都不需要更改：

```java
<!--Spring Framework and Spring Boot-->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-webflux</artifactId>
  <exclusions>
      <exclusion>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-reactor-netty</artifactId>
      </exclusion>
  </exclusions>
</dependency>
<!--Explicit Tomcat dependency-->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-tomcat</artifactId>
</dependency>
```

从`spring-boot-starter-webflux`工件中排除 Reactor Netty。然后，显式添加 Tomcat 依赖项，`spring-boot-starter-tomcat`。其余的`pom.xml`保持不变。对于其他服务器运行时，如 Undertow、Jetty 等，方法与此处详细介绍的方法类似。

# 运行应用程序

现在，对于我们构建的最重要的部分：运行应用程序。由于它是一个 Spring Boot 应用程序，执行默认命令如下：

```java
mvn spring-boot:run
```

一旦服务器启动（默认为 Rector Netty 或 Tomcat），打开浏览器并导航到`localhost:8080/movies`。我们已经创建了默认路由指向“列出所有电影”终点，如果一切顺利，您应该看到显示我们存储库类中所有硬编码电影的 JSON。

在本节中，我们创建了一个样本 Spring WebFlux 电影应用程序。在下一节中，我们将为这个应用程序添加所有重要的安全性。

# 添加安全性

与我们迄今为止所取得的成就分开，我们将有一个单独的项目，`spring-boot-security-webflux`（与`spring-boot-webflux`相同）。在其中，我们将构建所有安全方面。

# 配置类

我们将为 Spring Security 创建一个新的配置类：`SpringSecurityWebFluxConfig`。首先，我们将使用最重要的注解对类进行注释：`@EnableWebFluxSecurity`。这指示它为 WebFlux Web 应用程序启用 Spring Security。在配置类中，我们将查看两个重要的 bean，如下所示。

# UserDetailsService bean

我们将使用硬编码的用户详细信息进行身份验证。这不是生产就绪应用程序的操作方式，但为了简单起见并解释概念，让我们采取这种捷径：

```java
@Bean
public MapReactiveUserDetailsService userDetailsRepository() {
    UserDetails user = User.withUsername("user")
        .password("{noop}password").roles("USER").build();
    UserDetails admin = User.withUsername("admin")
        .password("{noop}password").roles("USER","ADMIN").build();
    return new MapReactiveUserDetailsService(user, admin);
}
```

该 bean 返回了包含两个用户的硬编码凭据的响应式用户详细信息服务；一个是普通用户，另一个是管理员。

# SpringSecurityFilterChain bean

这是我们实际指定 Spring Security 配置的 bean：

```java
@Bean
SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) 
    throws Exception {
    return http
      .authorizeExchange()
      .pathMatchers(HttpMethod.GET, "/api/movie/**").hasRole("USER")
      .pathMatchers(HttpMethod.POST, "/api/movie/**").hasRole("ADMIN")
      .anyExchange().authenticated()
      .and().formLogin()
      .and().build();
}
```

与我们之前在 Spring MVC 应用程序中看到的类似，我们匹配 URL 模式并指定访问所需的角色。我们正在将登录方法配置为一个表单，用户将通过 Spring Security 显示默认登录表单。

# 运行应用程序

执行以下命令：

```java
mvn spring-boot:run
```

服务器启动时，您有两种方式可以测试应用程序，如下所示。

# CURL

打开您喜欢的命令提示符并执行以下命令：

```java
curl http://localhost:8080/ -v
```

您将被重定向到`http://localhost:8080/login`页面。您的整个应用程序都是安全的，如果不登录，您将无法访问任何内容。使用表单登录作为方法，您将无法使用`curl`进行测试。让我们将登录方法从表单（`formLogin`）更改为基本（`httpBasic`）在 Spring Security 配置（`springWebFilterChain` bean）中。现在，执行以下命令：

```java
curl http://localhost:8080/api/movie -v -u admin:password
```

现在，您应该看到显示所有硬编码电影的原始 JSON。使用其他常见的 CURL 命令，如下所示，测试其他端点：

```java
curl http://localhost:8080/api/movie/1 -v -u admin:password
```

# 浏览器

让我们将登录方法改回表单，然后打开浏览器并导航到`http://localhost:8080`。您将被导航到默认的 Spring Security 登录页面。输入用户名为`admin`，密码为`password`，然后单击登录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/fe1f91c0-67a5-4870-8c70-74d01fe378db.png)

图 9：默认的 Spring Security 登录表单

成功登录后，您将被导航到列出所有电影的端点，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/7a0cd37d-e33b-4bb0-b2e5-64c2b9957c34.png)

图 10：登录后默认主页上列出所有电影

# WebClient

在该书的 GitHub 页面上，我们有一个单独的项目（`spring-boot-security-webclient-webflux`），您可以在其中看到本节中将详细介绍的整个代码。

# Maven 设置

创建一个基本的 maven 项目，并将以下主要依赖项添加到您的`pom.xml`文件中：

```java
<!--Spring Framework and Spring Boot-->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
```

现在，添加其他依赖项，以及默认的 Spring Boot 构建部分。

# 创建一个 WebClient 实例

`WebClient`实例可以通过使用`create()`方法或使用`builder()`方法来创建。在我们的示例中，我们使用了`builder()`方法，如下所示：

```java
@Service
public class WebClientTestImpl implements WebClientTestInterface {
    private final WebClient webClient;
    public WebClientTestImpl(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.defaultHeader(HttpHeaders.ACCEPT,     
        MediaType.APPLICATION_JSON_VALUE)
              .baseUrl("http://localhost:8080/api/movie").build();
    }
    //...Other methods
}
```

我们将使用我们在基本 Spring WebFlux 项目中创建的所有端点，并将使用`WebClient`访问它们。

使用`create()`方法创建`WebClient`的实例，如下所示：

```java
WebClient webClient = WebClient.create();
```

如果您有基本 URL，则可以创建`WebClient`如下：

```java
WebClient webClient = WebClient.create("http://localhost:8080/api/movie");
```

`builder()`方法提供了一堆实用方法，如过滤器、设置标头、设置 cookie 等。在我们的示例中，我们设置了一些默认标头，并设置了基本 URL。

# 处理错误

`WebClient`实例允许您处理错误（`WebClientTestImpl`类）在`listMovies()`方法中，如下所示：

```java
@Override
public Flux<Movie> listMovies() {
    return webClient.get().uri("/")
        .retrieve()
        .onStatus(HttpStatus::is4xxClientError, clientResponse ->
            Mono.error(new SampleException())
        )
        .onStatus(HttpStatus::is5xxServerError, clientResponse ->
            Mono.error(new SampleException())
        )
        .bodyToFlux(Movie.class);
}
```

`SampleException`是我们通过扩展`Exception`类创建的自定义异常类。我们正在处理 4xx 和 5xx 错误，并且在遇到时，它会将自定义异常作为响应发送。

# 发送请求和检索响应

`retrieve()`方法是一个简单的方法，可以用来检索响应主体。如果您想对返回的响应有更多控制，可以使用`exchange()`方法来检索响应。我们在示例应用程序中使用了这两种方法；`WebClientTestImpl`类中这两种方法的代码片段如下：

```java
@Override
public Mono<Movie> getMovieById(Long id) 
  return this.webClient.get().uri("/{id}", id)
          .retrieve().bodyToMono(Movie.class);
}
@Override
public Mono<Movie> saveMovie(Movie movie) {
  return webClient.post().uri("/")
          .body(BodyInserters.fromObject(movie))
          .exchange().flatMap( clientResponse ->     
            clientResponse.bodyToMono(Movie.class) );
}
```

在第一种方法中，我们在 URI `http://localhost:8080/api/movie/{id}` 上执行 GET 方法，使用`retrieve()`方法，然后转换为`Mono`。

在第二种方法中，我们在 URL `http://localhost:8080/api/movie` 上执行 POST 方法，使用`exchange()`方法，并使用`flatMap()`方法创建响应。

# 运行和测试应用程序

在这个示例项目中，我们将使用相同的电影模型。由于这是我们从之前的示例应用程序中需要的唯一类，我们将在这里复制该类。在理想情况下，我们将有一个包含所有公共类的 JAR 文件，并且可以将其包含在我们的`pom.xml`文件中。

创建`Run`类（如前所示）并调用`WebClient`方法。其中一个方法的代码片段如下：

```java
@SpringBootApplication
public class Run implements CommandLineRunner {
  @Autowired
  WebClientTestInterface webClient;
  public static void main(String[] args) {
      SpringApplication.run(Run.class, args);
  }
  @Override
  public void run(String... args) throws Exception {
      // get all movies
      System.out.println("Get All Movies");
      webClient.listMovies().subscribe(System.out::println);
      Thread.sleep(3000);
      … Other methods
  }
  //… Other WebClient methods getting called
}
```

在执行每个`WebClient`调用后，我们将休眠三秒。由于`WebClient`方法发出反应类型（`Mono`或`Flux`），您必须订阅，如前面的代码所示。

启动`spring-boot-webflux`项目，暴露端点，我们将使用此项目中的`WebClient`进行测试。

确保在您的`application.properties`文件中更改应用程序的默认端口，包括以下条目：

```java
server.port=8081
```

通过执行 Spring Boot 命令启动应用程序，如下所示：

```java
mvn spring-boot:run
```

如果一切顺利，您应该在服务器控制台中看到输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-sprsec5-rct-app/img/22f55554-5b13-4aa5-aeeb-10c9acc37545.png)

图 11：WebClient 测试执行

# 单元测试（WebTestClient）

在我们的基本`spring-boot-webflux`项目中，我们使用`WebTestClient`编写了测试用例。我们有两个测试用例：一个是获取所有电影，另一个是保存电影。

# Maven 依赖

确保在您的`pom.xml`文件中有以下依赖项：

```java
<!--Testing-->
<dependency>
  <groupId>junit</groupId>
  <artifactId>junit</artifactId>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-test</artifactId>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>org.skyscreamer</groupId>
  <artifactId>jsonassert</artifactId>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>io.projectreactor</groupId>
  <artifactId>reactor-test</artifactId>
  <scope>test</scope>
</dependency>
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-test</artifactId>
  <scope>test</scope>
</dependency>
```

如您所见，在前面的代码中，所有依赖项都可以用于测试目的。

# 测试类

创建一个普通的测试类，如下所示。在测试类中使用`@Autowired`注解来注入`WebTestClient`实例：

```java
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class WebclientDemoApplicationTests {
  @Autowired
  private WebTestClient webTestClient;
  @Test
  public void getAllMovies() {
      System.out.println("Test 1 executing getAllMovies");
      webTestClient.get().uri("/api/movie")
              .accept(MediaType.APPLICATION_JSON)
              .exchange()
              .expectStatus().isOk()
              .expectHeader().contentType(MediaType.APPLICATION_JSON)
              .expectBodyList(Movie.class);
  }
  @Test
  public void saveMovie() {
      System.out.println("Test 2 executing saveMovie");
      Movie movie = new Movie(Long.valueOf(10), "Test Title", "Test Genre");
      webTestClient.post().uri("/api/movie")
              .body(Mono.just(movie), Movie.class)
              .exchange()
              .expectStatus().isOk()
              .expectBody();
  }
}
```

`WebTestClient`对象的功能与之前看到的`WebClient`类似。我们可以检查响应中的各种属性，以确定我们要测试的内容。在前面的示例中，对于第一个测试，我们正在发送 GET 请求并检查 OK 状态，应用程序/JSON 内容类型标头，最后，一个包含`Movie`对象列表的主体。在第二个测试中，我们正在发送一个带有`Movie`对象的 POST 请求作为主体，并期望一个 OK 状态和一个空主体。

# Spring Data

尽管本书侧重于响应式概念上的 Spring Security，但我真的希望您也对其他领域的响应式概念有一些了解。因此，有一个单独的项目`spring-boot-security-mongo-webflux`，它通过将之前的项目与响应式 MongoDB 集成，使用 Spring Data 来实现响应式概念。我们不会涵盖与此相关的每个方面。但是，基于之前的项目，我们将在本节中涵盖一些重要方面。

# Maven 依赖

在您的应用程序`pom.xml`中，添加以下依赖项，都涉及将 MongoDB 包含到项目中：

```java
<!--Mongo-->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-mongodb-reactive</artifactId>
</dependency>
<dependency>
  <groupId>de.flapdoodle.embed</groupId>
  <artifactId>de.flapdoodle.embed.mongo</artifactId>
  <scope>test</scope>
</dependency>
```

我已在我的机器上安装了 MongoDB。我已在默认端口（`27017`）上本地启动数据库。

# MongoDB 配置

将以下内容添加到您的 application.properties 文件中：

```java
spring.data.mongodb.uri=mongodb://localhost:27017/movie
```

我们将把我们的数据库指向本地运行的默认端口上的数据库，利用电影数据库。

# 设置模型

在我们已经存在的`Movie`模型中，我们只添加了一个注解：`@Document(collection = "movies")`。此注解将告知 MongoDB 该模型将存储在 DB 中的集合的名称。

# 实现存储库

我们将创建一个新的存储库`ReactiveMovieRepository`，其中包含我们的两个精心策划的方法和我们扩展类提供的所有默认方法：

```java
@Repository
public interface ReactiveMovieRepository extends 
    ReactiveMongoRepository<Movie, Long> {
      @Query("{ 'title': ?0, 'genre': ?1}")
      Flux<Movie> findByTitleAndGenre(String title, String genre);
      @Query("{ 'genre': ?0}")
      Flux<Movie> findByGenre(String genre);
}
```

我们将从`ReactiveMongoRepository`扩展我们的存储库。`ReactiveMongoRepository`有很多通用方法，可以立即使用，毫不费力。我们实现的方法使用普通查询来对 MongoDB 进行操作并返回列表。

# 实现控制器

为了使其与我们现有的基于功能的编程分离，我们创建了一个新的控制器，它将以 RESTful 方式暴露一些方法，使用新创建的`ReactiveMovieRepository`：

```java
@RestController
public class MovieController {
  @Autowired
  private ReactiveMovieRepository reactiveMovieRepository;
  @GetMapping("/movies")
  public Flux<Movie> getAllMovies() {
      return reactiveMovieRepository.findAll();
  }
  @GetMapping("/movies/{genre}")
  public Flux<Movie> getAllMoviesByGenre(@PathVariable String genre) {
      return reactiveMovieRepository.findByGenre(genre);
  }
  @GetMapping("/movies/{title}/{genre}")
  public Flux<Movie> getAllMoviesByTitleAndGenre
    (@PathVariable String title, @PathVariable String genre) {
      return reactiveMovieRepository.findByTitleAndGenre(title, genre);
  }
  @PostMapping("/movies")
  public Mono<Movie> createMovies(@Valid @RequestBody Movie movie) {
      return reactiveMovieRepository.save(movie);
  }
}
```

这个类非常简单；每个方法都有适当的映射，并使用相应的存储库类来实际完成工作。

# 运行应用程序

使用`mongod`命令，我们将启动本地安装的 MongoDB，然后使用以下命令，我们将启动刚刚创建的项目：

```java
mvn spring-boot:run
```

转到 postman 并调用 URL `http://localhost:8080/movies`（GET）。您将看到其中有零个元素的数组。现在，调用 URL `http://localhost:8080/movies`（POST），在请求体中使用以下 JSON：

```java
{
   "id": 1,
   "title": "testtitle",
   "genre": "thriller"
}
```

您将获得一个 200 OK 状态，并应该看到新创建的 JSON 作为响应。现在，如果您在电影端点上运行 GET 请求，您应该会看到新创建的`Movie`作为响应。

在这里，我们通过使用 MongoDB 作为响应式编程范式中的持久存储库，实现了对我们的`Movie`模型的 CRUD。

# 授权

过去，我们已经看到使用`@EnableWebFluxSecurity`注解，我们可以获得 URL 安全性。Spring Security 还允许您以一种响应式的方式保护方法执行，通过使用另一个注解`@EnableReactiveMethodSecurity`。这个概念与我们之前基于 Spring MVC 的示例中看到的是相同的。我们将在本节中只涵盖方法安全性；其他方面完全相同，我们将避免在此重复。

# 方法安全性

要启用方法安全性，首先要用`@EnableReactiveMethodSecurity`注解 Spring Security 配置类：

```java
@EnableReactiveMethodSecurity
public class SpringSecurityWebFluxConfig {
    …
}
```

之后，对于任何您希望具有一些安全功能的方法，使用前几章讨论的各种安全相关注解：

```java
@GetMapping("/movies")
@PreAuthorize("hasRole('ADMIN')")
public Flux<Movie> getAllMovies() {
  return reactiveMovieRepository.findAll();
}
```

在上述方法中，我们指示 Spring Security，如果用户经过身份验证并被授予`ADMIN`角色，则应允许`getAllMovies()`的方法执行。

# 定制

Spring Security 允许进行许多定制。Spring Security 生成的默认页面，如登录表单、注销表单等，可以在所有方面完全定制，以适应您应用程序的品牌。如果您想要调整 Spring Security 的默认执行，实现自己的过滤器是合适的。由于 Spring Security 在很大程度上依赖过滤器来实现其功能，让我们看看在这方面的定制机会。

此外，几乎可以通过使用自己的类来定制 Spring Security 的几乎所有部分，并将其插入 Spring Security 默认流程中以管理自己的定制。

# 编写自定义过滤器

正如我们之前看到的，在 WebFlux Web 应用程序中，Spring Security 基于`WebFilter`（类似于 Spring MVC 中的 Servlet Filter）工作。如果您想要定制 Spring Security 中的某些方面，特别是在请求和响应操作中，实现自定义`WebFilter`是可以考虑的方法之一。

Spring WebFlux 提供了两种实现过滤器的方法：

+   **使用** `WebFilter`：适用于基于注解和基于功能的（`routerhandler`）

+   **使用** `HandlerFilterFunction`：仅适用于基于功能的

# 使用 WebFilter

我们将在我们的项目`spring-boot-webflux`的基础上进行构建。为了使其与其他项目隔离，我们将创建一个新项目`spring-boot-webflux-custom`。如前所述，使用`WebFilter`适用于基于注解和基于功能的 WebFlux 方法。在我们的示例中，我们将有两个路径：`filtertest1`和`filtertest2`。我们将使用`WebFluxTestClient`编写测试用例，并断言某些条件。作为与其他部分分离，我们将创建一个新的路由配置、一个处理程序和一个全新的 REST 控制器。我们不会详细介绍一些已经涵盖的方面。在本节中，我们只会介绍`WebFilter`代码，以及测试用例的一些重要方面：

```java
@Component
public class SampleWebFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange serverWebExchange, 
            WebFilterChain webFilterChain) {
        serverWebExchange.getResponse().getHeaders().add("filter-added-header", 
            "filter-added-header-value");
        return webFilterChain.filter(serverWebExchange);
    }
}
```

`SampleWebFilter`类实现了`WebFilter`，并实现了`filter`方法。在这个类中，我们将添加一个新的响应头，`filter-added-header`：

```java
@Test
public void filtertest1_with_pathVariable_equalTo_value1_apply_WebFilter() {
    EntityExchangeResult<String> result = 
        webTestClient.get().uri("/filtertest1/value1")
        .exchange()
        .expectStatus().isOk()
        .expectBody(String.class)
        .returnResult();
    Assert.assertEquals(result.getResponseBody(), "value1");
    Assert.assertEquals(result.getResponseHeaders()
        .getFirst("filter-added-header"), "filter-added-header-value");
}
@Test
public void filtertest2_with_pathVariable_equalTo_value1_apply_WebFilter() {
    EntityExchangeResult<String> result = 
        webTestClient.get().uri("/filtertest2/value1")
        .exchange()
        .expectStatus().isOk()
        .expectBody(String.class)
        .returnResult();
    Assert.assertEquals(result.getResponseBody(), "value1");
    Assert.assertEquals(result.getResponseHeaders()
        .getFirst("filter-added-header"), "filter-added-header-value");
}
```

在两个测试用例中，我们将检查新添加的头。当您运行测试用例（使用`mvn test`）时，它将确认这一发现。

# 使用 HandlerFilterFunction

我们将实现一个新的`HandlerFilterFunction`，`SampleHandlerFilterFunction`，在其中我们将查看一个路径变量（`pathVariable`）并检查其值。如果该值等于`value2`，我们将标记状态为`BAD_REQUEST`。需要注意的是，由于`HandlerFilterFunction`仅适用于基于功能的，即使路径变量值等于`value2`，状态也不会被标记为`BAD_REQUEST`，而接收到的响应是 OK：

```java
public class SampleHandlerFilterFunction implements 
        HandlerFilterFunction<ServerResponse, ServerResponse> {
    @Override
    public Mono<ServerResponse> filter(ServerRequest serverRequest, 
        HandlerFunction<ServerResponse> handlerFunction) {
        if (serverRequest.pathVariable("pathVariable")
                .equalsIgnoreCase("value2")) {
            return ServerResponse.status(BAD_REQUEST).build();
        }
        return handlerFunction.handle(serverRequest);
    }
}
```

`SampleHandlerFilterFunction`实现了`HandlerFilterFunction`类，并实现了`filter`方法。在这个类中，如果满足条件，我们将明确将响应状态设置为`bad request`：

```java
@Test
public void filtertest1_with_pathVariable_equalTo_value2_apply_HandlerFilterFunction() {
    webTestClient.get().uri("/filtertest1/value2")
        .exchange()
        .expectStatus().isOk();
}
@Test
public void filtertest2_with_pathVariable_equalTo_value2_apply_HandlerFilterFunction() {
    webTestClient.get().uri("/filtertest2/value2")
        .exchange()
        .expectStatus().isBadRequest();
}
```

在前面的测试用例中，测试的路径是不同的，由于`HandlerFilterFunction`仅适用于基于功能的，因此当路径为`filtertest1`时，响应为 OK，当路径为`filtertest2`时，响应为`BAD_REQUEST`。

# 总结

在本章中，我们首次详细介绍了响应式编程，使用了 Spring WebFlux 框架。我们首先从高层次上对框架本身进行了充分的介绍。我们介绍了一个非常基本的例子，然后介绍了 Spring Security 及其在 Spring WebFlux 中的功能。

最后，我们进行了一个实际的编码会话，使用了一个示例应用程序。在这个例子中，我们涵盖了其他响应式方面，比如 Spring Data Mongo，以便让您更深入地了解响应式世界。

我们以 Spring WebFlux 与 Spring Security 中可能的一些自定义结束了本章。

阅读完本章后，您应该清楚了解了 Spring MVC 和 Spring WebFlux 框架之间的区别。您还应该对使用 Spring Security 模块的 Spring WebFlux 安全性有很好的理解。这些示例旨在简单易懂，因为在本书中我们正在介绍 Spring Security，所以在解释中给予了更多的价值。
