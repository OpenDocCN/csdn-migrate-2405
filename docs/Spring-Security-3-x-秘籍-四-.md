# Spring Security 3.x 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD`](https://zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：Spring Security 与 Spring Social

在本章中，我们将涵盖：

+   Spring Security 与 Spring Social 访问 Facebook

+   Spring Security 与 Spring Social 访问 Twitter

+   Spring Security 与多个身份验证提供程序

+   OAuth 的 Spring Security

# 介绍

Spring Social 是一个著名的 API。大多数 Web 应用程序希望为用户提供从其应用程序到社交网络站点（如 Facebook 和 Twitter）的发布选项。Spring Social 是为满足此要求而构建的。

在本章中，我们将集成 Spring Security 与 Spring Social 以连接到 Facebook 和 Twitter 帐户。

# Spring Security 与 Spring Social 访问 Facebook

Spring Social 在身份验证方面使用`spring-security` API。我们需要在`pom.xml`中添加 spring-social 依赖项，以及`spring-core`和`spring-security`包。在本节中，我们将演示 Spring Social 如何将我们的 Java 应用程序与 Facebook 连接起来。我们可以在我们的 Java 应用程序中登录到 Facebook 应用程序。

一旦与社交网络站点建立连接，用户就可以在其中发布和检索消息。

我们使用了相同的 hibernate 恐怖电影应用程序。我使用了 derby 数据库，并在 glassfish 服务器上部署了应用程序。Spring Social 内部使用 Spring 的`jdbctemplate`类来检索数据库信息。

## 准备工作

要使用 Spring Security 与 Spring Social 访问 Facebook，您需要执行以下任务：

+   注册为 Facebook 开发人员并创建应用程序。您将获得可用于集成的 appID 和秘钥

+   将请求映射添加到控制器以处理 Facebook 创建的`jsp`页面以将消息发布到 Facebook

+   创建`UserConnection`表

+   将 Jackson 依赖项添加到您的`pom.xml`文件中。演示项目将随本书提供下载

+   添加 Spring Social 依赖项，如：

+   `Spring-social-core`

+   `Spring-social-web`

+   `Spring-social-facebook`

+   `Spring-social-twitter`

+   `Spring-social-linkedin`

+   `Spring-social-github`

+   为用户登录和注销创建`.jsp`页面

+   在`spring.properties`文件中提供数据库连接属性

+   在`jdbc.properties`文件中提供 Facebook 的应用程序秘钥和 appID

## 如何做...

以下是实现允许用户使用 Spring Social 和 Spring Security 登录到 Facebook 应用程序的应用程序的步骤：

1.  创建名为`MyController`的控制器来处理 Facebook 页面。

```java
  @RequestMapping(value = "/fbprofile", method = RequestMethod.GET)
  public String getfbProfile(ModelMap model,HttpServletRequest request, 
      HttpServletResponse response) {
    model.addAttribute("request.userPrincipal.name", request.getUserPrincipal().getName());
    Facebook facebook = connectionRepository.getPrimaryConnection(Facebook.class).getApi();
    model.addAttribute("profileLink", facebook.userOperations().getUserProfile().getLink());
    model.addAttribute("Gender", facebook.userOperations().getUserProfile().getGender());
    model.addAttribute("profileInfo", facebook.userOperations().getUserProfile());
    model.addAttribute("userpermissions", facebook.userOperations().getUserPermissions());
    List<Reference> friends = facebook.friendOperations().getFriends();
    model.addAttribute("friends", friends);
    model.addAttribute("friendlist", facebook.friendOperations().getFriendLists());
    return "facebookprofile";
  }
```

1.  在`Spring-social.xml`文件中提供连接工厂：

```java
  <bean id="connectionFactoryLocator" class="org.springframework.social.connect.support.ConnectionFactoryRegistry">
    <property name="connectionFactories">
      <list>
        <bean class="org.springframework.social.facebook.connect.FacebookConnectionFactory">
          <constructor-arg value="${facebook.clientId}" />
          <constructor-arg value="${facebook.clientSecret}" />
        </bean>
      </list>
    </property>
  </bean>
```

`ConnectionFactory`定位器创建了 Facebook bean。在这里，您可以添加其他社交网络提供商，如 Digg 和 Flickr。`UsersConnectionRepository`使用 JDBC 模板执行与各种社交网络提供商的连接查询。

1.  在`spring-social.xml`文件中使用连接工厂：

```java
  <bean id="textEncryptor" class="org.springframework.security.crypto.encrypt.Encryptors" factory-method="noOpText" />
  <bean id="usersConnectionRepository" class="org.springframework.social.connect.jdbc.JdbcUsersConnectionRepository">
    <constructor-arg ref="mydataSource" />
    <constructor-arg ref="connectionFactoryLocator" />
    <constructor-arg ref="textEncryptor" />
  </bean>
  <bean id="connectionRepository" factory-method="createConnectionRepository" factory-bean="usersConnectionRepository" scope="request">
      <constructor-arg value="#{request.userPrincipal.name}" />
      <aop:scoped-proxy proxy-target-class="false"/>
  </bean>
```

1.  在`spring-social`文件中配置`ConnectController`类。`ConnectController`类在连接到提供程序时起着重要作用。它与(`/connect`) URL 映射。为了充分利用`ConnectController`类，为 Facebook 和 Twitter 创建单独的文件夹。

```java
  <bean class="org.springframework.social.connect.web.ConnectController"
    p:applicationUrl="${application.url}"/>
```

1.  在您的 derby 数据库中运行 SQL 命令。

```java
create table UserConnection (userId varchar(255) not null,
  providerId varchar(255) not null,
  providerUserId varchar(255),
  rank int not null,
  displayName varchar(255),
  profileUrl varchar(512),
  imageUrl varchar(512),
  accessToken varchar(255) not null,
  secret varchar(255),
  refreshToken varchar(255),
  expireTime bigint,
  primary key (userId, providerId, providerUserId));

create unique index UserConnectionRank on UserConnection(userId, providerId, rank);
```

## 它是如何工作的...

Spring Social 使用`UserConnection`表存储网络站点提供程序信息以及用户信息。Spring Social 使用 Spring Security 以及 appID 和秘钥对用户进行身份验证。

访问 URL：`http://localhost:8080/horrormovie/list`

您将被重定向到`http://localhost:8080/horrormovie/login;jsessionid=581813e14c1752d2260521830d3d`。

使用用户名和密码登录。您将连接到`horromovie`数据库，如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_09_01.jpg)

单击**连接到 Facebook 个人资料**链接，用户将被重定向到以下网页：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_09_02.jpg)

该页面显示以下字段：

+   个人资料链接

+   性别

+   个人资料信息

+   发布消息到 Facebook 的文本框

您可以从此应用程序发布消息，然后打开 Facebook 个人资料以查看已发布的消息。该消息将以您创建的 Facebook 应用程序的名称发布。

## 另请参阅

+   *使用 Spring Social 访问 Twitter 的 Spring 安全*示例

+   *使用多个身份验证提供程序的 Spring 安全*示例

+   *使用 OAuth 进行 Spring 安全*示例

# 使用 Spring Social 访问 Twitter 的 Spring 安全

我们刚刚连接了 Facebook 并能够发布消息。在本节中，我们将看到如何连接 Twitter。让我们使用与 Facebook 相同的应用程序，该应用程序使用 derby 数据库和 hibernate 身份验证服务。

## 准备工作

您需要执行以下任务，以使用 Spring Social 和 Spring Security 访问 Twitter：

+   创建一个 Twitter 应用程序：[`dev.twitter.com/apps/new`](https://dev.twitter.com/apps/new)

+   将消费者 ID 和密钥添加到`.properties`文件中。

+   更新控制器以处理 Twitter 请求

+   创建 JSP 文件以访问和显示 Twitter 对象

## 如何做...

以下是在上一节演示的应用程序中实现 Twitter 登录选项的步骤：

1.  更新名为`HorrorMovie Controller`的控制器以处理 Twitter 请求。

```java
< @RequestMapping(value = "/posttofb", method = RequestMethod.GET)
  public String posttofb(String message, ModelMap model) {
    try {
      Facebook facebook = connectionRepository.getPrimaryConnection(Facebook.class).getApi();
      facebook.feedOperations().updateStatus(message);
      model.addAttribute("status", "success");
      model.addAttribute("message", message);
      return "redirect:/list";
    } catch (Exception e) {
      model.addAttribute("status", "failure");
      return "/facebook/fbconnect";
    }
  }
  @RequestMapping(value = "/twprofile", method = RequestMethod.GET)
  public String gettwProfile(ModelMap model) {
    try{
      Twitter twitter = connectionRepository.getPrimaryConnection(Twitter.class).getApi();
      model.addAttribute("twprofileLink", twitter.userOperations().getUserProfile().getUrl());
      model.addAttribute("twprofileInfo", twitter.userOperations().getUserProfile());
      model.addAttribute("twfollowers", twitter.friendOperations().getFollowers());
      model.addAttribute("twfriends", twitter.friendOperations().getFriends());
      return "/twitter/twitterprofile";
    } catch (Exception e) {
      model.addAttribute("status", "failure");
      return "/twitter/twconnect";
    }
  }
  @RequestMapping(value = "/posttotw", method = RequestMethod.GET)
  public String posttotw(String message, ModelMap model) {
    try {
      Twitter twitter = connectionRepository.getPrimaryConnection(Twitter.class).getApi();
      twitter.timelineOperations().updateStatus(message);
      model.addAttribute("status", "success");
      model.addAttribute("message", message);
      return "redirect:/list";
    } catch (Exception e) {
      model.addAttribute("status", "failure");
      return "/twitter/twconnect";
    }
  }
```

## 工作原理...

访问 URL：`http://localhost:8080/horrormovie/list.`

Spring Social 将检查用户是否已连接到 Twitter。如果用户已经连接，用户将被重定向到 Twitter 页面并被要求登录。Spring Social 使用 Twitter 消费者 ID 和密钥与 Spring Security 一起从应用程序登录到 Twitter 帐户。这是大多数手机应用程序允许我们登录到 Twitter 和 Facebook 的基础。

## 另请参阅

+   *使用 Spring Social 访问 Facebook 的 Spring 安全*示例

+   *使用多个身份验证提供程序的 Spring 安全*示例

+   *使用 OAuth 进行 Spring 安全*示例

# 具有多个身份验证提供程序的 Spring 安全

在本节中，我们将演示使用 Spring Social 和数据库进行多重身份验证。在我们之前的示例中，我们使用了`ConnectController`类来处理 Facebook 和 Twitter 的连接。对 Facebook 和 Twitter 的访问受限于 Spring Security URL，即只有`ROLE_EDITOR`可以访问 Facebook 和 Twitter。用户必须经过身份验证和授权才能使用 Facebook 和 Twitter。在本例中，我们将允许用户使用 Facebook 和 Twitter 或普通用户 ID 登录应用程序。

*Craig Walls*是 Spring Social API 的负责人，并在 gitHub 上提供了各种示例，其中使用了 Spring Social 和 Spring Security。这是*Craig Walls*提供的示例之一。

## 准备工作

您需要执行以下任务：

1.  创建一个通用页面，以用户身份登录或使用 Twitter、Facebook 或 linked-in 配置文件进行注册。

1.  Spring Social API 具有`ConnectController`类，该类会自动查找连接文件夹。创建一个连接文件夹，添加`${provider}Connect.jsp`和`${provider} Connected.jsp。$provider{twitter,facebook,linked-in,github}`

1.  Spring Social 在内部使用`spring-security`。它有自己的用户详细信息类——`SocialUserDetailsService`。创建一个实现`SocialUserDetailsService`并覆盖该方法的类。

1.  在`social-security.xml`文件中配置社交认证提供程序。`SocialAuthenticationProvider`类接受两个输入，例如：

+   `usersConnectionRepository`

+   `socialuserDetailsService`——实现`SocialUserDetailsService`的类

1.  在`security-xml`中配置多个身份验证提供程序：

+   `SocialAuthenticationProvider`

+   `UserDetailsService`，提供用户详细信息服务的 jdbc 接口

1.  配置`SocialAuthenticationFilter`过滤器，以处理 Spring Security 过滤器链中的提供程序登录流程。它应该被添加到`PRE_AUTH_FILTER`位置或之前的位置。

## 如何做...

以下是使用 Spring Security 实现多个提供程序进行身份验证的步骤：

1.  使用`SocialUsersDetailServiceImpl`类来实现`SocialUserDetailsService`类：

```java
public class SocialUsersDetailServiceImpl implements SocialUserDetailsService {
  private UserDetailsService userDetailsService;
  public SocialUsersDetailServiceImpl(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }
  @Override
    public SocialUserDetails loadUserByUserId(String userId) throws UsernameNotFoundException, DataAccessException {
    UserDetails userDetails = userDetailsService.loadUserByUsername(userId);
    return new SocialUser(userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
  }}
```

1.  在`Security.xml`文件中配置`SocialAuthenticationProvider`类：

```java
  <bean id="socialAuthenticationProvider" class="org.springframework.social.security.SocialAuthenticationProvider"
    c:_0-ref="usersConnectionRepository"
    c:_1-ref="socialUsersDetailService" />
  <bean id="socialUsersDetailService" class="org.springframework.social.showcase.security.SocialUsersDetailServiceImpl"
    c:_-ref="userDetailsService" />
```

1.  在`Security.xml`文件中配置多个身份验证提供程序：

```java
  <authentication-manager alias="authenticationManager">
    <authentication-provider user-service-ref="userDetailsService">
      <password-encoder ref="passwordEncoder" />
    </authentication-provider>
    <!-- Spring Social Security authentication provider -->
    <authentication-provider ref="socialAuthenticationProvider" />
 </authentication-manager>
  <jdbc-user-service id="userDetailsService" data-source-ref="dataSource" users-by-username-query="select username, password, true from Account where username = ?"
      authorities-by-username-query="select username, 'ROLE_USER' from Account where username = ?"/>
  <beans:bean id="textEncryptor" class="org.springframework.security.crypto.encrypt.Encryptors"
    factory-method="noOpText" />
  <beans:bean id="passwordEncoder" class="org.springframework.security.crypto.password.NoOpPasswordEncoder"
    factory-method="getInstance" />
```

1.  在`Social-security.xml`文件中配置`SocialAuthenticationFilter`类：

```java
<bean id="socialAuthenticationFilter" class="org.springframework.social.security.SocialAuthenticationFilter"
    c:_0-ref="authenticationManager"
    c:_1-ref="userIdSource"
    c:_2-ref="usersConnectionRepository"
    c:_3-ref="connectionFactoryLocator"
    p:signupUrl="/spring-social-showcase/signup"
    p:rememberMeServices-ref="org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices#0" />
```

1.  在`security.xml`文件中配置`SocialAuthenticationFilter`类与安全：

```java
<http use-expressions="true">
    <!-- Authentication policy -->
    <form-login login-page="/signin" login-processing-url="/signin/authenticate" authentication-failure-url="/signin?param.error=bad_credentials" />
    <logout logout-url="/signout" delete-cookies="JSESSIONID" />
    <intercept-url pattern="/favicon.ico"access="permitAll" />
    <intercept-url pattern="/resources/**" access="permitAll" />
    <intercept-url pattern="/auth/**" access="permitAll" />
    <intercept-url pattern="/signin/**" access="permitAll" />
    <intercept-url pattern="/signup/**" access="permitAll"/>
    <intercept-url pattern="/disconnect/facebook" access="permitAll" />
    <intercept-url pattern="/**" access="isAuthenticated()"/>
    <remember-me />
    <!--  Spring Social Security authentication filter -->
    <custom-filter ref="socialAuthenticationFilter" before="PRE_AUTH_FILTER" />
  </http>
```

## 它是如何工作的...

在这个实现中，用户可以通过数据库中的一些凭据或使用社交网络站点的 ID 和密码登录应用程序。`SocialAuthenticationProvider`类与`SocialAuthenticationFilter`处理对社交网络站点的身份验证，`UserDetailsService`管理数据库身份验证。这两个类在`security.xml`文件中配置。

以下是实施的工作流程。访问 URL：`http://localhost:8080/spring-social-showcase-sec-xml/signin`。您将被引导到以下网页：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_09_03.jpg)

## 另请参阅

+   *使用 Spring Security 与 Spring Social 访问 Facebook*配方

+   *使用 Spring Security 与 Spring Social 访问 Twitter*配方

+   *使用 Spring Security 与 OAuth*配方

# Spring Security 与 OAuth

OAuth 身份验证已被许多应用程序广泛使用。OAuth 是一种协议，通过该协议，应用程序可以以安全的方式共享数据。例如，考虑一个简单的场景，其中一个照片分享应用程序允许用户上传照片，第二个应用程序集成了所有照片存储应用程序，如 Flickr、Dropbox 和类似的网站。当第二个应用程序想要访问第一个应用程序以打印已上传的照片时，它使用 OAuth 身份验证来从用户那里获得确认以访问照片。理想情况下，它在应用程序之间交换一些安全令牌，即，消费者的私钥和服务器的公钥应匹配以使授权成功。

第一个应用程序充当服务器，第二个应用程序充当想要访问某些经过身份验证的数据的消费者。

客户端和服务器应用程序之间交换的一些参数如下：

+   `Oauth_consumerKey`：我们可以使用应用程序生成 OAuth 请求

+   `Oauth_token`：此令牌被编码并传递到 URL

+   `Oauth_timestamp`：此参数与 nonce 一起添加到每个请求中，以防止服务请求被再次使用，称为重放攻击

+   `Oauth_version`：这定义了正在使用的 OAuth 协议的版本

+   `Oauth_signaturemethod`：此参数用于签名和验证请求

+   `Oauth_nonce`：此参数与时间戳一起使用

+   `Size`：此参数定义文件的大小

+   `File`：此参数定义文件的名称

让我们开发一个样本客户端-服务器应用程序来演示 Spring Security 的 OAuth：

+   服务器应用程序：让我们想象一个电影故事应用程序。该应用程序接受用户的故事。用户可以将他们的故事上传到应用程序。这个应用程序的行为类似于服务提供商。用户写一些恐怖故事并将它们提交给电影制作公司。

+   客户端应用程序：想象另一个电影制作公司的应用程序，该应用程序接受从服务器应用程序上传的故事。电影制作公司必须从电影故事应用程序获取授权以下载故事。

## 准备工作

执行以下任务，将 Spring Security 与 OAuth 集成：

+   创建一个带有`ConfirmAccessController`和`StoryController`类的服务器应用程序

+   创建一个客户端应用程序以访问服务器数据

+   将`spring-security-oauth`依赖项添加到`pom.xml`文件

## 如何做...

以下是将`spring-security`与`spring-oauth`集成的步骤：

1.  为故事创建`CreateStoryController`类。

```java
@Controller
public class CreateStoryController {
  @RequestMapping(value="/stories", method=RequestMethod.GET)
  @ResponseBody
  public String loadStory() {
    StringBuilder horrorStory = new StringBuilder();
    horrorStory.append("Story Name -- Conjuring: Author").append(getAuthorName()).append(" Story:She and that girl and occasionally another girl went out several times a week, and the rest of the time Connie spent around the house—it was summer vacation—getting in her mother's way and thinking, dreaming about the boys she met. But all the boys fell back and dissolved into a single face that was not even a face but an idea, a feeling, mixed up with the urgent insistent pounding of the music and the humid night air of July. Connie's mother kept dragging her back to the daylight by finding things for her to do or saying suddenly, 'What's this about the Pettinger girl?");
    return horrorStory.toString();
  }
  private String getAuthorName() {
    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    String author;
    if (principal instanceof UserDetails) {
      author = ((UserDetails)principal).getUsername();
    } else {
      author = principal.toString();
    }
    return author;
  }
}
```

1.  创建`ConfirmAccessController`类。

```java
@Controller
public class ConfirmAccessController {
  private ClientAuthenticationCache clientauthenticationCache = new DefaultClientAuthenticationCache();
  private ClientDetailsService clientDetailsService;
  public ClientAuthenticationCache getAuthenticationCache() {
    return clientauthenticationCache;
  }
  @RequestMapping(value="/oauth/confirm_access")
  public ModelAndView accessConfirmation(HttpServletRequest request, HttpServletResponse response) {
    ClientAuthenticationToken clientAuthtoken = getAuthenticationCache().getAuthentication(request, response);
    if (clientAuthtoken == null) {
      throw new IllegalStateException("We did not recive any client authentication to authorize");
    }
    ClientDetails client = getClientDetailsService().loadClientByClientId(clientAuthtoken.getClientId());
    TreeMap<String, Object> model = new TreeMap<String, Object>();
    model.put("auth_request", clientAuthtoken);
    model.put("client", client);
    return new ModelAndView("access_confirmation", model);
  }
  public ClientDetailsService getClientDetailsService() {
    return clientDetailsService;
  }
  @Autowired
  public void setClientDetailsService(
      ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }
}
```

1.  配置 Spring 安全与 OAuth。

```java
<!-- Root Context: defines shared resources visible to all other web components -->
  <http auto-config='true'>
  <intercept-url pattern="/**" access="ROLE_EDITOR" />
  </http>
 <authentication-manager>
 <authentication-provider>
 <user-service>
 <user name="anju" password="anju123" authorities="ROLE_EDITOR" />
 </user-service>
 </authentication-provider>
 </authentication-manager>
 <!--apply the oauth client context -->
 <oauth:client token-services-ref="oauth2TokenServices" />
 <beans:bean id="oauth2TokenServices"
 class="org.springframework.security.oauth2.consumer.token.InMemoryOAuth2ClientTokenServices" />
 <oauth:resource id="story" type="authorization_code"
 clientId="movie" accessTokenUri="http://localhost:8080/story/oauth/authorize"
 userAuthorizationUri="http://localhost:8080/story/oauth/user/authorize" />
 <beans:bean id="storyService" class="org.springsource.oauth.StoryServiceImpl">
 <beans:property name="storyURL" value="http://localhost:8080/story/stories"></beans:property>
 <beans:property name="storyRestTemplate">
 <beans:bean class="org.springframework.security.oauth2.consumer.OAuth2RestTemplate">
 <beans:constructor-arg ref="story"/>
 </beans:bean>
 </beans:property>
 <beans:property name="tokenServices" ref="oauth2TokenServices"></beans:property>
 </beans:bean>
</beans:beans>

```

## 它是如何工作的...

您必须首先访问`movieCompanyapp`站点。`movieCompanyapp`反过来从`storyapp`站点获取故事。因此，我们必须在相同的端口上部署这两个应用程序。

我们创建了两个用户（`raghu`/`raghu123`用于`movieCompanyapp`和`anju`/`anju123`用于`storyapp`）。当用户单击**从 storyapp 获取故事**链接时，用户将被要求再次登录。这次用户必须输入他们的凭据，然后他们将能够阅读故事。

访问 URL：`http://localhost:8080/movieCompanyapp/spring_security_login;jsessionid=3b654cf3917d105caa7c273283b5`

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_09_04.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_09_05.jpg)

您将被要求授权以向公司展示故事。这发生在`storyapp`应用程序中。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_09_06.jpg)

授权后，故事将在`movieCompanyapp`中可用。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_09_07.jpg)

## 另请参阅

+   *使用 Spring Social 访问 Facebook 的 Spring 安全*配方

+   *使用 Spring Social 访问 Twitter 的 Spring 安全*配方

+   *具有多个身份验证提供程序的 Spring 安全*配方


# 第十章：Spring 安全与 Spring Web 服务

在本章中，我们将涵盖：

+   在 RESTful web 服务上应用 Spring Security

+   使用 cURL 工具为 Spring RESTful web 服务配置 Spring Security

+   将 Spring Security 与 Apache CXF RESTful 服务集成

+   将 Spring Security 与 Apache CXF 基于 SOAP 的 web 服务集成

+   将 Spring Security 与 Apache Camel 集成

# 介绍

**SOAP**（**Simple Object Access Protocol**）是基于 XML 的 web 服务。它用于在 web 服务之间传输请求和响应消息。

**REST**（**Representational State Transfer**）是一种以 XML、文本或 JSON 文件形式通过 HTTP 协议发送数据的手段。

在本节中，我们将向 web 服务应用 Spring Security。任何 web 服务的正常流程是将服务 WSDL 或 URL 暴露给最终用户。在应用 Spring Security 后，最终用户可以被验证和授权使用服务。

# 在 RESTful web 服务上应用 Spring Security

REST 已成为提供 web 服务的另一种手段。

数据可以使用 XML、文本或 JSON 格式在应用程序之间共享。REST web 服务被认为是轻量级的 web 服务。

让我们应用 Spring Security 来访问 REST web 服务，以便只有经过授权的用户才能访问 RESTful web 服务。由于 RESTful web 服务是通过 URL 访问并使用 HTTP 协议，我们可以轻松应用 URL 级别的安全性。此示例演示了基于表单的身份验证。但用户也可以使用基本和摘要身份验证。

以下是与 Spring 一起使用的注释，用于生成 RESTful web 服务：

+   `@PathVariable`

+   `@RequestMapping`

+   `@RequestMethod`

## 准备工作

+   使用 Spring web 服务 API 创建一个 RESTful web 服务

+   添加 Spring Security 依赖项

+   将 Spring 过滤器配置添加到`Web.xml`文件中

+   配置`application-security.xml`文件

+   创建一个`AccessController`类来处理登录和注销操作

+   在应用程序中配置 Spring Security 以对用户进行身份验证

## 如何做...

以下是将 RESTful web 服务与 Spring Security 集成的步骤：

1.  让我们创建一个`BookController`类，其中包含`@PathVariable`，如下面的代码片段所示：

```java
package org.springframework.rest;
@Controller
public class BookController {
  private static final Map<Integer, Books> books = new HashMap<Integer, Books>();
  static {
    try {
      books.put(1, new Books(1, "Someone Like You", "Penguin", "Durjoy Datta-Nikita Singh"));
      books.put(2, new Books(2, "The Secret Wish List", "Westland", " Preeti Shenoy"));
      books.put(3, new Books(3, "Love Stories That Touched My Heart ", "Metro Reads", " Preeti Shenoy"));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  @RequestMapping(value = "/books/{book_id}", method = RequestMethod.GET)
  @ResponseBody
  public Books findCharacter(@PathVariable int book_id) {
    return books.get(book_id);
  }
}
```

1.  创建一个`Books` POJO 类，其中包含`@JsonAutoDetect`注释，如下面的代码片段所示：

```java
@JsonAutoDetect
public class Books {
    private int book_id;
    private String book_name;
    private String book_publication;
    private String book_author;
    public Books(int book_id, String book_name, String book_publication, String book_author) {
      this.book_id = book_id;
      this.book_name = book_name;
      this.book_publication = book_publication;
      this.book_author = book_author;
    }
    public String getBook_author() {
      return book_author;
    }
    public void setBook_author(String book_author) {
      this.book_author = book_author;
    }
    public int getBook_id() {
      return book_id;
    }
    public void setBook_id(int book_id) {
      this.book_id = book_id;
    }
    public String getBook_name() {
      return book_name;
    }
    public void setBook_name(String book_name) {
      this.book_name = book_name;
    }
    public String getBook_publication() {
      return book_publication;
    }
    public void setBook_publication(String book_publication) {
      this.book_publication = book_publication;
    }
}
```

1.  创建一个`AccessController`类来处理登录和注销操作：

```java
package org.springframework.booksservice;
@Controller
public class AccessController {
  @RequestMapping(value = "/", method = RequestMethod.GET)
  public String defaultPage(ModelMap map) {
    return "redirect:/login";
  }
  @RequestMapping(value = "/login", method = RequestMethod.GET)
  public String login(ModelMap model) {
    return "login";
  }
  @RequestMapping(value = "/accessdenied", method = RequestMethod.GET)
  public String loginerror(ModelMap model) {
    model.addAttribute("error", "true");
    return "denied";
  }
  @RequestMapping(value = "/logout", method = RequestMethod.GET)
  public String logout(ModelMap model) {
    return "logout";
  }
}
```

1.  配置`Application-security.xml`文件，如下面的代码片段所示：

```java
  <http auto-config="false"  use-expressions="true">
    <intercept-url pattern="/login" access="permitAll" />
    <intercept-url pattern="/logout" access="permitAll" />
    <intercept-url pattern="/accessdenied" access="permitAll" />
    <intercept-url pattern="/**" access="hasRole('ROLE_EDITOR')" />
    <form-login login-page="/login" default-target-url="/books" authentication-failure-url="/accessdenied" />
    <logout logout-success-url="/logout" />
  </http>
  <authentication-manager>
    <authentication-provider>
    <user-service>
      <user name="anjana" password="packt123" authorities="ROLE_EDITOR" />
    </user-service>
  </authentication-provider>
</authentication-manager>
```

## 工作原理...

访问 URL：`http://localhost:8080/booksservice/books/1`。这是基于 REST 的 URL，使用 Spring Security 限制了访问。当用户调用基于 REST 的 web 服务 URL 时，Spring Security 将用户重定向到登录页面。在成功验证后，用户将被重定向到授权的基于 REST 的 web 服务页面。

以下是基于 REST 的应用程序与 Spring Security 的工作流程。您将被重定向到登录页面，如下面的屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_01.jpg)

在认证和授权后，您将能够访问 RESTful web 服务，如下面的屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_02.jpg)

## 另请参阅

+   *将 Spring Security 与 Apache CXF RESTful web 服务集成*配方

+   *将 Spring Security 与 Apache CXF 基于 SOAP 的 web 服务集成*配方

+   *将 Spring Security 与 Apache Camel 集成*配方

# 使用 cURL 工具为 Spring RESTful web 服务配置 Spring Security

在这个例子中，我们明确使用 Spring Security API 类和接口。我们将使用`curl`命令对 RESTful web 服务进行身份验证。使用 cURL 工具，您可以通过 URL 传输数据。它可以用来测试身份验证。这是一个相同的书籍服务示例，其中包含一些明确的 Spring Security 相关 API 类，如`AuthenticationEntryPoint`和`SimpleURLAuthenticationSuccessHandler`。在这里，目标是演示它们在 Spring Security 中的内部使用。

## 准备工作

+   实现`AuthenticationEntryPoint`接口并在 XML 文件中进行配置

+   扩展`SimpleUrlAuthenticationSuccessHandler`并在 XML 文件中进行配置

+   配置`Application-security.xml`文件

+   将安全相关的过滤器添加到`Web.xml`文件

+   下载适用于您操作系统的 cURL 工具

## 如何做...

以下是使用`AuthenticationEntryPoint`接口和`SimpleURLAuthenticationSuccessHandler`类应用 Spring Security 身份验证和授权机制的步骤：

1.  `AuthenticationEntryPoint`类是身份验证的入口类，它实现了`AuthenticationEntryPointImpl`类。

```java
public final class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
  @Override
  public void commence(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException authException) throws IOException {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
  }
}
```

1.  扩展`SimpleURLAuthenticationSuccessHandler`类，如下面的代码片段所示：

```java
  public class MySimpleUrlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private RequestCache requestCache = new HttpSessionRequestCache();
    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws ServletException, IOException {
      final SavedRequest savedRequest = requestCache.getRequest(request, response);
      if (savedRequest == null) {
        clearAuthenticationAttributes(request);
        return;
      }
      final String targetUrlParameter = getTargetUrlParameter();
      if (isAlwaysUseDefaultTargetUrl() || (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
        requestCache.removeRequest(request, response);
        clearAuthenticationAttributes(request);
        return;
      }
      clearAuthenticationAttributes(request);
    }
    public void setRequestCache(final RequestCache requestCache) {
      this.requestCache = requestCache;
    }
  }
```

1.  配置`Application-security.xml`文件。

```java
  <http entry-point-ref="authenticationEntryPoint">
    <intercept-url pattern="/**" access="ROLE_EDITOR"/>
    <form-login authentication-success-handler-ref="mySuccessHandler" />
    <logout />
  </http>
  <beans:bean id="mySuccessHandler"class="org.springframework.booksservice.MySimpleUrlAuthenticationSuccessHandler"/>
  <beans:bean id="authenticationEntryPoint"class="org.springframework.booksservice.AuthenticationEntryPointImpl"/>
  <authentication-manager>
    <authentication-provider>
      <user-service>
        <user name="anjana" password="packt123" authorities="ROLE_EDITOR" />
      </user-service>
    </authentication-provider>
  </authentication-manager>
  </beans:beans>
```

## 它是如何工作的...

现在访问 URL：`http://localhost:8080/booksservice/books/1`

您将看到一个页面，上面写着您没有权限查看页面。

让我们使用 cURL 工具，它会给我们一个 cookie。`200 OK`消息意味着我们已经通过身份验证。

```java
Command: curl -i -X POST -d j_username=anjana -d j_password=packt123 http://localhost:8080/booksservice/j_spring_security_check
curl -i --header "Accept:application/json" -X GET -b cookies.txt http://localhost:8080/booksservice/books/1

```

cookie 存储在名为`mycookies.txt`的文件中。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_03.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_04.jpg)

## 另请参阅

+   *将 Spring Security 与 Apache CXF RESTful web 服务集成*的方法

+   *将 Spring Security 与 Apache CXF 基于 SOAP 的 web 服务集成*的方法

+   *将 Spring Security 与 Apache Camel 集成*的方法

# 将 Spring Security 与 Apache CXF RESTful web 服务集成

在这一部分，让我们创建一个 Apache CXF RESTful web 服务。这是一个开源的 web 服务框架。让我们为这个演示使用基本身份验证。

CXF 支持契约优先和契约后的 web 服务。它还支持 RESTful web 服务。

让我们将 Spring Security 与 CXF 集成，并授权 RESTful web 服务。

## 准备工作

+   将`cxf`依赖项添加到`pom`文件中

+   使用 CXF 设置 RESTful web 服务

+   配置`spring-security.xml`文件

## 如何做...

以下是将 Spring Security 与 Apache CXF RESTful web 服务集成的步骤：

1.  配置`Book` POJO 类。

```java
@XmlRootElement(name = "book")
public class Book {
    private int book_id;
    private String book_name;
    private String book_publication;
    private String book_author;
    public Book(int book_id, String book_name, String book_publication, String book_author) {
      this.book_id = book_id;
      this.book_name = book_name;
      this.book_publication = book_publication;
      this.book_author = book_author;
    }
    public String getBook_author() {
      return book_author;
    }
    public void setBook_author(String book_author) {
      this.book_author = book_author;
    }
    public int getBook_id() {
      return book_id;
    }
    public void setBook_id(int book_id) {
      this.book_id = book_id;
    }
    public String getBook_name() {
      return book_name;
    }
    public void setBook_name(String book_name) {
      this.book_name = book_name;
    }
    public String getBook_publication() {
      return book_publication;
    }
    public void setBook_publication(String book_publication) {
      this.book_publication = book_publication;
    }
}
```

1.  配置`BookCollection` POJO 类。

```java
  @XmlType(name = "BookCollection")
  @XmlRootElement
  public class BookCollection {
    private Collection books;
    public BookCollection() {
    }
    public BookCollection(Collection books) {
      this.books = books;
    }
    @XmlElement(name="books")
    @XmlElementWrapper(name="books")
    public Collection getUsers() {
      return books;
    }
  }
```

1.  配置`BookService`接口。

```java
public interface BookService {
    BookCollection getBooks();
    Book getBook(Integer id);
    Response add(Book book);
}
```

1.  配置`BookServiceImpl`类。

```java
  @Path ("/services/")
  public class BookServiceImpl implements BookService {
    private static final Map<Integer, Book> books = new HashMap<Integer, Book>();
    private static int index = 4;
    static {
      try {
        books.put(1, new Book(1, "Someone Like You", "Penguin", "Durjoy Datta-Nikita Singh"));
          books.put(2, new Book(2, "The Secret Wish List", "Westland", " Preeti Shenoy"));
          books.put(3, new Book(3, "Love Stories That Touched My Heart ", "Metro Reads", " Preeti Shenoy"));
        } catch (Exception e) {
          e.printStackTrace();
        }
    }
 @Override
 @POST
 @Path("/book")
 @Consumes("application/json")
    public Response add(Book book) {
      System.out.println("Adding :" + book.getBook_name());
      book.setBook_id(index++);
      return Response.status(Response.Status.OK).build();
    }
 @Override
 @GET
 @Path("/book/{book_id}")
 @Produces("application/json")
    public Book getBook(@PathParam("book_id") Integer book_id) {
      return books.get(book_id);
    }
 @Override
 @GET
 @Path("/books")
 @Produces("application/json")
    public BookCollection getBooks() {
      return new BookCollection(books.values());
    }
}
```

1.  配置`application-security.xml`文件：

```java
  <sec:global-method-security pre-post-annotations="enabled" />
  <sec:http auto-config="true"  use-expressions="true">
    <sec:intercept-url pattern="/**" access="hasRole('ROLE_EDITOR')"/>
    <sec:http-basic></sec:http-basic>
    <sec:logout logout-success-url="/logout" />
  </sec:http>
  <import resource="classpath:META-INF/cxf/cxf.xml" />
  <import resource="classpath:META-INF/cxf/cxf-servlet.xml"/>
  <jaxrs:server address="/" id="myService">
    <jaxrs:serviceBeans>
      <ref bean="bookserviceImpl"/>
    </jaxrs:serviceBeans>
    <jaxrs:providers>
      <ref bean="jacksonProvider"/>
    </jaxrs:providers>
  </jaxrs:server>
  <bean id="jacksonProvider"
  class="org.codehaus.jackson.jaxrs.JacksonJaxbJsonProvider"/>
  <bean id="bookserviceImpl"
  class="org.springframework.booksservice.BookServiceImpl"/>
  <sec:authentication-manager>
    <sec:authentication-provider>
      <sec:user-service>
        <sec:user name="anjana" password="packt123" authorities="ROLE_EDITOR" />
      </sec:user-service>
    </sec:authentication-provider>
  </sec:authentication-manager>
</beans>
```

1.  配置`Web.xml`文件。

```java
    <!-- The definition of the Root Spring Container shared by all Servlets and Filters -->
  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>/WEB-INF/spring/application-security.xml</param-value>
  </context-param>
  <!-- Creates the Spring Container shared by all Servlets and Filters -->
  <listener>
  <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>
  <!-- Processes application requests -->
  <servlet>
    <servlet-name>cxf</servlet-name>
    <servlet-class>org.apache.cxf.transport.servlet.CXFServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>cxf</servlet-name>
    <url-pattern>/services/*</url-pattern>
  </servlet-mapping>
  <!-- Spring child -->
  <!-- <servlet>
  <servlet-name>bookservice_cxf</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>bookservice_cxf</servlet-name>
    <url-pattern>/bookservice_cxf/*</url-pattern>
  </servlet-mapping>-->
  <filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
</web-app>
```

## 它是如何工作的...

这个例子中，RESTful 服务是由 CXF 框架提供的。然后应用程序集成了 Spring Security，以提供安全的身份验证和授权模块给 RESTful web 服务。Spring Security 过滤器链管理身份验证和授权过程。当您访问服务时，将提示您登录，如下面的屏幕截图所示。登录后，您可以查看 RESTful 数据。Mozilla Firefox 浏览器将提示用户以文件格式下载数据。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_05.jpg)

现在访问 URL：`http://localhost:8080/booksservice_cxf/services/services/book/1`

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_06.jpg)

## 另请参阅

+   *将 Spring Security 与 Apache CXF RESTful web 服务集成*的方法

+   *将 Spring Security 与 Apache Camel 集成*的方法

# 将 Spring Security 与 Apache CXF 基于 SOAP 的 web 服务集成

在这一部分，让我们创建一个基于 SOAP 的 web 服务。我们将演示 Spring Security 与 Apache CXF 基于 SOAP 的 web 服务的集成。

使用 Apache CXF 创建基于 SOAP 的 web 服务已经变得简单。

## 准备就绪

+   将 CXF-SOAP 依赖项添加到`pom`文件中。

+   向`pom`文件添加基于 Spring Security 的依赖项。

+   使用`interface`和`Impl`类设置基于 SOAP 的 Web 服务。

+   配置`spring-security.xml`文件。

+   将 jar 添加到`Tomcat_7.0/lib`文件夹作为设置的一部分。 Tomcat 需要以下 jar 文件才能与 CXF Web 服务一起工作。缺少这些 jar 可能会导致一些错误：

+   `streambuffer.jar`

+   `stax-ex`

+   `jaxws-ap-2.1`

+   `jaxws-rt`

## 如何做...

以下是将 Apache CXF 基于 SOAP 的 Web 服务与 Spring Security 集成的步骤：

1.  `Book` POJO 具有 getter 和 setter 方法。它还具有参数化构造函数。`Book` POJO 在`BookService`接口中使用，以提供有关从客户端应用程序请求的`Book`的详细信息。

```java
package org.packt.cxf.domain;
public class Book {
  private int book_id;
  private String book_name;
  private String book_publication;
  private String book_author;
  public Book() {
  }
  public Book(int book_id, String book_name, String book_publication, String book_author) {
    this.book_id = book_id;
    this.book_name = book_name;
    this.book_publication = book_publication;
    this.book_author = book_author;
  }
  public String getBook_author() {
    return book_author;
    }
    public void setBook_author(String book_author) {
        this.book_author = book_author;
  }
  public int getBook_id() {
    return book_id;
  }
  public void setBook_id(int book_id) {
    this.book_id = book_id;
  }
  public String getBook_name() {
    return book_name;
  }
  public void setBook_name(String book_name) {
    this.book_name = book_name;
  }
  public String getBook_publication() {
    return book_publication;
  }
  public void setBook_publication(String book_publication) {
    this.book_publication = book_publication;
  }
}
```

1.  `BookService`接口使用`@WebService`注解创建，其中`getBookDetails`是 WSDL 中的服务方法。

```java
package org.packt.cxf.service;
import javax.jws.WebService;
import org.packt.cxf.domain.Book;
@WebService
public interface BookService {
  public Book getBookDetails(int book_id);
}
```

1.  `BookServiceImpl`类是`BookService`接口的实现类，并使用`@webservice`注解包`org.packt.cxf.service`配置为端点接口。

```java
import java.util.HashMap;
import java.util.Map;
import javax.jws.WebService;
import org.packt.cxf.domain.Book;
@WebService(endpointInterface = "org.packt.cxf.service.BookService")
public class BookServiceImpl implements BookService{
    private static final Map<Integer, Book> books = new HashMap<Integer, Book>();
    private static int index = 4;
    static {
      try {
        books.put(1, new Book(1, "Someone Like You", "Penguin", "Durjoy Datta-Nikita Singh"));
        books.put(2, new Book(2, "The Secret Wish List", "Westland", " Preeti Shenoy"));
        books.put(3, new Book(3, "Love Stories That Touched My Heart ", "Metro Reads", " Preeti Shenoy"));
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    @Override
    public Book getBookDetails(int book_id) {
      return books.get(book_id);
    }}
```

1.  在`Cxf-servlet.xml`文件中，我们注册了 Web 服务接口和实现类。

```java
  <beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsdhttp://cxf.apache.org/jaxwshttp://cxf.apache.org/schemas/jaxws.xsd">
  <import resource="classpath:META-INF/cxf/cxf.xml" />
  <import resource="classpath:META-INF/cxf/cxf-servlet.xml" />
  <import resource="classpath:META-INF/cxf/cxf-extension-http.xml" />
  <import resource="classpath:META-INF/cxf/cxf-extension-soap.xml" />
  <jaxws:endpoint id="bookService"implementor="org.packt.cxf.service.BookServiceImpl" address="/BookService" />
  </beans>
```

1.  在`Web.xml`文件中，我们引用`cxf-servlet.xml`的位置，并配置`CXFSservlet`。

```java
  <web-app version="2.5"   xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd">
    <display-name>SampleWSCxf</display-name>
    <listener>
      <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
    </listener>
    <context-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>WEB-INF/cxf-servlet.xml</param-value>
    </context-param>
    <servlet>
      <servlet-name>CXFServlet</servlet-name>
      <servlet-class>org.apache.cxf.transport.servlet.CXFServlet</servlet-class>
      <load-on-startup>1</load-on-startup>
    </servlet>
    <servlet-mapping>
      <servlet-name>CXFServlet</servlet-name>
      <url-pattern>/*</url-pattern>
    </servlet-mapping>
  </web-app>
```

## 工作原理...

在本节中，我们演示了 Web 服务的基本身份验证。访问 URL：`http://localhost:8080/bookservice/`

我们使用了 CXF 框架创建基于 SOAP 的 Web 服务。当用户访问 URL 时，期望的行为是允许访问 WSDL 及其服务。但是 Spring Security 中断了请求，并为用户弹出登录对话框。成功验证后，用户可以访问 WSDL。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_07.jpg)![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_08.jpg)

生成的 WSDL 可在以下 URL 找到：`http://localhost:8080/bookservice/BookService?wsdl`

```java
<wsdl:definitions    name="BookServiceImplService" targetNamespace="http://service.cxf.packt.org/">
  <wsdl:types>
  <xs:schema elementFormDefault="unqualified" targetNamespace="http://service.cxf.packt.org/" version="1.0">
  <xs:element name="getBookDetails"type="tns:getBookDetails"/>
  <xs:element name="getBookDetailsResponse" type="tns:getBookDetailsResponse"/>
  <xs:complexType name="getBookDetails">
    <xs:sequence>
      <xs:element name="arg0" type="xs:int"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="getBookDetailsResponse">
    <xs:sequence>
      <xs:element minOccurs="0" name="return"type="tns:book"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="book">
    <xs:sequence>
      <xs:element minOccurs="0" name="book_author" type="xs:string"/>
      <xs:element name="book_id" type="xs:int"/>
      <xs:element minOccurs="0" name="book_name" type="xs:string"/>
      <xs:element minOccurs="0" name="book_publication" type="xs:string"/>
      </xs:sequence>
    </xs:complexType>
  </xs:schema>
  </wsdl:types>
  <wsdl:message name="getBookDetails">
    <wsdl:part element="tns:getBookDetails" name="parameters"></wsdl:part>
  </wsdl:message>
  <wsdl:message name="getBookDetailsResponse">
    <wsdl:part element="tns:getBookDetailsResponse" name="parameters"></wsdl:part>
    </wsdl:message>
  <wsdl:portType name="BookService">
    <wsdl:operation name="getBookDetails">
      <wsdl:input message="tns:getBookDetails"name="getBookDetails"></wsdl:input>
      <wsdl:outputmessage="tns:getBookDetailsResponse"name="getBookDetailsResponse"></wsdl:output>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:bindingname="BookServiceImplServiceSoapBinding"type="tns:BookService">
    <soap:bindingstyle="document"transport="http://schemas.xmlsoap.org/soap/http"/>
      <wsdl:operationname="getBookDetails">
        <soap:operationsoapAction=""style="document"/>
      <wsdl:inputname="getBookDetails">
        <soap:bodyuse="literal"/>
      </wsdl:input>
      <wsdl:outputname="getBookDetailsResponse">
        <soap:bodyuse="literal"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:servicename="BookServiceImplService">
    <wsdl:portbinding="tns:BookServiceImplServiceSoapBinding"name="BookServiceImplPort">
      <soap:addresslocation="http://localhost:8080/bookservice/BookService"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
```

## 另请参阅

+   *将 Spring Security 与 Apache CXF RESTful Web 服务集成*配方

+   *将 Spring Security 与 Apache Camel 集成*配方

# 将 Spring Security 与 Apache Camel 集成

Apache Camel 可用于定义路由和调解应用程序的规则。 Spring Security 可用于与 Apache Camel 一起对路由器进行身份验证。 Spring Security 身份验证策略对象控制对路由器的访问。 Spring Security 身份验证策略对象包含角色信息，并引用 Spring 身份验证管理器。您可以从网站下载源代码。

## 准备就绪

+   创建 Camel 上下文

+   使用 XML 配置添加路由规则

+   在 Spring XML 文件中配置以下内容：

+   访问决策管理器

+   角色投票者

+   身份验证管理器

+   用户详细信息服务

+   使用权限配置身份验证策略对象

+   添加`camel-spring-security`依赖

## 如何做...

以下是将 Apache Camel 与 Spring Security 集成的步骤：

1.  创建`Camel–context.xml`文件，并使用 Spring Security 定义路由规则。

```java
  <spring-security:http realm="User Access Realm">
    <spring-security:intercept-url pattern="/apachecamel/**"     access="ROLE_EDITOR"/>
    <spring-security:http-basic/>
    <spring-security:remember-me/>
  </spring-security:http>
  <spring-security:authentication-manager alias="authenticationManager">
    <spring-security:authentication-provider user-service-ref="userDetailsService"/>
  </spring-security:authentication-manager>
  <spring-security:user-service id="userDetailsService">
    <spring-security:user name="anju" password="anju123" authorities="ROLE_EDITOR,ROLE_AUTHOR"/>
    <spring-security:user name="shami" password="shami123" authorities="ROLE_EDITOR"/>
  </spring-security:user-service>
  <bean id="accessDecisionManager" class="org.springframework.security.access.vote.AffirmativeBased">
    <property name="allowIfAllAbstainDecisions" value="true"/>
    <property name="decisionVoters">
      <list>
        <bean class="org.springframework.security.access.vote.RoleVoter"/>
      </list>
    </property>
  </bean>
  <!-- The Policy for checking the authentication role of AUTHOR -->
  <authorizationPolicy id="author" access="ROLE_AUTHOR"
    authenticationManager="authenticationManager"
    accessDecisionManager="accessDecisionManager"
    />
  <!-- The Policy for checking the authentication role of EDITOR -->
  <authorizationPolicy id="editor" access="ROLE_EDITOR"/>
  <camelContext id="myCamelContext" >
    <!-- Catch the authorization exception and set the Access Denied message back -->
    <onException>
    <exception>org.apache.camel.CamelAuthorizationException</exception>
    <handled>
      <constant>true</constant>
    </handled>
    <transform>
      <simple>Access Denied with the Policy of ${exception.policyId} !</simple>
      </transform>
    </onException>
 <route>
 <from uri="servlet:///editor"/>
 <!-- wrap the route in the policy which enforces security check -->
 <policy ref="editor">
 <transform>
 <simple>Normal user can access this service</simple>
 </transform>
 </policy>
 </route>
 <route>
 <from uri="servlet:///author"/>
 <!-- wrap the route in the policy which enforces security check -->
 <policy ref="author">
 <transform>
 <simple>Call the admin operation OK</simple>
 </transform>
 </policy>
 </route>
  </camelContext>
</beans>
```

1.  在`Web.xml`中配置 Camel servlet。

```java
<!-- location of spring xml files -->
  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>classpath:camel-context.xml</param-value>
  </context-param>
  <!-- the listener that kick-starts Spring -->
  <listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>
  <filter>
    <filter-name>springSecurityFilterChain</filter-name>
    <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>springSecurityFilterChain</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <servlet>
    <servlet-name>CamelServlet</servlet-name>
    <servlet-class>org.apache.camel.component.servlet.CamelHttpTransportServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>CamelServlet</servlet-name>
    <url-pattern>/apachecamel/*</url-pattern>
  </servlet-mapping>
</web-app>
```

## 工作原理...

现在访问 URL：`http://localhost:8080/apachecamel/editor`

`camel-context.xml`文件具有路由规则；`camel-context.xml`文件的位置在`Web.xml`中配置，同时配置了`CamelServlet`来处理路由机制。`<authorizationpolicy>`标签处理在`spring-security.xml`文件中配置的资源的身份验证和授权。`<spring-security:user-service>`标签包含用户和角色的详细信息，在路由请求之前可以给予访问权限。以下是 Apache Camel 使用 Spring Security 中断路由过程的工作流程。用户被授权使用两个角色中的任意一个：`EDITOR`或`AUTHOR`。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_10_10.jpg)

## 另请参阅

+   *将 Spring Security 与 Apache CXF RESTful Web 服务集成*配方

+   Spring Security 与 Apache Camel 集成的配方


# 第十一章：更多关于 Spring 安全

在本章中，我们将涵盖：

+   具有多个认证提供者的 Spring 安全

+   具有多个输入认证的 Spring 安全

+   集成验证码的 Spring 安全

+   Spring Security with JAAS

# 介绍

在本章中，我们将看到 Spring 安全的一些更多示例。让我们看看如何将 Spring 安全与多个认证提供者集成。我们还将看到使用 Spring 进行多个输入认证的示例。

# 具有多个认证提供者的 Spring 安全

Spring Security 提供了添加多个认证提供者的选项。过滤器链会检查每个认证提供者，直到成功认证。

在本节中，让我们看看如何配置多个认证提供者以及 Spring 如何使用多个认证提供者进行认证。

例如，我们正在使用`horrormovie`应用程序，其中认证和授权由 Spring Security 与数据库处理。

## 准备工作

+   创建一个 maven web 项目

+   添加`spring-security`依赖项

+   添加与 spring-core 相关的依赖项

+   在`Web.xml`文件中配置 Spring 上下文监听器

+   创建`AddHorroMovieController.java`控制器，并添加用于添加、删除和列出的请求映射方法

+   编辑`application-security.xml`文件以添加另一个认证提供者

## 如何做...

以下是将多个认证提供者与 Spring Security 集成的步骤：

1.  编辑`application-security.xml`文件。

```java
  <authentication-manager alias="authentication Manager">
    <authentication-provider>
 <jdbc-user-service data-source-ref="tenant1DataSource"users-by-username-query=" select username, password ,'true' as enabled from users where username=?"authorities-by-username-query=" select u.username as username, ur.authority as authority from users u, user_roles ur where u.user_id = ur.user_id and u.username =?" />
    </authentication-provider>
 <authentication-provider>
 <user-service>
 <user name="anjana" password="anjana123" authorities="ROLE_EDITOR"/>
 <user name="raghu" password="raghu123" authorities="ROLE_AUTHOR"/>
 <user name="shami" password="shami123" authorities="ROLE_EDITOR"/>
 </user-service>
 </authentication-provider>
  </authentication-manager>
```

## 工作原理...

将应用部署到 GlassFish 应用服务器；访问以下 URL：`http://localhost:8080/list`，并使用用户名/密码（`Vikash`/`Vikash123`）登录。

这是在 derby 数据库中创建的用户，具有访问权限（`ROLE_EDITOR`）。

然后注销并再次使用用户名`shami`和密码`shami123`登录。在这里，用户会按顺序通过两个认证提供者进行认证。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_11_01.jpg)

## 另请参阅

+   *具有多个输入认证的 Spring 安全*配方

+   集成验证码的 Spring 安全

+   *具有 JAAS 的 Spring 安全*配方

# 具有多个输入认证的 Spring 安全

在本节中，我们将演示多个输入认证。这也被称为双因素认证。到目前为止，在我们的所有示例中，我们都是根据用户名和密码进行认证。在这个示例中，我们将提供另一个字段用于电话号码以及用户名。这是使用 hibernate 和 derby 数据库的相同`horrormovie`应用程序。

## 准备工作

+   创建一个自定义过滤器来处理新的登录表单

+   在`Springsecurity.xml`文件中配置自定义过滤器

+   更新`UserDetailsService`实现类以处理额外的输入

+   在数据库中添加一个名为`MOBILE_NO`的额外列

+   更新`login.jsp`文件以接受`MOBILE_NO`作为输入

## 如何做...

以下是使用 Spring Security 实现多个输入认证的步骤：

1.  创建名为`MultipleInputAuthenticationFilter`的自定义过滤器以提取额外的手机号参数。

```java
  public class MultipleInputAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
    private String extraParameter = "mobile_no";

    public String getExtraParameter() {
        return extraParameter;
    }

    public void setExtraParameter(String extraParameter) {
      this.extraParameter = extraParameter;
    }
    private String delimiter = ":";

    @Override
    protected String obtainUsername(HttpServletRequest request)
      {
        String username = request.getParameter(getUsernameParameter());
        String mobile_no = request.getParameter(getExtraParameter());
        String combinedUsername = username + getDelimiter() + mobile_no;
        System.out.println("Combined username = " + combinedUsername);
        return combinedUsername;
      }

    public String getDelimiter()
    {
      return this.delimiter;
    }
    /**
      * @param delimiter The delimiter string used to separate the username and extra input values in the
        * string returned by <code>obtainUsername()</code>
    */
    public void setDelimiter(String delimiter) {
      this.delimiter = delimiter;
    }
```

1.  更新`application-security.xml`文件以处理自定义过滤器。

```java
  <global-method-security pre-post-annotations="enabled" />
    <http auto-config="false"  use-expressions="true" entry-point-ref="loginUrlAuthenticationEntryPoint">
      <intercept-url pattern="/login" access="permitAll" />
      <intercept-url pattern="/logout" access="permitAll" />
      <intercept-url pattern="/accessdenied" access="permitAll" />
      <intercept-url pattern="/list" access="hasRole('ROLE_EDITOR')" />
      <intercept-url pattern="/add" access="hasRole('ROLE_EDITOR')" />
      <custom-filter position="FORM_LOGIN_FILTER" ref="multipleInputAuthenticationFilter" />
      <!--<form-login login-page="/login" default-target-url="/list" authentication-failure-url="/accessdenied" />-->
      <logout logout-success-url="/logout" />
    </http>
    <authentication-manager alias="authenticationManager">
      <authentication-provider user-service-ref="MyUserDetails">
        <password-encoder hash="plaintext" />
      </authentication-provider>
    </authentication-manager>
 <beans:bean id="multipleInputAuthenticationFilter" class="com.packt.springsecurity.controller.MultipleInputAuthenticationFilter">
 <beans:property name="authenticationManager" ref="authenticationManager" />
 <beans:property name="authenticationFailureHandler" ref="failureHandler" />
 <beans:property name="authenticationSuccessHandler" ref="successHandler" />
 <beans:property name="filterProcessesUrl" value="/j_spring_security_check" />
 <beans:property name="postOnly" value="true" />
 <beans:property name="extraParameter" value="mobile_no" />
 </beans:bean>
    <beans:bean id="horrorMovieDAO" class="com.packt.springsecurity.dao.HorrorMovieDaoImpl" />
    <beans:bean id="horrorMovieManager" class="com.packt.springsecurity.service.HorrorMovieManagerImpl" />
    <beans:bean id="UsersDAO" class="com.packt.springsecurity.dao.UsersDAOImpl" />
    <beans:bean id="UsersManager" class="com.packt.springsecurity.service.UsersManagerImpl" />
    <beans:bean id="UserRoleDAO" class="com.packt.springsecurity.dao.UserRoleDAOImpl" />
    <beans:bean id="UserRoleManager" class="com.packt.springsecurity.service.UserRoleManagerImpl" />
    <beans:bean id="loginUrlAuthenticationEntryPoint" class="org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint">
      <beans:property name="loginFormUrl" value="/login" />
    </beans:bean>
    <beans:bean id="successHandler" class="org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler">
      <beans:property name="defaultTargetUrl" value="/list" />
    </beans:bean>

    <beans:bean id="failureHandler" class="org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler">
      <beans:property name="defaultFailureUrl" value="/accessdenied" />
    </beans:bean>
 <beans:bean id="MyUserDetails" class="com.packt.springsecurity.service.MyUserDetails" />
 </beans:beans> 

```

1.  更新`UsersDAOImpl`以处理额外的输入。

```java
@Override
 @Transactional
 public Users findByUserNameMobile(String userName, String mobile_no) {
 List<Users> userList = new ArrayList<Users>();
 Query query = (Query) sessionFactory.getCurrentSession().createQuery("from Users u where u.userName = :userName and u.mobile_no=:mobile_no");
 query.setParameter("userName", userName);
 query.setInteger("mobile_no", Integer.parseInt(mobile_no));
 userList = query.list();
 if (userList.size() > 0) {
 return userList.get(0);
 } else {
 return null;
 }
 }

```

1.  在实现`UserDetailsService`接口的`MyUserDetails`类中实现方法，以处理额外的输入。

```java
public UserDetails loadUserByUsername(String str)throws UsernameNotFoundException {
 String[] splitstring = str.split(":");
 if (splitstring.length < 2) {
 System.out.println("User did not enter both username and mobile number.");
 throw new UsernameNotFoundException("Must specify both username and mobile number");
 }
 String username = splitstring[0];
 String mobile = splitstring[1];

 System.out.println("Username = " + username);
 System.out.println("Mobile = " + mobile);

 Users users = UsersDAO.findByUserNameMobile(username, mobile);
 boolean enabled = true;
 boolean accountNonExpired = true;
 boolean credentialsNonExpired = true;
 boolean accountNonLocked = true;
 return new User(
 users.getUserName(),
 users.getUserPassword(),
 enabled,
 accountNonExpired,
 credentialsNonExpired,
 accountNonLocked,
 getAuthorities(users.getRole().getRoleId().intValue()));
}

```

## 工作原理...

访问以下 URL：`http://localhost:8080/SpringSecurity_MultipleInputAuth/login`

用户不仅通过用户名和密码进行认证，如本书中所有应用程序中所示，还通过手机号参数进行认证。

当用户在登录页面提交信息并点击**提交查询**时，用户名和手机号将与分隔符合并，并且 Spring 安全性将调用`MyUserDetails`类，该类将根据用户使用 hibernate 提供的输入再次拆分参数并对用户进行身份验证。

成功验证后，用户将被重定向到经过授权的页面。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_11_02.jpg)

## 另请参阅

+   具有多个身份验证提供程序的 Spring 安全性配方

+   具有验证码集成的 Spring 安全性配方

+   具有 JAAS 的 Spring 安全性配方

# 具有验证码集成的 Spring 安全性

让我们演示 Spring 安全性与验证码的集成。我们已经为此目的下载了`Kaptcha.jar`验证码提供程序。我们需要将 jar 文件安装到 maven 本地存储库中，以使应用程序正常工作。

该示例是前一个配方的扩展，其中考虑了额外的输入，即手机号码，用于 Spring 安全性的授权和身份验证。在此示例中，我们将从用户那里获取用户名和密码的代码以及验证码代码。用户名将与数据库进行身份验证，并且还将比较请求的验证码和用户输入的验证码。

当所有条件匹配时，用户被认为已经通过验证，否则认证失败。

## 准备就绪

+   将`Kaptcha` servlet 添加到`Web.xml`文件中

+   在您的`Springsecurity.xml`文件中配置自定义过滤器

+   更新`UserDetailsService`实现类以处理`Kaptcha`

+   更新`login.jsp`文件以将`Kaptcha`作为输入

+   扩展`UsernamePasswordAuthenticationFilter`

## 如何做...

以下是将 Spring 安全性与验证码集成的步骤：

1.  将`Kaptcha` servlet 添加到`Web.xml`文件中。

```java
  <servlet>
    <servlet-name>Kaptcha</servlet-name>
    <servlet-class>com.google.code.kaptcha.servlet.KaptchaServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>Kaptcha</servlet-name>
    <url-pattern>/kaptcha.jpg</url-pattern>
  </servlet-mapping>
```

1.  更新`application-security.xml`以处理自定义过滤器。

```java
  <beans:bean id="multipleInputAuthenticationFilter" class="com.packt.springsecurity.controller.MultipleInputAuthenticationFilter">
    <beans:property name="authenticationManager" ref="authenticationManager" />
    <beans:property name="authenticationFailureHandler" ref="failureHandler" />
    <beans:property name="authenticationSuccessHandler" ref="successHandler" />
    <beans:property name="filterProcessesUrl" value="/j_spring_security_check" />
    <beans:property name="postOnly" value="true" />
    <beans:property name="extraParameter" value="kaptcha" />
  </beans:bean>
```

1.  更新`UsersDAOImpl`以处理额外的输入。

```java
 @Override
 @Transactional
 public Users findByUserNameCaptcha(String userName, String kaptchaReceived, String kaptchaExpected) {
 List<Users> userList = new ArrayList<Users>();
 Query query = (Query) sessionFactory.getCurrentSession().createQuery("from Users u where u.userName = :userName");
 query.setParameter("userName", userName);
 userList = query.list();
 if (userList.size()>0 && kaptchaReceived.equalsIgnoreCase(kaptchaExpected)) {
 return (Users)userList.get(0);
 }  else {
 return null;
 }
 }

```

1.  更新`UserDetailsService`类以处理额外的输入。

```java
public UserDetails loadUserByUsername(String str)throws UsernameNotFoundException {
 String[] splitstring = str.split(":");
 if (splitstring.length < 2) {
 System.out.println("User did not enter both username and captcha code.");
 throw new UsernameNotFoundException("Must specify both username captcha code");
 }
 String username = splitstring[0];
 String kaptchaReceived = splitstring[1];
 String kaptchaExpected = splitstring[2];
 Users users = UsersDAO.findByUserNameCaptcha(username, kaptchaReceived,kaptchaExpected);
 boolean enabled = true;
 boolean accountNonExpired = true;
 boolean credentialsNonExpired = true;
 boolean accountNonLocked = true;
 return new User(
 users.getUserName(),
 users.getUserPassword(),
 enabled,
 accountNonExpired,
 credentialsNonExpired,
 accountNonLocked,
 getAuthorities(users.getRole().getRoleId().intValue())
 );
}

```

1.  扩展`UsernamePasswordAuthenticationFilter`并重写`MultipleInputAuthenticationFilter`类中的`obtainUsername`（`HttpServletRequest`请求）方法。

```java
@Override
  protected String obtainUsername(HttpServletRequest request) {
  String username = request.getParameter(getUsernameParameter());
  String kaptcha = request.getParameter(getExtraParameter());
  String kaptchaExpected = (String) request.getSession().getAttribute(com.google.code.kaptcha.Constants.KAPTCHA_SESSION_KEY);
  String combinedUsername = username + getDelimiter() + kaptcha + getDelimiter() + kaptchaExpected;
  System.out.println("Combined username = " + combinedUsername);
  return combinedUsername;
  }
```

## 工作原理...

访问以下 URL：

`http://localhost:8080/SpringSecurity_MultipleInputAuth/login`

`Kaptcha` servlet 在浏览器上为用户显示不同的图表。

用户输入的值和`Kaptcha`生成的值与`UsersDAOImpl.java`类中的`Username`字段一起与数据库中的值进行比较。当所有条件匹配时，即用户输入的`Kaptcha`应与浏览器显示的`Kaptcha`相同，并且用户名应存在于数据库中，那么用户被认为已通过验证。用户将被重定向到经过验证和授权的页面。

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_11_03.jpg)

## 另请参阅

+   具有多个身份验证提供程序的 Spring 安全性配方

+   具有多个输入身份验证的 Spring 安全性配方

+   具有 JAAS 的 Spring 安全性配方

# 具有 JAAS 的 Spring 安全性

在第一章中，*基本安全性*，我们已经演示了如何在 JBOSS 中使用 JAAS 配置进行身份验证和授权。 Spring 安全性还提供了完全支持以实现基于 JAAS 的身份验证。我们需要将`DefaultJaasAuthenticationProvider`配置为身份验证提供程序。在本节中，我们将演示将 Spring 安全性与 JAAS 集成。

让我们看一些由 Spring 安全性 API 提供的基于 JAAS 的类和接口：

+   `org.springframework.security.authentication.jaas`

+   `AbstractJaasAuthenticationProvider`

+   `AuthorityGranter`

+   `DefaultJaasAuthenticationProvider`

+   `DefaultLoginExceptionResolver`

+   `JaasAuthenticationCallbackHandler`

+   `JaasAuthenticationToken`

+   `JaasGrantedAuthority`

+   JaasNameCallbackHandler

+   登录异常解析器

+   `SecurityContextLoginModule`

## 准备就绪

+   通过`org.springframework.security.authentication.jaas.AuthorityGranter`实现`AuthorityGranter`接口

+   通过`javax.security.auth.spi.LoginModule`实现`LoginModule`接口

+   在`context.xml`文件中配置`DefaultJaasAuthenticationProvider`类。实现`AuthorityGranter`接口及其配置。

## 如何做...

以下是使用 Spring 安全实现 JAAS 的步骤：

1.  使用`AuthorityGranterImpl`类实现`AuthorityGranter`类

```java
public class AuthorityGranterImpl implements AuthorityGranter {
  public Set<String> grant(Principal principal) {
    if (principal.getName().equals("publisher"))
      return Collections.singleton("PUBLISHER");
    else
      return Collections.singleton("EDITOR");
  }
}
```

1.  使用`javax.security.auth.spi`包中的`LoginModule`类，使用`LoginModuleImpl`类

```java
public class LoginModuleImpl implements LoginModule {
  private String password;
  private String username;
  private Subject subject;
  public boolean login() throws LoginException {
    // Check the password against the username "publisher" or "editor"
    if (username == null || (!username.equals("publisher") && !username.equals("editor"))) {
      throw new LoginException("User not valid");
    }
    if (password == null || (!password.equals("publisher123") && !password.equals("editor123"))) {
      throw new LoginException("Password not valid");
    } else {
      subject.getPrincipals().add(new UserPrincipal(username));
      return true;
    }
  }

  @Override
  public boolean abort() throws LoginException {
    // TODO Auto-generated method stub
    return false;
  }

  @Override
  public boolean commit() throws LoginException {
    // TODO Auto-generated method stub
    return true;
  }

  @Override
  public boolean logout() throws LoginException {
    // TODO Auto-generated method stub
    return false;
  }

  public void initialize(Subject subject, CallbackHandler callbackHandler,
    Map<String, ?> state, Map<String, ?> options) {
    this.subject = subject;
    try {
      NameCallback nameCallback = new NameCallback("prompt");
      PasswordCallback passwordCallback = new PasswordCallback("prompt", false);
      callbackHandler.handle(new Callback[]{nameCallback,passwordCallback});
      password = new String(passwordCallback.getPassword());
      username = nameCallback.getName();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
```

1.  使用 JAAS 配置 Spring 安全。

```java
  <sec:authentication-manager>
    <sec:authentication-provider ref="jaasAuthProvider" />
  </sec:authentication-manager>
  <bean id="jaasAuthProvider" class="org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider">
    <property name="configuration">
      <bean class="org.springframework.security.authentication.jaas.memory.InMemoryConfiguration">
        <constructor-arg>
          <map><entry key="SPRINGSECURITY">
            <array>
              <bean class="javax.security.auth.login.AppConfigurationEntry">
                <constructor-arg value="org.packt.springsecurityjaas.LoginModuleImpl" />
                <constructor-arg>
                  <util:constant static-field="javax.security.auth.login.AppConfigurationEntry$LoginModuleControlFlag.REQUIRED" />
                </constructor-arg>
                <constructor-arg>
                  <map></map>
                </constructor-arg>
              </bean>
            </array>
          </entry>
          </map>
        </constructor-arg>
      </bean>
    </property>
    <property name="authorityGranters">
      <list>
        <bean class="org.packt.springsecurityjaas.AuthorityGranterImpl" />
      </list>
    </property>
  </bean>
</beans>
```

## 它是如何工作的...

访问 URL：`http://localhost:8080/SpringSecurity_Jaas/`

使用以下凭据登录：`publisher`/`publisher123`和`editor`/`editor123`

身份验证由`DefaultJaasAuthenticationProvider`处理。用户信息和身份验证由`InMemoryConfiguration`处理，这意味着 JAAS 的`LoginModule`类使用`callbackhandlers`进行身份验证和授权。成功验证后，用户将被重定向到授权页面。以下截图显示了应用程序的工作流程：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_11_04.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_11_05.jpg)

## 另请参阅

+   使用多个身份验证提供程序的 Spring 安全配方

+   使用多个输入验证的 Spring 安全配方

+   使用 JAAS 的 Spring 安全配方
