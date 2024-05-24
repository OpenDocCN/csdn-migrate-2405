# Spring WebService2 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/1F0369E05A9E0B8B44E275BC989E8AD8`](https://zh.annas-archive.org/md5/1F0369E05A9E0B8B44E275BC989E8AD8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 WSS4J 库保护 SOAP Web 服务

在本章中，我们将涵盖：

+   使用用户名令牌和明文/摘要密码对 Web 服务调用进行身份验证

+   使用 Spring 安全对用户名令牌进行身份验证，密码为明文/摘要

+   使用数字签名保护 SOAP 消息

+   使用 X509 证书对 Web 服务调用进行身份验证

+   加密/解密 SOAP 消息

# 介绍

在上一章中，解释了在 Spring-WS 中使用 SUN 的实现**(XWSS)**：OASIS **Web-Services Security** **(WS-Security**或**WSS)**规范（使用`XwsSecurityInterceptor`执行安全操作）。在本章中，将解释 Spring-WS 对 Apache 的实现（WSS4J）OASIS WS-Security 规范的支持。尽管这两种 WS-Security 的实现都能够执行所需的安全操作（身份验证、签名消息和加密/解密），但 WSS4J 的执行速度比 XWSS 快。

Spring-WS 支持使用`Wss4jSecurityInterceptor`来支持 WSS4J，这是一个在调用`Endpoint`之前对请求消息执行安全操作的`EndpointInterceptor`。

虽然 XWSS 使用外部配置策略文件，但 WSS4J（以及相应的`Wss4jSecurityInterceptor`）不需要外部配置文件，并且完全可以通过属性进行配置。该拦截器应用的**验证**（接收方）和**保护**（发送方）操作通过`validationActions`和`securementActions`属性指定。可以将多个操作设置为由空格分隔的字符串。以下是本章中接收方（服务器端）的示例配置：

```java
<!--In receiver side(server-side in this chapter)-->
<bean id="wss4jSecurityInterceptor"
<property name="validationActions" value="UsernameToken Encrypt" />
..
<!--In sender side(client-side in this chapter)-->
<property name="securementActions" value="UsernameToken Encrypt" />
..
</bean>

```

`validationActions`是由空格分隔的操作列表。当发送者发送消息时，将执行`validationActions`（在接收方）。

`securementActions`是由空格分隔的操作列表。当发送者向接收者发送消息时，将执行这些操作。

+   **验证操作：**`UsernameToken, Timestamp, Encrypt, signature`和`NoSecurity`。

+   **安全操作：**`UsernameToken, UsernameTokenSignature, Timestamp, Encrypt, Signature`和`NoSecurity`。

操作的顺序很重要，并由`Wss4jSecurityInterceptor`应用。如果传入的 SOAP 消息`securementActions`（在发送方）与`validationActions`（在接收方）配置的方式不同，该拦截器将返回故障消息。

对于加密/解密或签名等操作，WSS4J 需要从密钥库（`store.jks`）中读取数据：

```java
<bean class="org.springframework. ws.soap.security.wss4j.support.CryptoFactoryBean">
<property name="key storePassword" value="storePassword" />
<property name="key storeLocation" value="/WEB-INF/store.jks" />
</bean>

```

在上一章中已经详细介绍了身份验证、签名、解密和加密等安全概念。在本章中，我们将讨论如何使用 WSS4J 实现这些功能。

为简化起见，在本章的大多数示例中，使用*如何使用 Spring-JUnit 支持集成测试*项目，第三章，*测试和监控 Web 服务*，来设置服务器并通过客户端发送和接收消息。然而，在最后一个示例中，使用了来自第二章的项目，*为 WS-Addressing 端点创建 Web 服务客户端*，用于服务器和客户端。

# 使用用户名令牌和明文/摘要密码对 Web 服务调用进行身份验证

身份验证简单地意味着检查服务的调用者是否是其所声称的。检查调用者的身份验证的一种方式是检查其密码（如果我们将用户名视为一个人，密码类似于该人的签名）。Spring-WS 使用`Wss4jSecurityInterceptor`来发送/接收带有密码的用户名令牌以及 SOAP 消息，并在接收方进行比较，比较其与属性格式中预定义的用户名/密码。拦截器的此属性设置强制告诉消息发送方，发送消息中应包含带有密码的用户名令牌，并且在接收方，接收方期望接收此用户名令牌以进行身份验证。

传输明文密码会使 SOAP 消息不安全。`Wss4jSecurityInterceptor`提供了配置属性（以属性格式）来将密码的摘要与发送方消息一起包括。在接收方，将与属性格式中设置的摘要密码进行比较，该摘要密码包含在传入消息中。

本示例介绍了如何使用用户名令牌对 Web 服务调用进行身份验证。在这里，客户端充当发送方，服务器充当接收方。本示例包含两种情况。在第一种情况下，密码将以明文格式传输。在第二种情况下，通过更改属性，密码将以摘要格式传输。

## 准备工作

在本示例中，我们有以下两个项目：

1.  `LiveRestaurant_R-8.1`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

1.  `LiveRestaurant_R-8.1-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-ws-test-2.0.0.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

按照以下步骤使用带有明文密码的普通用户名令牌进行身份验证：

1.  在服务器端应用程序上下文（`spring-ws-servlet.xml`）中注册`Wss4jSecurityInterceptor`，将验证操作设置为`UsernameToken`，并在此拦截器中配置`callbackHandler`（`....wss4j.callback.SimplePasswordValidationCallbackHandler`）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册`Wss4jSecurityInterceptor`，将`securement`操作设置为`UsernameToken`，并在此处设置`username、password`和`password type`（以`text`格式）。

1.  在`Liverestaurant_R-8.1`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-8.1-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端的输出（请注意，在 SOAP 的`Envelope`的`Header`中突出显示了带有明文密码标记的`UsernameToken`）：

```java
Sent request .....
[<SOAP-ENV:Envelope>
<SOAP-ENV:Header>
<wsse:Security ...>
<wsse:UsernameToken ...>
<wsse:Username>admin</wsse:Username>
<wsse:Password #PasswordText">password</wsse:Password>
</wsse:UsernameToken>
</wsse:Security>
</SOAP-ENV:Header>
....
<tns:placeOrderRequest ...>
....
</tns:order>
</tns:placeOrderRequest>
... Received response ....
<tns:placeOrderResponse ...">
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>
... 

```

按照以下步骤使用用户名令牌和摘要密码实现身份验证：

1.  修改客户端应用程序上下文（`applicationContext.xml`）以将密码类型设置为摘要格式（请注意，服务器端无需进行任何更改）。

1.  在`Liverestaurant_R-8.1`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-8.1-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端输出（请注意，在 SOAP 信封的标头中突出显示了带有摘要密码标记的 UsernameToken）：

```java
Sent request .....
[<SOAP-ENV:Envelope>
<SOAP-ENV:Header>
<wsse:Security ...>
<wsse:UsernameToken ...>
<wsse:Username>admin</wsse:Username>
<wsse:Password #PasswordDigest">
VstlXUXOwyKCIxYh29bNWaSKsRI=
</wsse:Password>
</wsse:UsernameToken>
</wsse:Security>
</SOAP-ENV:Header>
....
<tns:placeOrderRequest ...>
....
</tns:order>
</tns:placeOrderRequest>
... Received response ....
<tns:placeOrderResponse ...">
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>
... 

```

## 工作原理...

`Liverestaurant_R-8.1`项目是一个服务器端 Web 服务，要求其客户端发送包含用户名和密码的 SOAP 信封。

`Liverestaurant_R-8.1-Client`项目是一个客户端测试项目，用于向服务器发送包含用户名令牌和密码的 SOAP 信封。

在服务器端，`Wss4jSecurityInterceptor`强制服务器对所有传入消息进行用户名令牌验证：

```java
<sws:interceptors>
....
<bean id="wss4jSecurityInterceptor" class="org. springframework. ws.soap.security.wss4j.Wss4jSecurityInterceptor">
<property name= "validationCallbackHandler" ref="callbackHandler" />
<property name="validationActions" value="UsernameToken" />
</bean>
</sws:interceptors>

```

拦截器使用`validationCallbackHandler`（`SimplePasswordValidationCallbackHandler`）来比较传入消息的用户名/密码与包含的用户名/密码（admin/password）。

```java
<bean id="callbackHandler" class="org.springframework.aws.soap. security.wss4j.callback.SimplePasswordValidationCallbackHandler">
<property name="users">
<props>
<prop key="admin">password</prop>
</props> 
</property>
</bean>

```

在客户端上，`wss4jSecurityInterceptor`在所有传出消息中包含用户名（`admin/password`）令牌：

```java
<bean id="wss4jSecurityInterceptor" class="org.springframework.ws. soap.security.wss4j.Wss4jSecurityInterceptor">
<property name="securementActions" value="UsernameToken" /> 
<property name="securementUsername" value="admin" />
<property name="securementPassword" value="password" />
<property name="securementPasswordType" value="PasswordText" /> 
</bean>

```

在这种情况下，使用纯文本用户名令牌进行身份验证，因为客户端在进行中的消息中包含了纯文本密码（`<property name="securementPasswordType" value="PasswordText"/>`）：

```java
<wsse:UsernameToke......>
<wsse:Username>admin</wsse:Username>
<wsse:Password ...#PasswordText">password</wsse:Password>
</wsse:UsernameToken> 

```

然而，在第二种情况下，使用摘要用户名令牌进行身份验证，因为密码摘要（`<property name="securementPasswordType" value="PasswordDigest">`）包含在用户名令牌中：

```java
<wsse:UsernameToken...>
<wsse:Username>admin</wsse:Username>
<wsse:Password ...#PasswordDigest">
VstlXUXOwyKCIxYh29bNWaSKsRI=
</wsse:Password>
...
</wsse:UsernameToken> 

```

在这种情况下，服务器将传入的 SOAP 消息摘要密码与`spring-ws-servlet.xml`中设置的计算摘要密码进行比较。通过这种方式，与密码以纯文本形式传输的第一种情况相比，通信将更加安全。

## 另请参阅...

在这一章中：

+   *使用 Spring 安全性进行 Web 服务调用，对具有纯文本/摘要密码的用户名令牌进行身份验证*

+   *使用 X509 证书进行 Web 服务调用的身份验证*

# 使用 Spring 安全性进行 Web 服务调用的身份验证，以验证具有纯文本/摘要密码的用户名令牌

在这里，我们使用用户名令牌进行身份验证，密码为摘要/纯文本，就像本章的第一个示例中所做的那样。这里唯一的区别是使用 Spring 安全框架进行身份验证（SpringPlainTextPasswordValidationCallbackHandler 和`SpringDigestPasswordValidationCallbackHandler`）。由于 Spring 安全框架超出了本书的范围，因此这里不进行描述。但是，您可以在以下网站的*Spring 安全参考*文档中了解更多信息：[`www.springsource.org/security`](http://www.springsource.org/security)。

就像本章的第一个示例一样，这个示例也包含两种情况。在第一种情况下，密码将以纯文本格式传输。在第二种情况下，通过更改配置，密码将以摘要格式传输。

## 准备工作

在这个示例中，我们有以下两个项目：

1.  `LiveRestaurant_R-8.2`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

1.  `LiveRestaurant_R-8.2-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-ws-test-2.0.0.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

按照以下步骤实现 Web 服务调用的身份验证，使用 Spring 安全性对具有纯文本密码的用户名令牌进行身份验证：

1.  在服务器端应用程序上下文（`spring-ws-servlet.xml`）中注册`Wss4jSecurityInterceptor`，将验证操作设置为`UsernameToken`，并在此拦截器中配置`validationCallbackHandler`（....wss4j.callback.SpringPlainTextPasswordValidationCallbackHandler）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册`Wss4jSecurityInterceptor`，将安全操作设置为`UsernameToken`，并设置用户名、密码和密码类型（这里是文本格式）。

1.  在`Liverestaurant_R-8.2`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-8.2-Client`上运行以下命令：

```java
mvn clean package 

```

+   这是客户端的输出（请注意，在 SOAP 的头部中突出显示的具有摘要密码标记的 UsernameToken）：

```java
Sent request .....
<SOAP-ENV:Envelope>
<SOAP-ENV:Header>
<wsse:Security ...>
<wsse:UsernameToken ...>
<wsse:Username>admin</wsse:Username>
<wsse:Password #PasswordText">password</wsse:Password>
</wsse:UsernameToken>
</wsse:Security>
</SOAP-ENV:Header>
....
<tns:placeOrderRequest ...>
....
</tns:order>
</tns:placeOrderRequest>
... Received response ....
<tns:placeOrderResponse ...">
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>
.... 

```

按照以下步骤实现使用 Spring 安全性进行 Web 服务调用的身份验证，以验证具有摘要密码的用户名令牌：

1.  在服务器端应用程序上下文（`spring-ws-servlet.xml`）中修改`Wss4jSecurityInterceptor`并在此拦截器中配置`validationCallbackHandler`（`....ws.soap.security.wss4j.callback.SpringDigestPasswordValidationCallbackHandler`）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中修改`Wss4jSecurityInterceptor`以设置密码类型（这里是摘要格式）。

1.  在`Liverestaurant_R-8.2`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-8.2-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端的输出（请注意 SOAP 信封的标头中突出显示的带有摘要密码标签的 UsernameToken）：

```java
Sent request .....
[<SOAP-ENV:Envelope>
<SOAP-ENV:Header>
<wsse:Security ...>
<wsse:UsernameToken ...>
<wsse:Username>admin</wsse:Username>
<wsse:Password #PasswordDigest">
VstlXUXOwyKCIxYh29bNWaSKsRI=</wsse:Password>
</wsse:UsernameToken>
</wsse:Security>
</SOAP-ENV:Header>
....
<tns:placeOrderRequest ...>
....
</tns:order>
</tns:placeOrderRequest>
... Received response ....
<tns:placeOrderResponse ...">
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse>
... 

```

## 它是如何工作的...

在`Liverestaurant_R-8.2`项目中，客户端和服务器的安全性几乎与`Liverestaurant_R-8.1`相同（如本章第一个配方所示），只是在服务器端验证用户名令牌。Spring 安全类负责通过与从 DAO 层获取的数据进行比较来验证用户名和密码（而不是在`spring-ws-servlet.xml`中硬编码用户名/密码）。此外，可以从 DAO 层获取其他与成功验证用户相关的数据，并返回以进行授权以检查一些帐户数据。

在第一种情况下，`CallbackHandler SpringPlainTextPasswordValidationCallbackHandler`使用`authenticationManager`，该管理器使用`DaoAuthenticationProvider`。

```java
<bean id="springSecurityHandler" class="org.springframework.ws.soap.security. wss4j.callback.SpringPlainTextPasswordValidationCallbackHandler">
<property name="authenticationManager" ref="authenticationManager"/>
</bean>
<bean id="authenticationManager" class= "org.springframework.security.authentication.ProviderManager">
<property name="providers">
<bean class="org.springframework. security.authentication.dao.DaoAuthenticationProvider">
<property name="userDetailsService" ref="userDetailsService"/>
</bean>
</property>
</bean>

```

此提供程序调用自定义用户信息服务（`MyUserDetailService.java`），该服务从提供程序获取用户名并在内部从 DAO 层获取该用户的所有信息（例如密码、角色、是否过期等）。最终，该服务以`UserDetails`类型类（`MyUserDetails.java`）返回填充的数据。现在，如果`UserDetails`数据与传入消息的用户名/密码匹配，则返回响应；否则，返回 SOAP 故障消息：

```java
public class MyUserDetailService implements UserDetailsService {
@Override
public UserDetails loadUserByUsername(String username)
throws UsernameNotFoundException, DataAccessException {
return getUserDataFromDao(username);
}
private MyUserDetail getUserDataFromDao(String username) {
/**
*Real scenario: find user data from a DAO layer by userName,
* if this user name found, populate MyUserDetail with its data(username, password,Role, ....).
*/
MyUserDetail mydetail=new MyUserDetail( username,"pass",true,true,true,true);
mydetail.getAuthorities().add( new GrantedAuthorityImpl("ROLE_GENERAL_OPERATOR"));
return mydetail;
}

```

然而，在第二种情况下，`CallbackHandler`是`SpringDigestPasswordValidationCallbackHandler`，它将 SOAP 传入消息中包含的摘要密码与从 DAO 层获取的摘要密码进行比较（请注意，DAO 层可以从不同的数据源获取数据，如数据库、LDAP、XML 文件等）：

```java
<bean id="springSecurityHandler" class="org.springframework.ws.soap.security.wss4j.callback. SpringDigestPasswordValidationCallbackHandler">
<property name="userDetailsService" ref="userDetailsService"/>
</bean>

```

与本章第一个配方相同，在客户端应用程序上下文中将`<property name="securementPasswordType" value="PasswordText">`修改为`PasswordDigest`会导致密码以摘要格式传输。

## 另请参阅...

在本章中：

+   *使用用户名令牌进行 Web 服务调用的身份验证，使用明文/摘要密码*

+   *使用 X509 证书对 Web 服务调用进行身份验证*

# 使用数字签名保护 SOAP 消息

在安全术语中，签名的目的是验证接收到的消息是否被篡改。签名在 WS-Security 中扮演着两个主要任务，即对消息进行签名和验证签名。消息签名涉及的所有概念都在上一章的*使用数字签名保护 SOAP 消息*中详细介绍。在这个配方中，使用 WSS4J 进行签名和验证签名。

Spring-WS 的`Wss4jSecurityInterceptor`能够根据 WS-Security 标准进行签名和验证签名。

将此拦截器的`securementActions`属性设置为`Signature`会导致发送方对传出消息进行签名。要加密签名令牌，需要发送方的私钥。需要在应用程序上下文文件中配置密钥库的属性。`securementUsername`和`securementPassword`属性指定了用于使用的密钥库中的私钥的别名和密码。`securementSignatureCrypto`应指定包含私钥的密钥库。

将`validationActions`设置为`value="Signature`"会导致消息的接收方期望并验证传入消息的签名（如开头所述）。`validationSignatureCrypto` bean 应指定包含发送方公钥证书（受信任证书）的密钥库。

来自`wss4j`包的`org.springframework.ws.soap.security.wss4j.support.CryptoFactoryBean`可以提取密钥库数据（例如证书和其他密钥库信息），并且这些数据可以用于身份验证。

在本教程中，客户端存储的私钥用于加密消息的客户端签名。在服务器端，包含在服务器密钥库中的客户端公钥证书（在受信任证书条目中）将用于解密消息签名令牌。然后服务器对签名进行验证（如开头所述）。在[第七章中使用的密钥库，在*准备配对和对称密钥库*中使用。

## 准备工作

在本教程中，我们有以下两个项目：

1.  `LiveRestaurant_R-8.3`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

1.  `LiveRestaurant_R-8.3-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-ws-test-2.0.0.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

1.  在服务器端应用程序上下文（`spring-ws-servlet.xml`）中注册`Wss4jSecurityInterceptor`，将验证操作设置为`Signature`，并在此拦截器中将`validationSignatureCrypto`属性设置为`CryptoFactoryBean`（配置服务器端密钥库位置及其密码）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册`Wss4jSecurityInterceptor`，将安全操作设置为`Signature`，并在此拦截器中将`securementSignatureCrypto`属性设置为`CryptoFactoryBean`（配置客户端密钥库位置及其密码）。

1.  在`Liverestaurant_R-8.3`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-8.3-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端的输出（请注意突出显示的文本）：

```java
Sent request ....
<SOAP-ENV:Header>
<wsse:Security...>
<ds:Signature ...>
<ds:SignedInfo>
.....
</ds:SignedInfo>
<ds:SignatureValue>
IYSEHmk+.....
</ds:SignatureValue>
<ds:KeyInfo ..>
<wsse:SecurityTokenReference ...>
<ds:X509Data>
<ds:X509IssuerSerial>
<ds:X509IssuerName>
CN=MyFirstName MyLastName,OU=Software,O=MyCompany,L=MyCity,ST=MyProvince,C=ME
</ds:X509IssuerName>
<ds:X509SerialNumber>1311686430</ds:X509SerialNumber>
</ds:X509IssuerSerial>
</ds:X509Data>
</wsse:SecurityTokenReference>
</ds:KeyInfo>
</ds:Signature>
</wsse:Security>
</SOAP-ENV:Header>
<SOAP-ENV:Body ...>
<tns:placeOrderRequest ...>
.....
</tns:order>
</tns:placeOrderRequest>
.. Received response
.....<tns:placeOrderResponse....>
<tns:refNumber>order-John_Smith_1234</tns:refNumber>
</tns:placeOrderResponse> 

```

## 它是如何工作的...

服务器端的安全配置要求客户端在消息中包含一个二进制签名令牌。客户端配置文件中的设置将签名令牌包含在传出消息中。客户端使用自己的私钥（包含在客户端密钥库中）对消息的签名进行加密（根据消息的内容计算）。在服务器端，来自服务器端的客户端证书（受信任证书）密钥库用于解密签名令牌。然后将对二进制签名令牌的签名验证（如本章开头所述）进行验证。

在服务器端将`validationActions`设置为`Signature`会导致它期望来自客户端配置的签名，并且设置密钥库会导致服务器端密钥库中的客户端公钥证书（受信任证书）用于解密签名。然后服务器对签名进行验证：

```java
<sws:interceptors>
<bean class="org.springframework.ws.soap.server.endpoint. interceptor.PayloadValidatingInterceptor">
<property name="schema" value="/WEB-INF/orderService.xsd" />
<property name="validateRequest" value="true" />
<property name="validateResponse" value="true" />
</bean>
<bean class="org.springframework.ws.soap.server.endpoint. interceptor.SoapEnvelopeLoggingInterceptor"/>
<bean id="wsSecurityInterceptor" class="org.springframework.ws. soap.security.wss4j.Wss4jSecurityInterceptor">
<property name="validationActions" value="Signature" />
<property name="validationSignatureCrypto">
<bean class="org.springframework.ws.soap.security. wss4j.support.CryptoFactoryBean">
<property name="key storePassword" value="serverPassword" />
<property name="key storeLocation" value="/WEB-INF/serverStore.jks" />
</bean>
</property>
</bean>
</sws:interceptors>

```

代码语句`<property name="securementActions" value="Signature" />`，并在客户端配置中设置密钥库会导致客户端发送加密签名（使用别名为`client`的客户端私钥，并且客户端加密从消息生成的哈希（签名）），并随消息一起发送：

```java
<bean id="wss4jSecurityInterceptor" class="org.springframework.ws. soap.security.wss4j.Wss4jSecurityInterceptor">
<property name="securementActions" value="Signature" />
<property name="securementUsername" value="client" />
<property name="securementPassword" value="cliPkPassword" />
<property name="securementSignatureCrypto">
<bean class="org.springframework.ws.soap.security. wss4j.support.CryptoFactoryBean">
<property name="key storePassword" value="clientPassword" />
<property name="key storeLocation" value="classpath:/clientStore.jks" />
</bean>
</property>
</bean>

```

## 另请参阅...

在本章中：

+   *使用 X509 证书对 Web 服务调用进行身份验证*

第七章，*使用 XWSS 库保护 SOAP Web 服务：*

+   *准备配对和对称密钥存储*

# 使用 X509 证书对 Web 服务调用进行身份验证

在本章的前面部分，介绍了如何使用用户名令牌对传入消息进行身份验证。随传入消息一起传来的客户端证书可以用作替代用户名令牌进行身份验证。

为了确保所有传入的 SOAP 消息携带客户端的证书，发送方的配置文件应该签名，接收方应该要求所有消息都有签名。换句话说，客户端应该对消息进行签名，并在传出消息中包含 X509 证书，服务器首先将传入的证书与信任的证书进行比较，该证书嵌入在服务器密钥库中，然后进行验证传入消息的签名。

## 准备工作

在此配方中，我们有以下两个项目：

1.  `LiveRestaurant_R-8.4`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

1.  `LiveRestaurant_R-8.4-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-ws-test-2.0.0.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

1.  在服务器端应用程序上下文（`spring-ws-servlet.xml`）中注册`Wss4jSecurityInterceptor`，将验证操作设置为`Signature`，并在此拦截器中将属性`validationSignatureCrypto`设置为`CryptoFactoryBean`（配置服务器端密钥库位置及其密码）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册`Wss4jSecurityInterceptor`，将安全操作设置为`Signature`，设置一个属性（`securementSignatureKeyIdentifier`）以包含二进制`X509`令牌，并在此拦截器中将属性`securementSignatureCrypto`设置为`CryptoFactoryBean`（配置客户端密钥库位置及其密码）。 

以下是客户端的输出（请注意突出显示的文本）：

```java
Sent request ....
<SOAP-ENV:Header>
<wsse:Security ...>
<wsse:BinarySecurityToken....wss-x509-token-profile- 1.0#X509v3" ...>
MIICbTCCAdagAwIBAgIETi6/HjANBgkqhki...
</wsse:BinarySecurityToken>
<ds:Signature ....>
.....
....
</ds:Signature>.... 

```

## 工作原理...

签名和验证签名与本章中*使用数字签名保护 SOAP 消息*的配方相同。不同之处在于配置的以下部分，用于生成包含 X509 证书的`BinarySecurityToken`元素，并在发送方的传出消息中包含它：

```java
<property name="securementSignatureKeyIdentifier" value="DirectReference" />

```

在签名消息时将客户端证书嵌入调用者消息中，使服务器验证该证书与密钥库中包含的证书（受信任的证书条目）一致。此验证确认了调用者是否是他/她声称的人。

## 另请参阅...

在本章中：

+   *使用数字签名保护 Soap 消息*

第七章，*使用 XWSS 库保护 SOAP Web 服务：*

+   *准备配对和对称密钥存储*

# 加密/解密 SOAP 消息

SOAP 消息的加密和解密概念与第七章中描述的*加密/解密 SOAP 消息*相同。Spring-WS 的`Wss4jSecurityInterceptor`通过在接收方（这里是服务器端）设置属性`validationActions`为`Encrypt`来提供对传入 SOAP 消息的解密。在发送方（这里是客户端）设置属性`securementActions`会导致发送方对传出消息进行加密。

`Wss4jSecurityInterceptor`需要访问密钥库进行加密/解密。在使用对称密钥的情况下，`Key storeCallbackHandler`负责访问（通过设置`location`和`password`属性）并从对称密钥库中读取，并将其传递给拦截器。然而，在使用私钥/公钥对存储的情况下，`CryptoFactoryBean`将执行相同的工作。

在这个示例中，在第一种情况下，客户端和服务器共享的对称密钥用于客户端的加密和服务器端的解密。然后，在第二种情况下，客户端密钥库中的服务器公钥证书（受信任的证书）用于数据加密，服务器端密钥库中的服务器私钥用于解密。

在前两种情况下，整个有效载荷用于加密/解密。通过设置一个属性，可以对有效载荷的一部分进行加密/解密。在第三种情况下，只有有效载荷的一部分被设置为加密/解密的目标。

## 准备工作

在这个示例中，我们有以下两个项目：

1.  `LiveRestaurant_R-8.5`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

1.  `LiveRestaurant_R-8.5-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-ws-security-2.0.1.RELEASE.jar`

+   `spring-ws-test-2.0.0.RELEASE.jar`

+   `spring-expression-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 操作步骤...

按照以下步骤使用对称密钥实施加密/解密：

1.  在服务器端应用程序上下文（`spring-ws-servlet.xml`）中注册`Wss4jSecurityInterceptor`，将验证操作设置为`Encrypt`，并在此拦截器内配置`Key storeCallbackHandler`以从对称密钥库中读取（配置服务器端对称密钥库位置及其密码）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册`Wss4jSecurityInterceptor`，将安全操作设置为`Encrypt`，并配置`Key storeCallbackHandler`以从对称密钥库中读取（配置客户端对称密钥库位置及其密码）。

1.  在`Liverestaurant_R-8.5`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-8.5-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端的输出（请注意突出显示的文本）：

```java
Sent request...
<SOAP-ENV:Header>
<wsse:Security...>
<xenc:ReferenceList><xenc:DataReference../> </xenc:ReferenceList>
</wsse:Security>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<xenc:EncryptedData ...>
<xenc:EncryptionMethod..tripledes-cbc"/>
<ds:KeyInfo...>
<ds:KeyName>symmetric</ds:KeyName>
</ds:KeyInfo>
<xenc:CipherData><xenc:CipherValue>
3a2tx9zTnVTKl7E+Q6wm...
</xenc:CipherValue></xenc:CipherData>
</xenc:EncryptedData>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope> 

```

按照以下步骤在客户端密钥库（在`clientStore.jsk`中）上使用服务器信任的证书实施加密，并在服务器端私钥（在`serverStore.jks`中）上进行解密：

1.  在服务器端应用程序上下文（`spring-ws-servlet.xml`）中注册`Wss4jSecurityInterceptor`，将验证操作设置为`Encrypt`，并在此拦截器内将属性`validationSignatureCrypto`设置为`CryptoFactoryBean`（配置服务器端密钥库位置及其密码）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册`Wss4jSecurityInterceptor`，将安全操作设置为`Encrypt`，并在此拦截器内将`securementSignatureCrypto`设置为`CryptoFactoryBean`（配置客户端密钥库位置及其密码）。

以下是服务器端的输出（请注意突出显示的文本）：

```java
<SOAP-ENV:Header>
<wsse:Security...>
<xenc:EncryptionMethod ..">
<wsse:SecurityTokenReference ...>
<ds:X509Data>
<ds:X509IssuerSerial>
<ds:X509IssuerName>
CN=MyFirstName MyLastName,OU=Software,O=MyCompany, L=MyCity,ST=MyProvince,C=ME
</ds:X509IssuerName>
<ds:X509SerialNumber>1311685900</ds:X509SerialNumber>
</ds:X509IssuerSerial>
</ds:X509Data>
</wsse:SecurityTokenReference>
</ds:KeyInfo>
<xenc:CipherData>
<xenc:CipherValue>dn0lokNhtmZ9...</xenc:CipherValue>
</xenc:CipherData><xenc:ReferenceList>
....
</wsse:Security>
</SOAP-ENV:Header><SOAP-ENV:Body>
<xenc:EncryptedData .../>
<ds:KeyInfo ...xmldsig#">
<wsse:SecurityTokenReference ...>
<wsse:Reference .../>
</wsse:SecurityTokenReference>
</ds:KeyInfo>
<xenc:CipherData><xenc:CipherValue>
UDO872y+r....</xenc:CipherValue>
</xenc:CipherData></xenc:EncryptedData>
</SOAP-ENV:Body> 

```

按照以下步骤在有效载荷上实施加密/解密：

1.  修改第 2 种情况，将`Wss4jSecurityInterceptor`上的`securementEncryptionParts`属性设置为有效载荷的特定部分，无论是在服务器端还是客户端。

1.  在`Liverestaurant_R-8.5`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-8.5-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端的输出（请注意突出显示的文本）：

```java
..........
<SOAP-ENV:Body>
<tns:placeOrderRequest...>
<xenc:EncryptedData...>
<xenc:EncryptionMethod .../>
<ds:KeyInfo..xmldsig#">
<wsse:SecurityTokenReference ...>
<wsse:Reference.../></wsse:SecurityTokenReference>
</ds:KeyInfo><xenc:CipherData>
<xenc:CipherValue>
pGzc3/j5GX......
</xenc:CipherValue>
</xenc:CipherData>
</xenc:EncryptedData>
</tns:placeOrderRequest>
....... 

```

## 工作原理...

在第一种情况下，客户端和服务器都共享对称密钥。客户端使用对称密钥加密整个有效载荷，并将其发送到服务器。在服务器端，相同的密钥将用于解密有效载荷。

然而，在第二和第三种情况下，客户端存储中嵌入的服务器证书用于加密有效负载，在服务器端，服务器存储的私钥将用于解密。第二种和第三种情况之间的区别在于第二种情况加密/解密整个有效负载，但在第三种情况下，只有部分有效负载将成为加密/解密的目标。

在第一种情况下，在服务器端将`validationActions`设置为`Encrypt`会导致服务器使用对称密钥解密传入消息。拦截器使用`ValidationCallbackHandler`进行解密，使用在`location`属性中设置的对称密钥存储。`type`属性设置密钥的存储类型，`password`设置对称密钥的密钥存储密码：

```java
<bean class="org.springframework.ws.soap. security.wss4j.Wss4jSecurityInterceptor">
<property name="validationActions" value="Encrypt"/>
<property name="validationCallbackHandler">
<bean class="org.springframework.ws.soap.security. wss4j.callback.Key storeCallbackHandler">
<property name="key store">
<bean class="org.springframework.ws.soap.security. support.Key storeFactoryBean">
<property name="location" value="/WEB- INF/symmetricStore.jks"/>
<property name="type" value="JCEKS"/>
<property name="password" value="symmetricPassword"/>
</bean>
</property>
<property name="symmetricKeyPassword" value="keyPassword"/>
</bean>
</property>
</bean>

```

在客户端，将`securementActions`属性设置为`Encrypt`会导致客户端加密所有传出消息。通过将`securementEncryptionKeyIdentifier`设置为`EmbeddedKeyName`来自定义加密。选择`EmbeddedKeyName`类型时，加密的秘钥是必需的。对称密钥别名（此处为对称）由`securementEncryptionUser`设置。

默认情况下，SOAP 标头中的`ds:KeyName`元素采用`securementEncryptionUser`属性的值。`securementEncryptionEmbeddedKeyName`可用于指示不同的值。`securementEncryptionKeyTransportAlgorithm`属性定义要使用的算法来加密生成的对称密钥。`securementCallbackHandler`提供了`Key storeCallbackHandler`，指向适当的密钥存储，即服务器端配置中描述的对称密钥存储：

```java
<bean class="org.springframework.ws.soap. security.wss4j.Wss4jSecurityInterceptor">
<property name="securementActions" value="Encrypt" />
<property name="securementEncryptionKeyIdentifier" value="EmbeddedKeyName"/>
<property name="securementEncryptionUser" value="symmetric"/>
<property name="securementEncryptionEmbeddedKeyName" value="symmetric"/>
<property name="SecurementEncryptionSymAlgorithm" value="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
<property name="securementCallbackHandler">
<bean class="org.springframework.ws.soap.security. wss4j.callback.Key storeCallbackHandler">
<property name="symmetricKeyPassword" value="keyPassword"/>
<property name="key store">
<bean class="org.springframework.ws.soap.security. support.Key storeFactoryBean">
<property name="location" value="/symmetricStore.jks"/>
<property name="type" value="JCEKS"/>
<property name="password" value="symmetricPassword"/>
</bean>
</property>
</bean>
</property>
</bean>

```

在第二和第三种情况下，服务器端配置的`validationDecryptionCrypto`几乎与第一种情况解密数据的方式相同：

```java
<bean class="org.springframework.ws.soap.security. wss4j.Wss4jSecurityInterceptor">
<property name="validationActions" value="Encrypt" />
<property name="validationDecryptionCrypto">
<bean class="org.springframework.ws.soap.security. wss4j.support.CryptoFactoryBean">
<property name="key storePassword" value="serverPassword" />
<property name="key storeLocation" value="/WEB- INF/serverStore.jks" />
</bean>
</property>
<property name="validationCallbackHandler">
<bean class="org.springframework.ws.soap.security. wss4j.callback.Key storeCallbackHandler">
<property name="privateKeyPassword" value="serPkPassword" />
</bean>
</property>
</bean>

```

在客户端，将`securementActions`的`value="Encrypt`"设置为会导致客户端加密所有传出消息。`securementEncryptionCrypto`用于设置密钥存储位置和密码。`SecurementEncryptionUser`用于设置服务器证书在客户端密钥存储中的别名：

```java
<bean class="org.springframework.ws.soap.security. wss4j.Wss4jSecurityInterceptor">
<property name="securementActions" value="Encrypt" />
<property name="securementEncryptionUser" value="server" />
<property name="securementEncryptionCrypto">
<bean class="org.springframework.ws.soap.security. wss4j.support.CryptoFactoryBean">
<property name="key storePassword" value="clientPassword" />
<property name="key storeLocation" value="/clientStore.jks" />
</bean>
</property>
</bean>

```

*第 2 种*和*第 3 种*之间的区别在于在客户端/服务器端配置中的配置设置仅导致部分有效负载被加密/解密。

```java
---client/server configuration file
<property name="securementEncryptionParts"value="{Content} {http://www.packtpub.com/LiveRestaurant/OrderService/schema} placeOrderRequest"/>

```

## 另请参阅...

在本章中：

+   *使用数字签名保护 SOAP 消息*

第二章,*为 SOAP Web 服务构建客户端*

+   *为 WS-Addressing 端点创建 Web 服务客户端*

第七章,*使用 XWSS 库保护 SOAP Web 服务*

+   *准备*一对和对称密钥存储*


# 第九章：RESTful Web 服务

在本章中，我们将涵盖：

+   使用 Spring MVC 中的 RESTful 功能设置 Spring RESTful Web 服务

+   使用`RESTClient`工具访问 Spring RESTful Web 服务

+   使用 HTTP 消息转换设置 Spring RESTful Web 服务

+   为 Spring RESTful Web 服务创建 WS 客户端，使用 Spring 模板类

# 介绍

**简单对象访问协议（SOAP）**允许应用程序使用 XML 作为通信格式进行通信（SOAP 很容易理解），但由于它是基于 XML 的，即使对于非常简单的 Web 服务场景，它也往往冗长。

**表述性状态转移（REST）**，由 Roy Fielding 于 2000 年发表的博士论文，旨在简化 Web 服务的使用。

SOAP 使用大量 XML（看起来非常复杂）进行通信，而 REST 使用非常轻量级和易读的数据（例如，请求 URI[`localhost:8080/LiveRestaurant/customerAccount/234`](http://localhost:8080/LiveRestaurant/customerAccount/234)返回`123-3456`）。将此简单请求和响应与 SOAP 请求/响应信封进行比较，这些信封已经在本书的前几章中介绍过。由于 REST Web 服务实现非常灵活且非常简单，因此不需要工具包。但是，基于 SOAP 的 Web 服务需要工具来简化（例如，要调用 SOAP Web 服务，您将使用工具为合同后的 Web 服务类生成客户端代理类，或者使用工具从合同优先的 Web 服务中生成域类）。在前几章中，您将意识到合同优先的 Web 服务有多么严格（它必须与合同匹配）。REST Web 服务的请求/响应格式完全由开发人员决定，并且可以尽可能轻松地设计。在使用 SOAP Web 服务时，使用 JavaScript 并不容易（需要大量代码）。使用 AJAX 技术和 JSON 格式简化了 REST 的使用。

以下是 REST 的一些缺点：REST 仅适用于 HTTP；调用 RESTful Web 服务受到 HTTP 动词的限制：GET、POST、PUT 和 DELETE。

RESTful 是建立在 REST 原则之上的，其中使用 HTTP 的方法基于其概念。例如，HTTP 的`GET、POST、PUT`和`DELETE`都在 RESTful 架构中使用，与 HTTP 的含义相匹配。

RESTful Web 服务公开其资源的状态。在本章中，例如，RESTful 服务公开了获取在线餐厅中可用订单项目列表和订单对象的服务。要获取可用订单项目列表，使用`GET`方法，而要下订单，则使用`POST`方法。`PUT`方法可用于添加/更新条目，`DELETE`方法可用于删除条目。

以下是用于进行 RESTful Web 服务调用并获取可用订单项目列表的示例 URL：

[`localhost:8080/LiveRestaurant/orderItems`](http://localhost:8080/LiveRestaurant/orderItems)。

以下是返回响应（响应格式不一定是 XML 格式；它可以是 JSON、纯文本或任何格式）：

```java
<list>
<orderItem>
<name>Burger</name>
<id>0</id>
</orderItem>
<orderItem>
<name>Pizza</name>
<id>1</id>
</orderItem>
<orderItem>
<name>Sushi</name><id>2</id>
</orderItem>
<orderItem>
<name>Salad</name>
<id>3</id>
</orderItem>
</list> 

```

RESTful Web 服务有几种实现，例如`Restlet、RestEasy`和`Jersey`。其中，Jersey 是这一组中最重要的实现，是 JAX-RS（JSR 311）的实现。

Spring 作为 Java EE 广泛使用的框架，在 3.0 版本中引入了对 RESTful Web 服务的支持。RESTful 已经集成到 Spring 的 MVC 层中，允许应用程序使用 RESTful 功能构建 Spring。其中最重要的功能包括：

+   **注释**，例如`@RequestMapping`和`@PathVariable`，用于 URI 映射和传递参数。

+   `ContentNegotiatingViewResolver`，允许使用不同的 MIME 类型（如`text/xml、text/json`和`text/plain`）

+   `HttpMessageConverter`允许基于客户端请求（如 ATOM、XML 和 JSON）生成多种表示。

# 使用 Spring MVC 中的 RESTful 特性设置 Spring RESTful Web 服务。

Spring 3.0 支持基于 Spring MVC 的 RESTful Web 服务。Spring 使用注解来设置 RESTful Web 服务，并需要在 Spring 应用程序上下文文件中进行配置以扫描注解。需要一个 Spring MVC 控制器来设置 RESTful Web 服务。`@Controller`注解标记一个类为 MVC 控制器。`@RequestMapping`注解将传入的请求映射到控制器类中的适当 Java 方法。使用这个注解，你可以定义 URI 和 HTTP 方法，这些方法映射到 Java 类方法。例如，在下面的例子中，如果请求 URI 后跟着`/orderItems`，那么方法`loadOrderItems`将被调用，`@PathVariable`用于将请求参数（`{cayegoryId}`）的值注入到方法参数中（`String cayegoryId`）：

```java
@RequestMapping( value="/orderItem/{cayegoryId}", method=RequestMethod.GET )
public ModelAndView loadOrderItems(@PathVariable String cayegoryId)
{...}

```

在这个示例中，介绍了使用 Spring 3 MVC 实现 RESTful Web 服务。这个 Web 服务的客户端项目在这里实现了，但将在本章的最后一个示例中详细介绍：*使用 Spring 模板类为 Spring RESTful Web 服务创建 WS 客户端*。

## 准备工作

在这个示例中，项目的名称是`LiveRestaurant_R-9.1`（`LiveRestaurant_R-9.1-Client`项目包含在代码中用于测试目的），具有以下 Maven 依赖项：

+   `com.springsource.javax.servlet-2.5.0.jar`

+   `spring-oxm-3.0.5.RELEASE.jar`

+   `spring-web-3.0.5.RELEASE.jar`

+   `spring-webmvc-3.0.5.RELEASE.jar`

+   `xstream-1.3.1.jar`

+   `commons-logging-1.1.1.jar`

`spring-oxm`是 Spring 对对象/XML 映射的支持，`spring-web`和`spring-webmvc`是对 Seb 和 MVC 支持的支持，`xstream`是用于对象/XML 映射框架的支持。

## 如何做...

1.  在`web.xml`文件中配置`MessageDispatcherServlet`（URL：http://<host>:<port>/<appcontext>/*将被转发到此 servlet）。

1.  定义控制器文件（`OrderController.java`）。

1.  定义领域 POJO（`Order.java,OrderItem.java`）和服务（`OrderService, OrderServiceImpl`）。

1.  配置服务器端应用程序上下文文件（`order-servlet.xml`）。

1.  在`Liverestaurant_R-9.1`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-9.1-Client`上运行以下命令：

```java
mvn clean package 

```

+   这是客户端输出：

```java
.... Created POST request for "http://localhost:8080/LiveRestaurant/order/1"
.....Setting request Accept header to [application/xml, text/xml, application/*+xml]
.... POST request for "http://localhost:8080/LiveRestaurant/order/1" resulted in 200 (OK)
.....Reading [com.packtpub.liverestaurant.domain.Order] as "application/xml;charset=ISO-8859-1"
.....
.....Created GET request for "http://localhost:8080/LiveRestaurant/orderItems"
.....Setting request Accept header to [application/xml, text/xml, application/*+xml]
.....GET request for "http://localhost:8080/LiveRestaurant/orderItems" resulted in 200 (OK) 

```

1.  浏览到此链接：[`localhost:8080/LiveRestaurant/orderItems`](http://localhost:8080/LiveRestaurant/orderItems)，您将得到以下响应：

```java
<list>
<orderItem>
<name>Burger</name>
<id>0</id>
</orderItem>
<orderItem>
<name>Pizza</name>
<id>1</id>
</orderItem>
<orderItem>
<name>Sushi</name><id>2</id>
</orderItem>
<orderItem>
<name>Salad</name>
<id>3</id>
</orderItem>
</list> 

```

## 它是如何工作的...

该应用程序是一个 MVC Web 项目，其中一个控制器返回 Spring 的`Model`和`View`对象。Spring 的`MarshallingView`将模型对象编组成 XML，使用`marshaller`（`XStreamMarshaller`），并将 XML 发送回客户端。

所有请求将到达`DispatcherServlet`，它将被转发到控制器`OrderController`，根据请求 URI，将调用适当的方法返回响应给调用者。`web.xml`中的以下配置将所有请求转发到`DispatcherServlet`：

```java
<servlet>
<servlet-name>order</servlet-name>
<servlet-class>
org.springframework.web.servlet.DispatcherServlet
</servlet-class>
<load-on-startup>1</load-on-startup>
</servlet>
<servlet-mapping>
<servlet-name>order</servlet-name>
<url-pattern>/*</url-pattern>
</servlet-mapping>

```

在`order-context.xml`中的以下设置导致 Spring 检测包中的所有注解（包括`OrderService`和`OrderController`）。`BeanNameViewResolver`用于将名称（`OrderController`中的`orderXmlView`）映射到视图（`orderXmlView` bean），它是`org.springframework.web.servlet.view.xml.MarshallingView`的实例：

```java
<context:component-scan base-package= "com.packtpub.liverestaurant.orderservice" />
<bean class= "org.springframework.web.servlet.view.BeanNameViewResolver" />
<bean id="orderXmlView" class= "org.springframework.web.servlet.view.xml.MarshallingView">
...
</bean>

```

`@Controller`标记`OrderController`类为 MVC 模式中的控制器。所有调用请求将被转发到该类，并根据请求 URI，将调用适当的方法。例如，如果来自调用者请求的 HTTP `POST`方法的 URI 类似于`http://<host>:<port>/<appcontext>/order/1`，则将调用`placeOrder`方法。

```java
@RequestMapping(value = "/order/{orderId}", method = RequestMethod.POST)
public ModelAndView placeOrder(@PathVariable String orderId) {..}

```

`@PathVariable`导致从 URI 中注入并传递给`placeOrder`方法的`orderId`参数。

方法的主体`placeOrder`调用`OrderService`接口的方法并返回`Order`对象：

```java
Order order = orderService.placeOrder(orderId);
ModelAndView mav = new ModelAndView("orderXmlView", BindingResult.MODEL_KEY_PREFIX + "order", order);
return mav;

```

然后，它基于将`Order`对象编组成 XML 格式来构建视图，使用`Marshallingview` bean（MVC 中的视图使用`XStreamMarshaller`将模型对象编组成 XML 格式），并将其返回给服务的调用者。

```java
<bean id="orderXmlView" class= "org.springframework.web.servlet.view.xml.MarshallingView">
<constructor-arg>
<bean class="org.springframework.oxm.xstream.XStreamMarshaller">
<property name="autodetectAnnotations" value="true"/>
</bean>
</constructor-arg>
</bean>

```

`loadOrderItems`方法的工作方式相同，只是 URI 应该类似于以下模式：`http://<host>:<port>/<appcontext>/orderItems`，使用 HTTP `GET`：

```java
@RequestMapping(value = "/orderItems", method = RequestMethod.GET)
public ModelAndView loadOrderItems() {
List<OrderItem> orderItems = orderService.listOrderItems();
ModelAndView modelAndView = new ModelAndView("orderXmlView", BindingResult.MODEL_KEY_PREFIX + "orderItem", orderItems);
return modelAndView;
}

```

在本教程中，数据库活动未实现。但是，在实际应用中，可以使用 HTTP 方法`DELETE`从数据库中删除实体（例如`orderItem`），并且可以使用`PUT`方法更新记录（例如`order`）。

## 另请参阅...

在本书中：

第六章，*编组和对象-XML 映射（OXM）*：

*使用 XStream 进行编组*

# 使用 REST 客户端工具访问 Spring RESTful Web-Service

**REST Client**是一个用于调用和测试 RESTful Web-Services 的应用程序。REST Client 作为 Firefox/Flock 附加组件提供。Firefox REST Client 支持所有 HTTP 方法，**RFC2616（HTTP/1.1）**和**RFC2518（WebDAV）**。使用此附加组件，您可以构建自己定制的 URI，添加标头，将其发送到 RESTful Web-Services，并获取响应。

在本教程中，我们将学习如何使用 Firefox REST Client 测试 RESTful Web-Service 的呈现方式。本教程使用本章的第一个教程，*使用 Spring MVC 中的 RESTful 功能设置 Spring RESTful Web-Service*，作为 RESTful Web-Services。

## 准备工作

下载并安装 Firefox 的以下附加组件：

[`addons.mozilla.org/en-US/firefox/addon/restclient/`](http://https://addons.mozilla.org/en-US/firefox/addon/restclient/)。

## 如何做...

1.  从本章运行`LiveRestaurant_R-9.1`。

1.  打开 Firefox 浏览器，转到**工具 | Rest Client**。

1.  将**方法**更改为**GET**，并输入 URL：[`localhost:8080/LiveRestaurant/orderItems`](http://localhost:8080/LiveRestaurant/orderItems)，然后单击**发送**：

这是结果：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825OS_09_01.jpg)

1.  将**方法**更改为**POST**，输入 URL：[`localhost:8080/LiveRestaurant/order/1`](http://localhost:8080/LiveRestaurant/order/1)，然后单击**发送**：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825OS_09_02.jpg)

## 另请参阅...

在本章中：

使用 Spring MVC 中的 RESTful 功能设置 Spring RESTful Web-Service

# 使用 HTTP 消息转换设置 Spring RESTful Web-Service

HTTP 协议上的客户端和服务器使用文本格式交换数据。最终，需要接受不同的请求格式，并将文本格式转换为有意义的格式，例如对象或 JSON 格式。Spring 提供了提供从相同文本格式到多个请求/演示的功能。

Spring 3 引入了`ContentNegotiatingViewResolver`，它可以从相同的 URI 选择各种视图，并提供多个演示。

执行相同任务的另一种方法是使用`HttpMessageConverter`接口和`@ResponseBody`注解。Spring 中`HttpMessageConverter`接口的实现将 HTTP 消息转换为多种格式。其广泛使用的实现包括：

+   `StringHttpMessageConverter`实现从 HTTP 请求/响应中读取/写入文本。这是默认转换器。

+   `MarshallingHttpMessageConverter`实现从文本 HTTP 请求/响应中编组/解组对象。它获取构造函数参数以指定编组器的类型（如`Jaxb，XStream`等）。

+   `MappingJacksonHttpMessageConverter`实现将文本转换为 JSON 数据格式，反之亦然。

在本示例中，使用`MarshallingHttpMessageConverter, MappingJacksonHttpMessageConverter`和`AtomFeedHttpMessageConverter`进行消息转换。由于此项目类似于本章的第一个示例，*使用 Spring MVC 中的 RESTful 功能设置 Spring RESTful Web 服务*，因此它被重用作项目的模板。本示例的区别在于控制器实现和应用程序上下文配置。

这个 Web 服务的客户端项目在这里实现，但将在本章的最后一个示例中详细介绍，*使用 Spring 模板类为 Spring RESTful Web 服务创建 WS 客户端*。

## 准备工作

在本示例中，项目名称为`LiveRestaurant_R-9.2（LiveRestaurant_R-9.2-Client`在本示例中包含在代码中以进行测试。但是，它将在最后一个示例中解释），并且具有以下 Maven 依赖项：

+   `com.springsource.javax.servlet-2.5.0.jar`

+   `spring-oxm-3.0.5.RELEASE.jar`

+   `spring-web-3.0.5.RELEASE.jar`

+   `spring-webmvc-3.0.5.RELEASE.jar`

+   `xstream-1.3.1.jar`

+   `commons-logging-1.1.1.jar`

+   `jackson-core-asl-1.7.5.jar`

+   `jackson-mapper-asl-1.7.5.jar`

+   `rome-1.0.jar`

`jackson-core`和`jackson-mapper`支持 JSON 格式，其他支持 ATOM 格式。

## 操作步骤...

1.  在`web.xml`文件中配置`DispatcherServlet`（URL：http://<host>:<port>/<appcontext>`/*将被转发到此 servlet）。

1.  定义控制器文件（`OrderController.java`）。

1.  定义领域 POJOs（`Order.java,OrderItem.java`）和服务（`OrderService, OrderServiceImpl`）

1.  配置服务器端应用程序上下文文件（`order-servlet.xml`）并注册转换器。

1.  将**方法**更改为**POST**，并添加**请求头:名称** - `accept`，**值** - `application/json`。输入 URL [`localhost:8080/LiveRestaurant/orderJson/1`](http://localhost:8080/LiveRestaurant/orderJson/1) 并点击**发送：**![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825OS_09_03.jpg)

1.  将**方法**更改为**GET**，并添加**请求头:名称** - `accept`，**值** - `application/atom+xml`。输入 URL [`localhost:8080/LiveRestaurant/orderItemsFeed`](http://localhost:8080/LiveRestaurant/orderItemsFeed) 并点击**发送：**

![操作步骤...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-websvc2-cb/img/5825OS_09_04.jpg)

## 工作原理...

这个示例与本章的第一个示例几乎相同，只是它使用了消息转换器和`@ResponseBody`来提供多个表示。

在第一个示例中，`MarshallingView`负责将响应转换为所选视图的 XML 类型（使用`XstreamMarshaller`）。然而，在这里，消息转换器负责将数据模型呈现为所选格式，`MarshallingHttpMessageConverter`负责将`List<OrderItem>`转换为`application/xml`格式（使用`XstreamMarshaller`），`MappingJacksonHttpMessageConverter`用于将订单转换为`application/json`格式。`AtomFeedHttpMessageConverter`用于将`Feed`（包装来自`List<OrderItem>`的 XML 内容，使用`XStreamMarshaller`生成的）转换为`application/atom+xml`格式：

```java
<context:component-scan base-package= "com.packtpub.liverestaurant.orderservice" />
<bean id="xStreamMarshaller" class= "org.springframework.oxm.xstream.XStreamMarshaller"/>
<bean class="org.springframework. web.servlet.mvc.annotation.DefaultAnnotationHandlerMapping" />
<bean class="org.springframework. web.servlet.mvc.annotation.AnnotationMethodHandlerAdapter">
<property name="messageConverters">
<list>
<ref bean="marshallingConverter" />
<ref bean="jsonConverter" />
<ref bean="atomConverter" />
</list>
</property>
</bean>
<bean id="marshallingConverter" class="org.springframework. http.converter.xml.MarshallingHttpMessageConverter">
<constructor-arg>
<bean class="org.springframework.oxm.xstream.XStreamMarshaller">
<property name="autodetectAnnotations" value="true"/>
</bean>
</constructor-arg>
<property name="supportedMediaTypes" value="application/xml"/>
</bean>
<bean id="jsonConverter" class="org.springframework. http.converter.json.MappingJacksonHttpMessageConverter">
<property name="supportedMediaTypes" value="application/json" />
</bean>
<bean id="atomConverter"class="org.springframework. http.converter.feed.AtomFeedHttpMessageConverter">
<property name="supportedMediaTypes" value="application/atom+xml" />
</bean>

```

在控制器中，以下代码导致控制器方法接受请求 URI 方法的`POST`格式 - `json：`

```java
@RequestMapping(method=RequestMethod.POST, value="/orderJson/{orderId}", headers="Accept=application/json")
public @ResponseBody Order placeOrderJson(@PathVariable String orderId) {
Order order=orderService.placeOrder(orderId);
return order;
}

```

并以 JSON 格式返回`Order`对象（使用`@ResponseBody`和`MappingJacksonHttpMessageConverter`在`order-context.xml`中配置）：

```java
{"message":"Order Pizza has been placed","ref":"Ref:1","orderItemId":"1"} 

```

以下代码导致控制器方法接受请求 URI 方法的`GET`格式 - `atom：`

```java
@RequestMapping(method=RequestMethod.GET, value="/orderItemsFeed", headers="Accept=application/atom+xml")
public @ResponseBody Feed loadOrderItemsAtom() {
Feed feed = null;
try {
feed= getOrderItemsFeed(orderService.listOrderItems());
} catch (Exception e) {
throw new RuntimeException(e);
}
return feed;
}

```

它还以`Atom`格式返回`List<OrderItem>`对象（使用`@ResponseBody`和`AtomFeedHttpMessageConverter`在`order-context.xml`中配置）：

```java
<?xml version="1.0" encoding="UTF-8"?>
<feed >
<title>OrderItems Atom Feed</title>
<entry>
<title>Burger</title>
<id>0</id>
<content type="xml">
&lt;com.packtpub.liverestaurant.domain.OrderItem&gt;&lt;name&gt; Burger&lt;/name&gt;&lt;id&gt;0&lt;/id&gt;&lt;/com.packtpub. liverestaurant.domain.OrderItem&gt;
</content>
</entry>
<entry>
<title>Pizza</title>
<id>1</id>
<content type="xml">&lt;com.packtpub.liverestaurant.domain. OrderItem&gt;&lt;name&gt;Pizza&lt;/name&gt;&lt;id&gt;1&lt; /id&gt;&lt;/com.packtpub.liverestaurant.domain.OrderItem&gt;
</content>
</entry>
...

```

## 另请参阅...

在本章中：

*使用 Spring MVC 中的 RESTful 功能设置 Spring RESTful Web 服务*

# 使用 Spring 模板类为 Spring RESTful Web 服务创建 WS 客户端

Spring 提供了各种模板类，使用不同的技术简化了许多复杂性。例如，`WebServiceTemplate`用于调用基于 SOAP 的 Web 服务，`JmsTemplate`用于发送/接收 JMS 消息。Spring 还有`RestTemplate`来简化与 RESTful Web 服务的交互。

使用`RestTemplate:`

+   创建一个`RestTemplate`的实例（可以使用`@Autowired`特性来完成）

+   配置一对多的消息转换器（如前面的示例中所述）

+   调用`RestTemplate`的方法来调用 RESTful Web 服务并获取响应

在这个示例中，我们将学习如何使用`RestTemplate`消耗 RESTful Web 服务。这个示例使用了本章的第三个示例，*使用 HTTP 消息转换设置 Spring RESTful Web 服务*，作为 RESTful Web 服务。

## 准备工作

在这个示例中，项目的名称是`LiveRestaurant_R-9.2-Client`（`LiveRestaurant_R-9.2`包含在这个示例中，用于设置 RESTful 服务器，如前面的示例*使用 HTTP 消息转换设置 Spring RESTful Web 服务*中所解释的），具有以下 Maven 依赖项：

+   `spring-oxm-3.0.5.RELEASE.jar`

+   `spring-web-3.0.5.RELEASE.jar`

+   `xstream-1.3.1.jar`

+   `commons-logging-1.1.1.jar`

+   `jackson-core-asl-1.7.5.jar`

+   `jackson-mapper-asl-1.7.5.jar`

+   `rome-1.0.jar`

+   `junit-4.6.jar`

+   `spring-test-3.0.5.RELEASE.jar`

## 如何做...

1.  定义领域 POJOs（`Order.java`、`OrderItem.java`）和服务（`OrderService`、`OrderServiceImpl`）。

1.  配置客户端应用程序上下文文件（`order-servlet.xml`）并注册转换器。

1.  创建一个辅助类（`OrderClient`），用`RestTemplate`来调用 RESTful Web 服务。

1.  在`Liverestaurant_R-9.2`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-9.2-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端输出：

```java
....
.. Created GET request for "http://localhost:8080/LiveRestaurant/orderItems"
.. Setting request Accept header to [application/xml, text/xml, application/*+xml, application/json]
.. GET request for "http://localhost:8080/LiveRestaurant/orderItems" resulted in 200 (OK)
.. Reading [java.util.List] as "application/xml" using ....
.. Created POST request for "http://localhost:8080/LiveRestaurant/orderJson/1"
.. Setting request Accept header to [application/xml, text/xml, application/*+xml, application/json]
.. POST request for "http://localhost:8080/LiveRestaurant/orderJson/1" resulted in 200 (OK)
.. Reading [com.packtpub.liverestaurant.domain.Order] as "application/xml" using ...
...Created GET request for "http://localhost:8080/LiveRestaurant/orderItemsFeed"
.. Setting request Accept header to [application/xml, text/xml, application/*+xml, application/json, application/atom+xml]
.. GET request for "http://localhost:8080/LiveRestaurant/orderItemsFeed" resulted in 200 (OK)
.. Reading [com.sun.syndication.feed.atom.Feed] as "application/xml" using ... 

```

## 工作原理...

由`OrderServiceClientTest`加载的应用程序上下文加载、实例化和注入`RestTemplate`到`OrderClient`中。这个类使用`RestTemplate`调用控制器的方法，并将值返回给测试套件类（`OrderServiceClientTest`）。

在套件类测试方法中，响应将与期望的值进行比较。

`applicationContext.xml`定义了`restTemplate` bean 并设置了一系列消息转换器：

```java
......
<bean id="restTemplate" class="org.springframework.web.client.RestTemplate">
<property name="messageConverters">
<list>
<ref bean="xmlMarshallingHttpMessageConverter" />
<ref bean="jsonConverter" />
<ref bean="atomConverter" />
</list>
</property>
</bean>
<bean id="xmlMarshallingHttpMessageConverter" class="org.springframework. http.converter.xml.MarshallingHttpMessageConverter">
<constructor-arg>
<ref bean="xStreamMarshaller" />
</constructor-arg>
</bean>
<bean id="xStreamMarshaller" class="org.springframework.oxm.xstream.XStreamMarshaller">
<property name="annotatedClasses">
<list>
<value>com.packtpub.liverestaurant.domain.Order</value>
<value>com.packtpub.liverestaurant.domain.OrderItem</value>
</list>
</property>
</bean>
<bean id="atomConverter" class="org.springframework. http.converter.feed.AtomFeedHttpMessageConverter">
<property name="supportedMediaTypes" value="application/atom+xml" />
</bean>
<bean id="jsonConverter" class="org.springframework. http.converter.json.MappingJacksonHttpMessageConverter">
<property name="supportedMediaTypes" value="application/json" />
</bean>

```

设置在`messageConverters`内部的转换器负责将不同格式（XML、JSON、ATOM）的请求/响应转换回`object`类型。`XstreamMarshaller`使用这些类中的注释标签获取已识别的 POJOs（Order、OrderItem）的列表。

`OrderClient.java`是一个辅助类，用于调用 RESTful Web 服务，使用`RestTemplate:`

```java
protected RestTemplate restTemplate;
private final static String serviceUrl = "http://localhost:8080/LiveRestaurant/";
@SuppressWarnings("unchecked")
public List<OrderItem> loadOrderItemsXML() {
HttpEntity<String> entity = getHttpEntity(MediaType.APPLICATION_XML);
ResponseEntity<List> response = restTemplate.exchange(serviceUrl + "orderItems", HttpMethod.GET, entity, List.class);
return response.getBody();
}
.....
...
public String loadOrderItemsAtom() {
HttpEntity<String> httpEntity = getHttpEntity(MediaType.APPLICATION_ATOM_XML);
String outputStr = null;
ResponseEntity<Feed> responseEntity = restTemplate.exchange(serviceUrl + "orderItemsFeed", HttpMethod.GET, httpEntity, Feed.class);
WireFeed wireFeed = responseEntity.getBody();
WireFeedOutput wireFeedOutput = new WireFeedOutput();
try {
outputStr = wireFeedOutput.outputString(wireFeed);
} catch (Exception e) {
throw new RuntimeException(e);
}
return outputStr;
}
private HttpEntity<String> getHttpEntity(MediaType mediaType) {
HttpHeaders httpHeaders = new HttpHeaders();
httpHeaders.setContentType(mediaType);
HttpEntity<String> httpEntity = new HttpEntity<String>(httpHeaders);
return httpEntity;
}

```

## 还有更多

这个示例只使用了`RestTemplate`的两种方法（exchange 和`postForEntity`）。然而，`RestTemplate`支持多种调用方法：

+   `exchange:`它调用特定的 HTTP（GET、`POST、PUT`和`DELETE`）方法并转换 HTTP 响应

+   `getForObject:`它调用 HTTP 的`GET`方法并将 HTTP 响应转换为对象

+   `postForObject:`它调用 HTTP 的`POST`方法并将 HTTP 响应转换为对象

## 另请参阅...

在本章中：

+   *使用 Spring MVC 中的 RESTful 功能设置 Spring RESTful Web 服务*

+   *使用 HTTP 消息转换设置 Spring RESTful Web 服务*

书籍《RESTful Java Web Services》，网址为[`www.packtpub.com/restful-java-web-services/book`](http://www.packtpub.com/restful-java-web-services/book)。


# 第十章：Spring 远程

在本章中，我们将涵盖：

+   使用 RMI 设置 Web 服务

+   使用 Hessian/Burlap 设置基于 servlet 的 Web 服务，暴露业务 bean

+   使用 JAX-WS 设置 Web 服务

+   使用 Apache CXF 暴露基于 servlet 的 Web 服务

+   使用 JMS 作为底层通信协议暴露 Web 服务

# 介绍

Spring-WS 项目是一种基于契约的方法来构建 Web 服务。这种方法已经在前八章中详细介绍过。然而，有时的要求是将现有的业务 Spring bean 暴露为 Web 服务，这被称为**契约后**方法，用于设置 Web 服务。

Spring 的远程支持与多种远程技术的通信。Spring 远程允许在服务器端暴露现有的 Spring bean 作为 Web 服务。在客户端，Spring 远程允许客户端应用程序通过本地接口调用远程 Spring bean（该 bean 作为 Web 服务暴露）。在本章中，详细介绍了 Spring 的以下远程技术的功能：

+   RMI：Spring 的`RmiServiceExporter`允许您在服务器端使用远程方法调用（RMI）暴露本地业务服务，而 Spring 的`RmiProxyFactoryBean`是客户端代理 bean，用于调用 Web 服务。

+   Hessian：Spring 的`HessianServiceExporter`允许您在服务器端使用 Caucho 技术引入的轻量级基于 HTTP 的协议暴露本地业务服务，而`HessianProxyFactoryBean`是调用 Web 服务的客户端代理 bean。

+   Burlap：这是 Caucho Technology 的 Hessian 的 XML 替代方案。Spring 提供了支持类，使用 Spring 的两个 bean，即`BurlapProxyFactoryBean`和`BurlapServiceExporter`。

+   JAX-RPC：Spring 支持设置 Web 服务，基于 J2EE 1.4 的 JAX-RPC Web 服务 API

+   JAX-WS：Spring 支持使用 Java EE 5+ JAX-WS API 设置 Web 服务，该 API 允许基于消息和远程过程调用的 Web 服务开发。

+   JMS：Spring 使用 JMS 作为底层通信协议来暴露/消费 Web 服务，使用`JmsInvokerServiceExporter`和`JmsInvokerProxyFactoryBean`类。

由于 JAX-WS 是 JAX-RPC 的后继者，因此本章不包括 JAX-RPC。相反，本章将详细介绍 Apache CXF，因为它可以使用 JAX-WS 来设置 Web 服务，即使它不是 Spring 的远程的一部分。

为简化起见，在本章中，将暴露以下本地业务服务作为 Web 服务（领域模型在第一章的*介绍*部分中已经描述，*构建 SOAP Web 服务*）。

```java
public interface OrderService {
placeOrderResponse placeOrder(PlaceOrderRequest placeOrderRequest);
}

```

这是接口实现：

```java
public class OrderServiceImpl implements OrderService{
public PlaceOrderResponse placeOrder(PlaceOrderRequest placeOrderRequest) {
PlaceOrderResponse response=new PlaceOrderResponse();
response.setRefNumber(getRandomOrderRefNo());
return response;
}
...

```

# 使用 RMI 设置 Web 服务

RMI 是 J2SE 的一部分，允许在不同的 Java 虚拟机（JVM）上调用方法。RMI 的目标是在单独的 JVM 中公开对象，就像它们是本地对象一样。通过 RMI 调用远程对象的客户端不知道对象是远程还是本地，并且在远程对象上调用方法与在本地对象上调用方法具有相同的语法。

Spring 的远程提供了基于 RMI 技术的暴露/访问 Web 服务的功能。在服务器端，Spring 的`RmiServiceExporter` bean 将服务器端 Spring 业务 bean 暴露为 Web 服务。在客户端，Spring 的`RmiProxyFactoryBean`将 Web 服务的方法呈现为本地接口。

在这个示例中，我们将学习使用 RMI 设置 Web 服务，并了解通过 RMI 呼叫 Web 服务的呈现方式。

## 准备工作

在这个示例中，我们有以下两个项目：

1.  `LiveRestaurant_R-10.1`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-context-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

1.  `LiveRestaurant_R-10.1-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-context-3.0.5.RELEASE.jar`

+   `spring-ws-test-2.0.0.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

+   `xmlunit-1.1.jar`

## 如何做...

1.  在服务器端应用程序上下文（`applicationContext.xml`）中注册服务器端服务实现在 Spring 的`RmiServiceExporter`中，并设置端口和服务名称。

1.  在客户端应用程序上下文（`applicationContext.xml`）中，使用 Spring 的`RmiProxyFactoryBean`注册本地接口（与服务器端相同）并设置服务的 URL。

1.  添加一个 Java 类来加载服务器端应用程序上下文文件（在类的`main`方法中）以设置服务器。

1.  在客户端添加一个 JUnit 测试用例类，通过本地接口调用 Web 服务。

1.  在`Liverestaurant_R-10.1`上运行以下命令：

```java
mvn clean package exec:java 

```

1.  在`Liverestaurant_R-10.1-Client`上运行以下命令：

```java
mvn clean package 

```

+   以下是客户端输出：

```java
......
... - Located RMI stub with URL [rmi://localhost:1199/OrderService]
....- RMI stub [rmi://localhost:1199/OrderService] is an RMI invoker
......
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.78 sec
...
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
......
[INFO] BUILD SUCCESS 

```

## 工作原理...

`OrderServiceSetUp`是加载服务器端应用程序上下文并设置服务器以将服务器端业务服务暴露为 Web 服务的类。`OrderServiceClientTest`是客户端测试类，加载客户端应用程序上下文并通过代表远程业务服务的客户端本地接口调用 Web 服务方法。

`OrderServiceImpl`是要通过 Web 服务公开的服务。在服务器端的应用程序上下文中，在`org.springframework.remoting.rmi.RmiServiceExporter` Bean 中，`OrderService`是将在 RMI 注册表中注册的服务的名称。服务属性用于传递`RmiServiceExporter`和 bean 实例。`serviceInterface`是表示本地业务服务的接口。只有在此接口中定义的方法才能远程调用：

```java
<bean id="orderService" class="com.packtpub.liverestaurant.service.OrderServiceImpl" />
<bean class="org.springframework.remoting.rmi.RmiServiceExporter">
<property name="serviceName" value="OrderService" />
<property name="service" ref="orderService" />
<property name="serviceInterface" value="com.packtpub.liverestaurant.service.OrderService" />
<property name="registryPort" value="1199" />
</bean>

```

在客户端配置文件中，`serviceUrl`是 Web 服务的 URL 地址，`serviceInterface`是本地接口，使客户端可以远程调用服务器端的方法：

```java
<bean id="orderService" class="org.springframework.remoting.rmi.RmiProxyFactoryBean">
<property name="serviceUrl" value=" rmi://localhost:1199/OrderService" />
<property name="serviceInterface" value="com.packtpub.liverestaurant.service.OrderService" />
</bean>

```

`OrderServiceClientTest`是加载应用程序上下文并通过本地接口调用远程方法的 JUnit 测试用例类：

```java
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/applicationContext.xml")
public class OrderServiceClientTest {
@Autowired
OrderService orderService;
@Autowired
private GenericApplicationContext applicationContext;
@Before
@After
public void setUpAfter() {
applicationContext.close();
}
@Test
public final void testPlaceOrder() throws Exception {
PlaceOrderRequest orderRequest = new PlaceOrderRequest();
orderRequest.setOrder(getDummyOrder());
PlaceOrderResponse orderResponse = orderService.placeOrder(orderRequest);
Assert.assertTrue(orderResponse.getRefNumber().indexOf("1234")>0);
}
private Order getDummyOrder() {
Order order=new Order();
order.setRefNumber("123");
List<FoodItem> items=new ArrayList<FoodItem>();
FoodItem item1=new FoodItem();
item1.setType(FoodItemType.BEVERAGES);
item1.setName("beverage");
item1.setQuantity(1.0);
......
}
........
}

```

# 使用 Hessian/Burlap 设置基于 servlet 的 Web 服务，暴露业务 bean

**Hessian 和 Burlap**，由 Caucho 开发（[`hessian.caucho.com`](http://hessian.caucho.com)），是轻量级基于 HTTP 的远程技术。尽管它们都使用 HTTP 协议进行通信，但 Hessian 使用二进制消息进行通信，而 Burlap 使用 XML 消息进行通信。

Spring 的远程提供了基于这些技术的 Web 服务的暴露/访问功能。在服务器端，Spring 的`ServiceExporter` bean 将服务器端 Spring 业务 bean（`OrderServiceImpl`）暴露为 Web 服务：

```java
<bean id="orderService" class="com.packtpub.liverestaurant.service.OrderServiceImpl" />
<bean name="/OrderService" class="....ServiceExporter">
<property name="service" ref="orderService" />
</bean>

```

在客户端，Spring 的`ProxyFactory` bean 通过本地客户端接口（`OrderService`）暴露远程接口：

```java
<bean id="orderService" class="....ProxyFactoryBean">
<property name="serviceUrl" value="http://localhost:8080/LiveRestaurant/services/OrderService" />
<property name="serviceInterface" value="com.packtpub.liverestaurant.service.OrderService" />

```

## 准备工作

在这个示例中，我们有以下两个项目：

1.  `LiveRestaurant_R-10.2`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-webmvc-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `hessian-3.1.5.jar`

1.  `LiveRestaurant_R-10.2-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-web-3.0.5.RELEASE.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

+   `hessian-3.1.5.jar`

## 如何做...

按照以下步骤设置基于 servlet 的 Web 服务，使用 Hessian 服务：

1.  在`web.xml`文件中配置`DispatcherServlet`（URL：`http://<host>:<port>/<appcontext>/services`将被转发到此 servlet）。

1.  在服务器端应用程序上下文（`applicationContext.xml`）中注册服务器端服务接口，并设置服务名称和服务接口。

1.  在客户端应用程序上下文（`applicationContext.xml`）中，使用 Spring 的`HessianProxyFactoryBean`注册本地接口（与服务器端相同），并设置服务的 URL。

1.  在客户端添加一个 JUnit 测试用例类，使用本地接口调用 Web 服务

1.  在`Liverestaurant_R-10.2`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-10.2-Client`上运行以下命令：

```java
mvn clean package 

```

+   在客户端输出中，您将能够看到运行测试用例的成功消息，如下所示：

```java
text.annotation.internalCommonAnnotationProcessor]; root of factory hierarchy
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.71 sec
Results :
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
[INFO] 

```

按照以下步骤使用 Burlap 服务设置基于 servlet 的 Web 服务：

1.  将服务器端服务接口修改为 Spring 的`BurlapServiceExporter`，在服务器端应用程序上下文（`applicationContext.xml`）中。

1.  将客户端应用程序上下文（`applicationContext.xml`）修改为 Spring 的`BurlapProxyFactoryBean`。

1.  在`Liverestaurant_R-10.2`上运行以下命令：

```java
mvn clean package tomcat:run 

```

1.  在`Liverestaurant_R-10.2-Client`上运行以下命令：

```java
mvn clean package 

```

+   在客户端输出中，您将能够看到运行测试用例的成功消息，如下所示：

```java
text.annotation.internalCommonAnnotationProcessor]; root of factory hierarchy
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.849 sec
Results :
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
[INFO]
[INFO] --- maven-jar-plugin:2.3.1:jar ..
[INFO] Building jar: ...
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS 

```

## 它是如何工作的...

`Liverestaurant_R-10.2`项目是一个服务器端 Web 服务，使用 Spring 远程的 burlap/hessian 出口商设置基于 servlet 的 Web 服务。

`Liverestaurant_R-10.2-Client`项目是一个客户端测试项目，调用了 Spring 远程的 burlap/hessian Web 服务，使用了 burlap/hessian 客户端代理。

在服务器端，`DiapatcherServlet`将使用 URL 模式将所有请求转发到`BurlapServiceExporter/HessianServiceExporter`（http://<hostaddress>/<context>/<services>）：

```java
<servlet>
<servlet-name>order</servlet-name>
<servlet-class>
org.springframework.web.servlet.DispatcherServlet
</servlet-class>
<load-on-startup>1</load-on-startup>
</servlet>
<servlet-mapping>
<servlet-name>order</servlet-name>
<url-pattern>/services/*</url-pattern>
</servlet-mapping>

```

这些出口商将内部本地服务实现（`OrderServiceImpl`）公开为 Web 服务：

```java
<bean name="/OrderService" class="org.springframework.remoting.caucho.BurlapServiceExporter">
<property name="service" ref="orderService" />
<property name="serviceInterface" value="com.packtpub.liverestaurant.service.OrderService" />
</bean>

```

在客户端，`BurlapProxyFactoryBean/HessianProxyFactoryBean`负责使用本地客户端服务接口（`OrderService`）向客户端公开远程方法：

```java
<bean id="orderService" class="org.springframework.remoting.caucho.BurlapProxyFactoryBean">
<property name="serviceUrl" value="http://localhost:8080/LiveRestaurant/services/OrderService" />
<property name="serviceInterface" value="com.packtpub.liverestaurant.service.OrderService" />
</bean>

```

`OrderServiceClientTest`的实现与食谱*使用 RMI 设置 Web 服务*中描述的相同。

## 另请参阅...

在本章中：

*使用 RMI 设置 Web 服务*

# 使用 JAX-WS 设置 Web 服务

**JAX-RPC**是 Java EE 1.4 中附带的一个标准，用于开发 Web 服务，在近年来变得越来越不受欢迎。JAX-WS 2.0 是在 Java EE 5 中引入的，比 JAX-RPC 更灵活，基于注解的绑定概念。以下是 JAX-WS 相对于 JAX-RPC 的一些优势：

+   JAX-WS 支持面向消息和**远程过程调用（RPC）**Web 服务，而 JAX-RPC 仅支持 RPC

+   JAX-WS 支持 SOAP 1.2 和 SOAP 1.1，但 JAX-RPC 支持 SOAP 1.1

+   JAX-WS 依赖于 Java 5.0 的丰富功能，而 JAX-RPC 与 Java 1.4 一起工作

+   JAX-WS 使用非常强大的 XML 对象映射框架（使用 JAXB），而 JAX-RPC 使用自己的框架，对于复杂的数据模型显得薄弱

Spring 远程提供了设置使用 Java 1.5+功能的 JAX-WS Web 服务的功能。例如，在这里，注解`@WebService`会导致 Spring 检测并将此服务公开为 Web 服务，`@WebMethod`会导致以下方法：`public OrderResponse placeOrder(..)`，被调用为 Web 服务方法（placeOrder）：

```java
@Service("OrderServiceImpl")
@WebService(serviceName = "OrderService",endpointInterface = "com.packtpub.liverestaurant.service.OrderService")
public class OrderServiceImpl implements OrderService {
@WebMethod(operationName = "placeOrder")
public PlaceOrderResponse placeOrder(PlaceOrderRequest placeOrderRequest) {

```

在这个食谱中，使用 JDK 内置的 HTTP 服务器来设置 Web 服务（自从 Sun 的`JDK 1.6.0_04`以来，JAX-WS 可以与 JDK 内置的 HTTP 服务器集成）。

## 准备工作

安装 Java 和 Maven（SE 运行时环境（构建`jdk1.6.0_29`））。

在这个食谱中，我们有以下两个项目：

1.  `LiveRestaurant_R-10.3`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `spring-web-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

1.  `LiveRestaurant_R-10.3-Client`（用于客户端），具有以下 Maven 依赖项：

+   `spring-web-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

1.  为业务服务类及其方法添加注释。

1.  在应用程序上下文文件（`applicationContext.xml`）中注册服务，然后配置`SimpleJaxWsServiceExporter` bean，并创建一个类来加载服务器端应用程序上下文（这将设置服务器）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册本地接口（与服务器端接口相同的方式），并设置服务的 URL。

1.  在客户端添加一个 JUnit 测试用例类，该类使用本地接口调用 Web 服务。

1.  在`Liverestaurant_R-10.3`上运行以下命令，并浏览以查看位于`http://localhost:9999/OrderService?wsdl`的 WSDL 文件：

```java
mvn clean package exec:java 

```

1.  在`Liverestaurant_R-10.3-Client`上运行以下命令：

```java
mvn clean package 

```

+   在客户端输出中，您将能够看到运行测试用例的成功消息，如下所示：

```java
.....
Dynamically creating request wrapper Class com.packtpub.liverestaurant.service.jaxws.PlaceOrder
Nov 14, 2011 11:34:13 PM com.sun.xml.internal.ws.model.RuntimeModeler getResponseWrapperClass
INFO: Dynamically creating response wrapper bean Class com.packtpub.liverestaurant.service.jaxws.PlaceOrderResponse
......
Results :
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0 

```

## 它是如何工作的...

`Liverestaurant_R-10.3`项目是一个服务器端 Web 服务（通过 Spring 远程的出口器 bean），它使用 DK 内置的 HTTP 服务器设置了一个 JAX-WS。

`Liverestaurant_R-10.3-Client`项目是一个客户端测试项目，它使用 Spring 远程的客户端代理调用 JAX-WS Web 服务。

在服务器端，`applicationContext.xml`扫描并检测`OrderServiceImpl`中的注释标签。然后，`SimpleJaxWsServiceExporter`将此业务服务公开为 Web 服务：

```java
<context:annotation-config/>
<context:component-scan base-package= "com.packtpub.liverestaurant.service"/>
<bean class= "org.springframework.remoting.jaxws.SimpleJaxWsServiceExporter">
<property name="baseAddress" value="http://localhost:9999/" />
</bean>

```

在服务类中，注释`@WebService`和`@WebMethod`导致 Spring 检测（通过扫描），并通过`SimpleJaxWsServiceExporter`将此服务类公开为 Web 服务及其方法（`placeOrder`）公开为 Web 服务方法：

```java
@Service("orderServiceImpl")
@WebService(serviceName = "OrderService")
public class OrderServiceImpl implements OrderService {
@WebMethod(operationName = "placeOrder")
public PlaceOrderResponse placeOrder(PlaceOrderRequest placeOrderRequest) {
PlaceOrderResponse response=new PlaceOrderResponse();
response.setRefNumber(getRandomOrderRefNo());
return response;
}
.......
}

```

在客户端，`JaxWsPortProxyFactoryBean`负责将远程方法暴露给客户端，使用本地客户端接口。`WsdlDocumentUrl`是 Web 服务 WSDL 地址，`portName`是 WSDL 中的`portName`值，`namespaceUri`是 WSDL 中的`targetNameSpace`，`serviceInterface`是本地客户端服务接口：

```java
<bean id="orderService" class= "org.springframework.remoting.jaxws.JaxWsPortProxyFactoryBean">
<property name="serviceInterface" value= "com.packtpub.liverestaurant.service.OrderService"/>
<property name="serviceInterface" value= "com.packtpub.liverestaurant.service.OrderService"/>
<property name="wsdlDocumentUrl" value= "http://localhost:9999/OrderService?wsdl"/>
<property name="namespaceUri" value= "http://service.liverestaurant.packtpub.com/"/>
<property name="serviceName" value="OrderService"/>
<property name="portName" value="OrderServiceImplPort"/>
</bean>

```

`OrderServiceClientTest`的实现与名为*使用 RMI 设置 Web 服务*的配方中描述的相同。

## 另请参阅...

在本章中：

*使用 RMI 设置 Web 服务*

在本书中：

第二章,*构建 SOAP Web 服务的客户端*

*在 HTTP 传输上创建 Web 服务客户端*

# 使用 Apache CXF 暴露基于 servlet 的 Web 服务

**Apache CXF**起源于以下项目的组合：**Celtix**（IONA Technologies）和**XFire**（Codehaus），它们被整合到**Apache 软件基金会**中。CXF 的名称意味着它起源于**Celtix**和**XFire**项目名称。

Apache CXF 提供了构建和部署 Web 服务的功能。Apache CXF 推荐的 Web 服务配置方法（前端或 API）是 JAX-WS 2.x。Apache CXF 并不是 Spring 的远程的一部分，但是，由于它可以使用 JAX-WS 作为其前端，因此将在本配方中进行解释。

## 准备工作

安装 Java 和 Maven（SE Runtime Environment（构建`jdk1.6.0_29`））。

在这个配方中，我们有以下两个项目：

1.  `LiveRestaurant_R-10.4`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `cxf-rt-frontend-jaxws-2.2.6.jar`

+   `cxf-rt-transports-http-2.2.6.jar`

+   `spring-web-3.0.5.RELEASE.jar`

+   `commons-logging-1.1.1.jar`

1.  `LiveRestaurant_R-10.4-Client`（用于客户端），具有以下 Maven 依赖项：

+   `cxf-rt-frontend-jaxws-2.2.6.jar`

+   `cxf-rt-transports-http-2.2.6.jar`

+   `spring-web-3.0.5.RELEASE.jar`

+   `log4j-1.2.9.jar`

+   `junit-4.7.jar`

## 如何做...

1.  在业务服务类和方法上进行注释（与您为 JAX-WS 所做的方式相同）。

1.  在应用程序上下文文件（`applicationContext.xml`）中注册服务，并在`web.xml`文件中配置`CXFServlet`（URL：`http://<host>:<port>/`将被转发到此 servlet）。

1.  在客户端应用程序上下文（`applicationContext.xml`）中注册本地接口（与您为服务器端执行的方式相同），并设置服务的 URL。

1.  在客户端添加一个 JUnit 测试用例类，使用本地接口调用 Web 服务。

## 工作原理...

`Liverestaurant_R-10.4`项目是一个服务器端 Web 服务，它使用 JAX-WS API 设置了一个 CXF。

`Liverestaurant_R-10.4-Client`项目是一个客户端测试项目，它使用 Spring 的远程调用从 JAX-WS Web 服务调用客户端代理。

在服务器端，`applicationContext.xml`中的配置检测`OrderServiceImpl`中的注释标签。然后`jaxws:endpoint`将此业务服务公开为 Web 服务：

```java
<!-- Service Implementation -->
<bean id="orderServiceImpl" class= "com.packtpub.liverestaurant.service.OrderServiceImpl" />
<!-- JAX-WS Endpoint -->
<jaxws:endpoint id="orderService" implementor="#orderServiceImpl" address="/OrderService" />

```

`OrderServiceImpl`的解释与在*使用 JAX-WS 设置 Web 服务*中描述的相同。

在客户端，`JaxWsProxyFactoryBean`负责使用本地客户端接口向客户端公开远程方法。`address`是 Web 服务的地址，`serviceInterface`是本地客户端服务接口：

```java
<bean id="client" class= "com.packtpub.liverestaurant.service.OrderService" factory-bean="clientFactory" factory-method="create"/>
<bean id="clientFactory" class="org.apache.cxf.jaxws.JaxWsProxyFactoryBean">
<property name="serviceClass" value="com.packtpub.liverestaurant.service.OrderService"/>
<property name="address" value="http://localhost:8080/LiveRestaurant/OrderService"/>
</bean>

```

`OrderServiceClientTest`的实现与在*使用 RMI 设置 Web 服务*中描述的相同。

## 另请参阅...

*在本章中：*

*使用 RMI 设置 Web 服务*

# 使用 JMS 作为底层通信协议公开 Web 服务

**Java 消息服务（JMS）**由 Java 2 和 J2EE 引入，由 Sun Microsystems 于 1999 年成立。使用 JMS 的系统能够以同步或异步模式进行通信，并且基于点对点和发布-订阅模型。

Spring 远程提供了使用 JMS 作为底层通信协议公开 Web 服务的功能。Spring 的 JMS 远程在单线程和非事务会话中在同一线程上发送和接收消息。

但是，对于 JMS 上的 Web 服务的多线程和事务支持，您可以使用基于 Spring 的 JMS 协议的 Spring-WS，该协议基于 Spring 的基于 JMS 的消息传递。

在这个示例中，使用`apache-activemq-5.4.2`来设置一个 JMS 服务器，并且默认对象，由这个 JMS 服务器创建的（队列，代理），被项目使用。

## 准备就绪

安装 Java 和 Maven（SE Runtime Environment（构建`jdk1.6.0_29`））。

安装`apache-activemq-5.4.2`。

在这个示例中，我们有以下两个项目：

1.  `LiveRestaurant_R-10.5`（用于服务器端 Web 服务），具有以下 Maven 依赖项：

+   `activemq-all-5.2.0.jar`

+   `spring-jms-3.0.5.RELEASE.jar`

1.  `LiveRestaurant_R-10.5-Client`（用于客户端），具有以下 Maven 依赖项：

+   `activemq-all-5.2.0.jar`

+   `spring-jms-3.0.5.RELEASE.jar`

+   `junit-4.7.jar`

+   `spring-test-3.0.5.RELEASE.jar`

+   `xmlunit-1.1.jar`

## 如何做...

在服务器端应用程序上下文文件中注册业务服务到`JmsInvokerServiceExporter` bean，并使用`activemq`默认对象（代理，`destination`）注册`SimpleMessageListenerContainer`。

1.  创建一个 Java 类来加载应用程序上下文并设置服务器。

1.  在客户端应用程序上下文文件中使用`activemq`默认对象（代理，目的地）注册`JmsInvokerProxyFactoryBean`。

1.  在客户端添加一个 JUnit 测试用例类，调用本地接口使用 Web 服务。

1.  运行`apache-activemq-5.4.2`（设置 JMS 服务器）。

1.  在`Liverestaurant_R-10.5`上运行以下命令并浏览以查看位于`http://localhost:9999/OrderService?wsdl`的 WSDL 文件：

```java
mvn clean package exec:java 

```

1.  在`Liverestaurant_R-10.5-Client`上运行以下命令：

```java
mvn clean package 

```

+   在客户端输出中，您将能够看到运行测试用例的成功消息。

```java
T E S T S
-------------------------------------------------------
Running com.packtpub.liverestaurant.service.client.OrderServiceClientTest
log4j:WARN No appenders could be found for logger (org.springframework.test.context.junit4.SpringJUnit4ClassRunner).
log4j:WARN Please initialize the log4j system properly.
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 1.138 sec
Results :
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0 

```

## 工作原理...

`Liverestaurant_R-10.5`项目是一个服务器端 Web 服务，它通过监听 JMS 队列设置了一个 Web 服务。

`Liverestaurant_R-10.5-Client`项目是一个客户端测试项目，它向 JMS 队列发送 JMS 消息。

在服务器端，`OrderServiceSetUp` 类加载 `applicationContext.xml` 并在容器中创建一个 `messageListener`（使用 `SimpleMessageListenerContainer`），等待在特定目的地（`requestQueue`）监听消息。一旦消息到达，它通过 Spring 的远程调用类（`JmsInvokerServiceExporter`）调用业务类（`OrderServiceImpl`）的方法。

```java
<bean id="orderService" class="com.packtpub.liverestaurant.service.OrderServiceImpl"/>
<bean id="listener" class="org.springframework.jms.remoting.JmsInvokerServiceExporter">
<property name="service" ref="orderService"/>
<property name="serviceInterface" value="com.packtpub.liverestaurant.service.OrderService"/>
</bean>
<bean id="container" class= "org.springframework.jms.listener.SimpleMessageListenerContainer">
<property name="connectionFactory" ref="connectionFactory"/>
<property name="messageListener" ref="listener"/>
<property name="destination" ref="requestQueue"/>
</bean>

```

在客户端，`JmsInvokerProxyFactory` 负责使用本地客户端接口（OrderService）向客户端公开远程方法。当客户端调用 `OrderService` 方法时，`JmsInvokerProxyFactory` 会向队列（requestQueue）发送一个 JMS 消息，这是服务器正在监听的队列：

```java
<bean id="orderService" class= "org.springframework.jms.remoting.JmsInvokerProxyFactoryBean">
<property name="connectionFactory" ref="connectionFactory"/>
<property name="queue" ref="requestQueue"/>
<property name="serviceInterface" value="com.packtpub.liverestaurant.service.OrderService"/>
</bean>

```
