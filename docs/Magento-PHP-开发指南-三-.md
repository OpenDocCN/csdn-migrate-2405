# Magento PHP 开发指南（三）

> 原文：[`zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2`](https://zh.annas-archive.org/md5/f2e271327b273df27fc8bf4ef750d5c2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Magento API

在上一章中，我们扩展了 Magento 后端，并学习了如何使用一些后端组件，以便商店所有者可以管理和操作每个客户的礼品注册数据。

在本章中，我们将涵盖以下主题：

+   Magento 核心 API

+   可用的多个 API 协议（REST、SOAP、XML-RPC）

+   如何使用核心 API

+   如何扩展 API 以实现新功能

+   如何将 API 的部分限制为特定的 Web 用户角色

虽然后端提供了日常操作的界面，但有时我们需要访问和/或传输来自第三方系统的数据。Magento 已经为大多数核心功能提供了 API 功能，但对于我们的自定义礼品注册扩展，我们需要扩展`Mage_Api`功能。

# 核心 API

在谈论 API 时，我经常听到开发人员谈论 Magento SOAP API 或 Magento XML-RPC API 或 RESTful API。但重要的事实是，这些并不是针对每个协议的单独 API；相反，Magento 有一个单一的核心 API。

正如您可能注意到的，Magento 主要建立在抽象和配置（主要是 XML）周围，Magento API 也不例外。我们有一个单一的核心 API 和每种不同协议类型的适配器。这是非常灵活的，如果我们愿意，我们可以为另一个协议实现自己的适配器。

核心 Magento API 使我们能够管理产品、类别、属性、订单和发票。这是通过暴露三个核心模块来实现的：

+   `Mage_Catalog`

+   `Mage_Sales`

+   `Mage_Customer`

API 支持三种不同类型：SOAP、XML-RPC 和 REST。现在，如果您在 Magento 之外进行了 Web 开发并使用了其他 API，那么很可能那些 API 是 RESTful API。

在我们深入研究 Magento API 架构的具体细节之前，重要的是我们了解每种支持的 API 类型之间的区别。

## XML-RPC

XML-RPC 是 Magento 支持的第一个协议，也是最古老的协议。该协议有一个单一的端点，所有功能都在此端点上调用和访问。

### 注意

**XML-RPC**是一种使用 XML 编码其调用和 HTTP 作为传输机制的**远程过程调用**（**RPC**）协议。

由于只有一个单一的端点，XML-RPC 易于使用和维护；它的目的是成为发送和接收数据的简单有效的协议。实现使用简单的 XML 来编码和解码远程过程调用以及参数。

然而，这是有代价的，整个 XML-RPC 协议存在几个问题：

+   发现性和文档不足。

+   参数是匿名的，XML-RPC 依赖于参数的顺序来区分它们。

+   简单性是 XML-RPC 的最大优势，也是最大问题所在。虽然大多数任务可以很容易地通过 XML-RPC 实现，但有些任务需要您费尽周折才能实现应该很简单的事情。

SOAP 旨在解决 XML-RPC 的局限性并提供更强大的协议。

### 注意

有关 XML-RPC 的更多信息，您可以访问以下链接：

[`en.wikipedia.org/wiki/XML-RPC`](http://en.wikipedia.org/wiki/XML-RPC)

## SOAP

自 Magento 1.3 以来，SOAP v1 是 Magento 支持的第一个协议，与 XML-RPC 一起。

### 注意

**SOAP**最初定义为**简单对象访问协议**，是用于在计算机网络中实现 Web 服务的结构化信息交换的协议规范。

**SOAP 请求**基本上是一个包含 SOAP 信封、头和主体的 HTTP POST 请求。

SOAP 的核心是**Web 服务描述语言**（**WSDL**），基本上是 XML。WSDL 用于描述 Web 服务的功能，这里是我们的 API 方法。这是通过使用以下一系列预定的对象来实现的：

+   **类型**：用于描述与 API 传输的数据；类型使用 XML Schema 进行定义，这是一种专门用于此目的的语言

+   **消息**：用于指定执行每个操作所需的信息；在 Magento 的情况下，我们的 API 方法将始终使用请求和响应消息

+   **端口类型**：用于定义可以执行的操作及其相应的消息

+   **端口**：用于定义连接点；在 Magento 的情况下，使用简单的字符串

+   **服务**：用于指定通过 API 公开的功能

+   **绑定**：用于定义与 SOAP 协议的操作和接口

### 注意

有关 SOAP 协议的更多信息，请参考以下网站：

[`en.wikipedia.org/wiki/SOAP`](http://en.wikipedia.org/wiki/SOAP)

所有 WSDL 配置都包含在每个模块的`wsdl.xml`文件中；例如，让我们看一下目录产品 API 的摘录：

文件位置为`app/code/local/Mdg/Giftregistry/etc/wsdl.xml`。

```php
<?xml version="1.0" encoding="UTF-8"?>
<definitions  

             name="{{var wsdl.name}}" targetNamespace="urn:{{var wsdl.name}}">
    <types>
        <schema  targetNamespace="urn:Magento">
      ...
            <complexType name="catalogProductEntity">
                <all>
                    <element name="product_id" type="xsd:string"/>
                    <element name="sku" type="xsd:string"/>
                    <element name="name" type="xsd:string"/>
                    <element name="set" type="xsd:string"/>
                    <element name="type" type="xsd:string"/>
                    <element name="category_ids" type="typens:ArrayOfString"/>
                    <element name="website_ids" type="typens:ArrayOfString"/>
                </all>
            </complexType>

        </schema>
    </types>
    <message name="catalogProductListResponse">
        <part name="storeView" type="typens:catalogProductEntityArray"/>
    </message>
  ...
    <portType name="{{var wsdl.handler}}PortType">
    ...
        <operation name="catalogProductList">
            <documentation>Retrieve products list by filters</documentation>
            <input message="typens:catalogProductListRequest"/>
            <output message="typens:catalogProductListResponse"/>
        </operation>
        ...
    </portType>
    <binding name="{{var wsdl.handler}}Binding" type="typens:{{var wsdl.handler}}PortType">
        <soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http"/>
    ...
        <operation name="catalogProductList">
            <soap:operation soapAction="urn:{{var wsdl.handler}}Action"/>
            <input>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded"
                           encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
            </input>
            <output>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded"
                           encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"/>
            </output>
        </operation>
    ...
    </binding>
    <service name="{{var wsdl.name}}Service">
        <port name="{{var wsdl.handler}}Port" binding="typens:{{var wsdl.handler}}Binding">
            <soap:address location="{{var wsdl.url}}"/>
        </port>
    </service>
</definitions>
```

通过使用 WSDL，我们可以记录、列出和支持更复杂的数据类型。

## RESTful API

RESTful API 是 Magento 支持的协议家族的新成员，仅适用于 Magento CE 1.7 或更早版本。

### 注意

**RESTful web** **service**（也称为**RESTful web API**）是使用 HTTP 和 REST 原则实现的 Web 服务。

RESTful API 可以通过以下三个方面来定义：

+   它使用标准的 HTTP 方法，如 GET、POST、DELETE 和 PUT

+   其公开的 URI 以目录结构的形式进行格式化

+   它使用 JSON 或 XML 来传输信息

### 注意

REST API 支持两种格式的响应，即 XML 和 JSON。

REST 相对于 SOAP 和 XML-RPC 的优势之一是，与 REST API 的所有交互都是通过 HTTP 协议完成的，这意味着它几乎可以被任何编程语言使用。

Magento REST API 具有以下特点：

+   通过向 Magento API 服务发出 HTTP 请求来访问资源

+   服务回复请求的数据或状态指示器，甚至两者都有

+   所有资源都可以通过`https://magento.localhost.com/api/rest/`访问

+   资源返回 HTTP 状态码，例如`HTTP 状态码 200`表示响应成功，或`HTTP 状态码 400`表示错误请求

+   通过将特定路径添加到基本 URL（`https://magento.localhost.com/api/rest/`）来请求特定资源

REST 使用**HTTP 动词**来管理资源的状态。在 Magento 实现中，有四个动词可用：GET、POST、PUT 和 DELETE。因此，在大多数情况下，使用 RESTful API 是微不足道的。

# 使用 API

现在我们已经澄清了每个可用协议，让我们探索一下 Magento API 可以做什么，以及如何使用每个可用协议进行操作。

我们将使用产品端点作为访问和处理不同 API 协议的示例。

### 注意

示例是用 PHP 提供的，并且使用了三种不同的协议。要获取 PHP 的完整示例并查看其他编程语言的示例，请访问[`magedevguide.com`](http://magedevguide.com)。

## 为 XML-RPC/SOAP 设置 API 凭据

在开始之前，我们需要创建一组 Web 服务凭据，以便访问 API 功能。

我们需要设置 API 用户角色。**角色**通过使用**访问控制列表**（**ACL**）来控制 API 的权限。通过实施这种设计模式，Magento 能够限制其 API 的某些部分只对特定用户开放。

在本章的后面，我们将学习如何将自定义函数添加到 ACL 并保护自定义扩展的 API 方法。现在，我们只需要通过执行以下步骤创建一个具有完全权限的角色：

1.  转到 Magento 后端。

1.  从主导航菜单转到**系统** | **Web 服务** | **角色**。

1.  单击**添加新角色**按钮。

1.  如下截图所示，您将被要求提供角色名称并指定角色资源：![为 XML-RPC/SOAP 设置 API 凭据](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_06_02.jpg)

1.  默认情况下，**资源访问**选项设置为**自定义**，未选择任何资源。在我们的情况下，我们将通过从下拉菜单中选择**全部**来更改**资源访问**选项。

1.  单击**保存角色**按钮。

现在我们在商店中有一个有效的角色，让我们继续创建 Web API 用户：

1.  转到 Magento 后端。

1.  从主导航菜单转到**系统** | **Web 服务** | **用户**。

1.  单击**添加新用户**按钮。

1.  接下来，我们将被要求提供用户信息，如下截图所示：![为 XML-RPC/SOAP 设置 API 凭据](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_06_01.jpg)

1.  在**API 密钥**和**API 密钥确认**字段中输入您想要的密码。

1.  单击**用户角色**选项卡。

1.  选择我们刚创建的用户角色。

1.  单击**保存用户**按钮。

我们需要为访问 API 创建用户名和角色的原因是，每个 API 函数都需要传递会话令牌作为参数。

因此，每次我们需要使用 API 时，我们必须首先调用`login`函数，该函数将返回有效的会话令牌 ID。

## 设置 REST API 凭据

新的 RESTful API 在身份验证方面略有不同；它不是使用传统的 Magento 网络服务用户，而是使用三足 OAuth 1.0 协议来提供身份验证。

OAuth 通过要求用户授权其应用程序来工作。当用户注册应用程序时，他/她需要填写以下字段：

+   **用户**：这是一个客户，他在 Magento 上有帐户，并可以使用 API 的服务。

+   **消费者**：这是使用 OAuth 访问 Magento API 的第三方应用程序。

+   **消费者密钥**：这是用于识别 Magento 用户的唯一值。

+   **消费者密钥**：这是客户用来保证消费者密钥所有权的秘密。此值永远不会在请求中传递。

+   **请求令牌**：此值由消费者（应用程序）用于从用户那里获取授权以访问 API 资源。

+   **访问令牌**：这是在成功认证时以请求令牌交换返回的。

让我们继续通过转到**系统** | **Web 服务** | **REST - OAuth 消费者**并在**管理**面板中选择**添加新**来注册我们的应用程序：

![设置 REST API 凭据](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_06_03.jpg)

### 注意

需要注意的一件重要的事情是必须定义回调 URL，用户在成功授权应用程序后将被重定向到该 URL。

我们的第一步是学习如何在每个可用的 API 协议中获取此会话令牌 ID。

要在 XML-RPC 中获取会话令牌 ID，我们需要执行以下代码：

```php
$apiUser = 'username';
$apiKey = 'password';
$client = new Zend_XmlRpc_Client('http://ourhost.com/api/xmlrpc/');
// We authenticate ourselves and get a session token id 
$sessionId = $client->call('login', array($apiUser, $apiKey));
```

要在 SOAP v2 中获取会话令牌 ID，我们需要执行以下代码：

```php
$apiUser = 'username';
$apiKey = 'password';
$client = new SoapClient('http://ourhost.com/api/v2_soap/?wsdl');
// We authenticate ourselves and get a session token id 
$sessionId = $client->login($apiUser, $apiKey);
```

要在 REST 中获取会话令牌 ID，我们需要执行以下步骤：

```php
$callbackUrl = "http://magento.localhost.com/oauth_admin.php";
$temporaryCredentialsRequestUrl = "http://magento.localhost.com/oauth/initiate?oauth_callback=" . urlencode($callbackUrl);
$adminAuthorizationUrl = 'http://magento.localhost.com/admin/oAuth_authorize';
$accessTokenRequestUrl = 'http://magento.localhost.com/oauth/token';
$apiUrl = 'http://magento.localhost.com/api/rest';
$consumerKey = 'yourconsumerkey';
$consumerSecret = 'yourconsumersecret';

session_start();

$authType = ($_SESSION['state'] == 2) ? OAUTH_AUTH_TYPE_AUTHORIZATION : OAUTH_AUTH_TYPE_URI;
$oauthClient = new OAuth($consumerKey, $consumerSecret, OAUTH_SIG_METHOD_HMACSHA1, $authType);

$oauthClient->setToken($_SESSION['token'], $_SESSION['secret']);
```

## 加载和读取数据

`Mage_Catalog`模块产品端点具有以下公开方法，我们可以使用这些方法来管理产品：

+   `catalog_product.currentStore`：设置/获取当前商店视图

+   `catalog_product.list`：使用过滤器检索产品列表

+   `catalog_product.info`：检索产品

+   `catalog_product.create`：创建新产品

+   `catalog_product.update`：更新产品

+   `catalog_product.setSpecialPrice`：为产品设置特殊价格

+   `catalog_product.getSpecialPrice`：获取产品的特殊价格

+   `catalog_product.delete`：删除产品

目前，我们特别感兴趣的功能是`catalog_product.list`和`catalog_product.info`。让我们看看如何使用 API 从我们的暂存商店中检索产品数据。

要从我们的暂存商店中以 XML-RPC 检索产品数据，请执行以下代码：

```php
…
$result = $client->call($sessionId, 'catalog_product.list');
print_r ($result);
…
```

要从我们的暂存商店中以 SOAPv2 检索产品数据，请执行以下代码：

```php
…
$result = $client->catalogProductList($sessionId);
print_r($result);
…
```

要从我们的暂存商店中以 REST 检索产品数据，请执行以下代码：

```php
…
$resourceUrl = $apiUrl . "/products";
$oauthClient->fetch($resourceUrl, array(), 'GET', array('Content-Type' => 'application/json'));
$productsList = json_decode($oauthClient->getLastResponse());
…
```

无论使用哪种协议，我们都将得到所有产品的 SKU 列表，但是如果我们想根据属性筛选产品列表呢？Magento 列出了允许我们根据属性筛选产品列表的功能，通过传递参数。话虽如此，让我们看看如何为我们的产品列表调用添加过滤器。

要在 XML-RPC 中为我们的产品列表调用添加过滤器，请执行以下代码：

```php
…
$result = $client->call('catalog_product.list', array($sessionId, $filters);
print_r ($result);
…
```

要在 SOAPv2 中为我们的产品列表调用添加过滤器，请执行以下代码：

```php
…
$result = $client->catalogProductList($sessionId,$filters);
print_r($result);
…
```

使用 REST，事情并不那么简单，无法按属性检索产品集合。但是，我们可以通过执行以下代码来检索属于特定类别的所有产品：

```php
…
$categoryId = 3;
$resourceUrl = $apiUrl . "/products/category_id=" . categoryId ;
$oauthClient->fetch($resourceUrl, array(), 'GET', array('Content-Type' => 'application/json'));
$productsList = json_decode($oauthClient->getLastResponse());
…
```

## 更新数据

现在我们能够从 Magento API 中检索产品信息，我们可以开始更新每个产品的内容。

`catalog_product.update`方法将允许我们修改任何产品属性；函数调用需要以下参数。

要在 XML-RPC 中更新数据，请执行以下代码：

```php
…
$productId = 200;
$productData = array( 'sku' => 'changed_sku', 'name' => 'New Name', 'price' => 15.40 );
$result = $client->call($sessionId, 'catalog_product.update', array($productId, $productData));
print_r($result);
…
```

要在 SOAPv2 中更新数据，请执行以下代码：

```php
…
$productId = 200;
$productData = array( 'sku' => 'changed_sku', 'name' => 'New Name', 'price' => 15.40 );
$result = $client->catalogProductUpdate($sessionId, array($productId, $productData));
print_r($result);
…
```

要在 REST 中更新数据，请执行以下代码：

```php
…
$productData = json_encode(array(
    'type_id'           => 'simple',
    'attribute_set_id'  => 4,
    'sku'               => 'simple' . uniqid(),
    'weight'            => 10,
    'status'            => 1,
    'visibility'        => 4,
    'name'              => 'Test Product',
    'description'       => 'Description',
    'short_description' => 'Short Description',
    'price'             => 29.99,
    'tax_class_id'      => 2,
));
$oauthClient->fetch($resourceUrl, $productData, OAUTH_HTTP_METHOD_POST, array('Content-Type' => 'application/json'));
$updatedProduct = json_decode($oauthClient->getLastResponseInfo());
…
```

## 删除产品

使用 API 删除产品非常简单，可能是最常见的操作之一。

要在 XML-RPC 中删除产品，请执行以下代码：

```php
…
$productId = 200;
$result = $client->call($sessionId, 'catalog_product.delete', $productId);
print_r($result);
…
```

要在 SOAPv2 中删除产品，请执行以下代码：

```php
…
$productId = 200;
$result = $client->catalogProductDelete($sessionId, $productId);
print_r($result);
…
```

要删除 REST 中的代码，请执行以下代码：

```php
…
$productData = json_encode(array(
    'id'           => 4
));
$oauthClient->fetch($resourceUrl, $productData, OAUTH_HTTP_METHOD_DELETE, array('Content-Type' => 'application/json'));
$updatedProduct = json_decode($oauthClient->getLastResponseInfo());
…
```

# 扩展 API

现在我们已经基本了解了如何使用 Magento Core API，我们可以继续扩展并添加我们自己的自定义功能。为了添加新的 API 功能，我们必须修改/创建以下文件：

+   `wsdl.xml`

+   `api.xml`

+   `api.php`

为了使我们的注册表可以被第三方系统访问，我们需要创建并公开以下功能：

+   `giftregistry_registry.list`：这将检索所有注册表 ID 的列表，并带有可选的客户 ID 参数

+   `giftregistry_registry.info`：这将检索所有注册表信息，并带有必需的`registry_id`参数

+   `giftregistry_item.list`：这将检索与注册表关联的所有注册表项 ID 的列表，并带有必需的`registry_id`参数

+   `giftregistry_item.info`：这将检索注册表项的产品和详细信息，并带有一个必需的`item_id`参数

到目前为止，我们只添加了读取操作。现在让我们尝试包括用于更新、删除和创建注册表和注册表项的 API 方法。

### 提示

要查看完整代码和详细说明的答案，请访问[`www.magedevguide.com/`](http://www.magedevguide.com/)。

我们的第一步是实现 API 类和所需的功能：

1.  导航到`Model`目录。

1.  创建一个名为`Api.php`的新类，并将以下占位符内容放入其中：

文件位置是`app/code/local/Mdg/Giftregistry/Model/Api.php`。

```php
<?php
class Mdg_Giftregisty_Model_Api extends Mage_Api_Model_Resource_Abstract
{
    public function getRegistryList($customerId = null)
    {

    }

    public function getRegistryInfo($registryId)
    {

    }

    public function getRegistryItems($registryId)
    {

    }

    public function getRegistryItemInfo($registryItemId)
    {

    }
}
```

1.  创建一个名为`Api/`的新目录。

1.  在`Api/`内创建一个名为`V2.php`的新类，并将以下占位符内容放入其中：

文件位置是`app/code/local/Mdg/Giftregistry/Model/Api/V2.php`。

```php
<?php
class Mdg_Giftregisty_Model_Api_V2 extends Mdg_Giftregisty_Model_Api
{

}
```

您可能注意到的第一件事是`V2.php`文件正在扩展我们刚刚创建的`API`类。唯一的区别是`V2`类由`SOAP_v2`协议使用，而常规的`API`类用于所有其他请求。

让我们使用以下有效代码更新`API`类：

文件位置是`app/code/local/Mdg/Giftregistry/Model/Api.php`。

```php
<?php 
class Mdg_Giftregisty_Model_Api extends Mage_Api_Model_Resource_Abstract
{
    public function getRegistryList($customerId = null)
    {
        $registryCollection = Mage::getModel('mdg_giftregistry/entity')->getCollection();
        if(!is_null($customerId))
        {
            $registryCollection->addFieldToFilter('customer_id', $customerId);
        }
        return $registryCollection;
    }

    public function getRegistryInfo($registryId)
    {
        if(!is_null($registryId))
        {
            $registry = Mage::getModel('mdg_giftregistry/entity')->load($registryId);
            if($registry)
            {
                return $registry;
            } else {
		   return false;	  
		}
        } else {
            return false;
        }
    }

    public function getRegistryItems($registryId)
    {
        if(!is_null($registryId))
        {
            $registryItems = Mage::getModel('mdg_giftregistry/item')->getCollection();
            $registryItems->addFieldToFilter('registry_id', $registryId);
		Return $registryItems;
        } else {
            return false;
        }
    }

    public function getRegistryItemInfo($registryItemId)
    {
        if(!is_null($registryItemId))
        {
            $registryItem = Mage::getModel('mdg_giftregistry/item')->load($registryItemId);
            if($registryItem){
                return $registryItem;
            } else {
		   return false;
		}
        } else {
            return false;
        }
    }
}
```

从前面的代码中可以看到，我们并没有做任何新的事情。每个函数负责加载 Magento 对象的集合或基于所需参数加载特定对象。

为了将这个新功能暴露给 Magento API，我们需要配置之前创建的 XML 文件。让我们从更新`api.xml`文件开始：

1.  打开`api.xml`文件。

1.  添加以下 XML 代码：

文件位置是`app/code/local/Mdg/Giftregistry/etc/api.xml`。

```php
<?xml version="1.0"?>
<config>
    <api>
        <resources>
            <giftregistry_registry translate="title" module="mdg_giftregistry">
                <model>mdg_giftregistry/api</model>
                <title>Mdg Giftregistry Registry functions</title>
                <methods>
                    <list translate="title" module="mdg_giftregistry">
                        <title>getRegistryList</title>
                        <method>getRegistryList</method>
                    </list>
                    <info translate="title" module="mdg_giftregistry">
                        <title>getRegistryInfo</title>
                        <method>getRegistryInfo</method>
                    </info>
                </methods>
            </giftregistry_registry>
            <giftregistry_item translate="title" module="mdg_giftregistry">
                <model>mdg_giftregistry/api</model>
                <title>Mdg Giftregistry Registry Items functions</title>
                <methods>
                    <list translate="title" module="mdg_giftregistry">
                        <title>getRegistryItems</title>
                        <method>getRegistryItems</method>
                    </list>
                    <info translate="title" module="mdg_giftregistry">
                        <title>getRegistryItemInfo</title>
                        <method>getRegistryItemInfo</method>
                    </info>
                </methods>
            </giftregistry_item>
        </resources>
        <resources_alias>
            <giftregistry_registry>giftregistry_registry</giftregistry_registry>
            <giftregistry_item>giftregistry_item</giftregistry_item>
        </resources_alias>
        <v2>
            <resources_function_prefix>
                <giftregistry_registry>giftregistry_registry</giftregistry_registry>
                <giftregistry_item>giftregistry_item</giftregistry_item>
            </resources_function_prefix>
        </v2>
    </api>
</config>
```

还有一个文件需要更新，以确保 SOAP 适配器接收到我们的新 API 函数：

1.  打开`wsdl.xml`文件。

1.  由于`wsdl.xml`文件通常非常庞大，我们将在几个地方分解它。让我们从定义`wsdl.xml`文件的框架开始：

文件位置是`app/code/local/Mdg/Giftregistry/etc/wsdl.xml`。

```php
<?xml version="1.0" encoding="UTF-8"?>
<definitions   

             name="{{var wsdl.name}}" targetNamespace="urn:{{var wsdl.name}}">
    <types>

    </types>
    <message name="gitregistryRegistryListRequest">

    </message>
    <portType name="{{var wsdl.handler}}PortType">

    </portType>
    <binding name="{{var wsdl.handler}}Binding" type="typens:{{var wsdl.handler}}PortType">
        <soap:binding style="rpc" transport="http://schemas.xmlsoap.org/soap/http" />

    </binding>
    <service name="{{var wsdl.name}}Service">
        <port name="{{var wsdl.handler}}Port" binding="typens:{{var wsdl.handler}}Binding">
            <soap:address location="{{var wsdl.url}}" />
        </port>
    </service>
</definitions> 
```

1.  这是基本的占位符。我们有本章开头定义的所有主要节点。我们首先要定义的是我们的 API 将使用的自定义数据类型：

文件位置是`app/code/local/Mdg/Giftregistry/etc/wsdl.xml`。

```php
…
<schema  targetNamespace="urn:Magento">
            <import namespace="http://schemas.xmlsoap.org/soap/encoding/" schemaLocation="http://schemas.xmlsoap.org/soap/encoding/"/>
            <complexType name="giftRegistryEntity">
                <all>
                    <element name="entity_id" type="xsd:integer" minOccurs="0" />
                    <element name="customer_id" type="xsd:integer" minOccurs="0" />
                    <element name="type_id" type="xsd:integer" minOccurs="0" />
                    <element name="website_id" type="xsd:integer" minOccurs="0" />
                    <element name="event_date" type="xsd:string" minOccurs="0" />
                    <element name="event_country" type="xsd:string" minOccurs="0" />
                    <element name="event_location" type="xsd:string" minOccurs="0" />
                </all>
            </complexType>
            <complexType name="giftRegistryEntityArray">
                <complexContent>
                    <restriction base="soapenc:Array">
                        <attribute ref="soapenc:arrayType" wsdl:arrayType="typens:giftRegistryEntity[]" />
                    </restriction>
                </complexContent>
            </complexType>
            <complexType name="registryItemsEntity">
                <all>
                    <element name="item_id" type="xsd:integer" minOccurs="0" />
                    <element name="registry_id" type="xsd:integer" minOccurs="0" />
                    <element name="product_id" type="xsd:integer" minOccurs="0" />
                </all>
            </complexType>
            <complexType name="registryItemsArray">
                <complexContent>
                    <restriction base="soapenc:Array">
                        <attribute ref="soapenc:arrayType" wsdl:arrayType="typens:registryItemsEntity[]" />
                    </restriction>
                </complexContent>
            </complexType>
        </schema>
…
```

### 注意

复杂数据类型允许我们映射通过 API 传输的属性和对象。

1.  消息允许我们定义在每个 API 调用请求和响应中传输的复杂类型。让我们继续在我们的`wsdl.xml`中添加相应的消息：

文件位置是`app/code/local/Mdg/Giftregistry/etc/wsdl.xml`。

```php
…
    <message name="gitregistryRegistryListRequest">
        <part name="sessionId" type="xsd:string" />
        <part name="customerId" type="xsd:integer"/>
    </message>
    <message name="gitregistryRegistryListResponse">
        <part name="result" type="typens:giftRegistryEntityArray" />
    </message>
    <message name="gitregistryRegistryInfoRequest">
        <part name="sessionId" type="xsd:string" />
        <part name="registryId" type="xsd:integer"/>
    </message>
    <message name="gitregistryRegistryInfoResponse">
        <part name="result" type="typens:giftRegistryEntity" />
    </message>
    <message name="gitregistryItemListRequest">
        <part name="sessionId" type="xsd:string" />
        <part name="registryId" type="xsd:integer"/>
    </message>
    <message name="gitregistryItemListResponse">
        <part name="result" type="typens:registryItemsArray" />
    </message>
    <message name="gitregistryItemInfoRequest">
        <part name="sessionId" type="xsd:string" />
        <part name="registryItemId" type="xsd:integer"/>
    </message>
    <message name="gitregistryItemInfoResponse">
        <part name="result" type="typens:registryItemsEntity" />
    </message>
…
```

1.  一个重要的事情要注意的是，每个请求消息将始终包括一个`sessionId`属性，用于验证和认证每个请求，而响应用于指定返回的编译数据类型或值：

文件位置是`app/code/local/Mdg/Giftregistry/etc/wsdl.xml`。

```php
…
    <portType name="{{var wsdl.handler}}PortType">
        <operation name="giftregistryRegistryList">
            <documentation>Get Registries List</documentation>
            <input message="typens:gitregistryRegistryListRequest" />
            <output message="typens:gitregistryRegistryListResponse" />
        </operation>
        <operation name="giftregistryRegistryInfo">
            <documentation>Get Registry Info</documentation>
            <input message="typens:gitregistryRegistryInfoRequest" />
            <output message="typens:gitregistryRegistryInfoResponse" />
        </operation>
        <operation name="giftregistryItemList">
            <documentation>getAllProductsInfo</documentation>
            <input message="typens:gitregistryItemListRequest" />
            <output message="typens:gitregistryItemListResponse" />
        </operation>
        <operation name="giftregistryItemInfo">
            <documentation>getAllProductsInfo</documentation>
            <input message="typens:gitregistryItemInfoRequest" />
            <output message="typens:gitregistryItemInfoResponse" />
        </operation>
    </portType>
…
```

1.  为了正确添加新的 API 端点，下一个需要的是定义绑定，用于指定哪些方法是公开的：

文件位置是`app/code/local/Mdg/Giftregistry/etc/wsdl.xml`。

```php
…        
<operation name="giftregistryRegistryList">
            <soap:operation soapAction="urn:{{var wsdl.handler}}Action" />
            <input>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </input>
            <output>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </output>
        </operation>
        <operation name="giftregistryRegistryInfo">
            <soap:operation soapAction="urn:{{var wsdl.handler}}Action" />
            <input>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </input>
            <output>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </output>
        </operation>
        <operation name="giftregistryItemList">
            <soap:operation soapAction="urn:{{var wsdl.handler}}Action" />
            <input>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </input>
            <output>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </output>
        </operation>
        <operation name="giftregistryInfoList">
            <soap:operation soapAction="urn:{{var wsdl.handler}}Action" />
            <input>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </input>
            <output>
                <soap:body namespace="urn:{{var wsdl.name}}" use="encoded" encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" />
            </output>
        </operation>
…
```

### 注意

你可以在`http://magedevguide.com/chapter6/wsdl`上看到完整的`wsdl.xml`。

即使我们把它分解了，WSDL 代码仍然可能令人不知所措，老实说，我花了一些时间才习惯这样一个庞大的 XML 文件。所以如果你觉得或者感觉它太多了，就一步一步来吧。

## 扩展 REST API

到目前为止，我们只是在扩展 API 的 SOAP 和 XML-RPC 部分上工作。扩展 RESTful API 的过程略有不同。

### 注意

REST API 是在 Magento Community Edition 1.7 和 Enterprise Edition 1.12 中引入的。

为了将新的 API 方法暴露给 REST API，我们需要创建一个名为`api2.xml`的新文件。这个文件的配置比普通的`api.xml`复杂一些，所以我们将在添加完整代码后对其进行分解：

1.  在`etc/`文件夹下创建一个名为`api2.xml`的新文件。

1.  打开`api2.xml`。

1.  复制以下代码：

文件位置是`app/code/local/Mdg/Giftregistry/etc/api2.xml`。

```php
<?xml version="1.0"?>
<config>
    <api2>
        <resource_groups>
            <giftregistry translate="title" module="mdg_giftregistry">
                <title>MDG GiftRegistry API calls</title>
                <sort_order>30</sort_order>
                <children>
                    <giftregistry_registry translate="title" module="mdg_giftregistry">
                        <title>Gift Registries</title>
                        <sort_order>50</sort_order>
                    </giftregistry_registry>
                    <giftregistry_item translate="title" module="mdg_giftregistry">
                        <title>Gift Registry Items</title>
                        <sort_order>50</sort_order>
                    </giftregistry_item>
                </children>
            </giftregistry>
        </resource_groups>
        <resources>
            <giftregistryregistry translate="title" module="mdg_giftregistry">
                <group>giftregistry_registry</group>
                <model>mdg_giftregistry/api_registry</model>
                <working_model>mdg_giftregistry/api_registry</working_model>
                <title>Gift Registry</title>
                <sort_order>10</sort_order>
                <privileges>
                    <admin>
                        <create>1</create>
                        <retrieve>1</retrieve>
                        <update>1</update>
                        <delete>1</delete>
                    </admin>
                </privileges>
                <attributes translate="product_count" module="mdg_giftregistry">
                    <registry_list>Registry List</registry_list>
                    <registry>Registry</registry>
                    <item_list>Item List</item_list>
                    <item>Item</item>
                </attributes>
                <entity_only_attributes>
                </entity_only_attributes>
                <exclude_attributes>
                </exclude_attributes>
                <routes>
                    <route_registry_list>
                        <route>/mdg/registry/list</route>
                        <action_type>collection</action_type>
                    </route_registry_list>
                    <route_registry_entity>
                        <route>/mdg/registry/:registry_id</route>
                        <action_type>entity</action_type>
                    </route_registry_entity>
                    <route_registry_list>
                        <route>/mdg/registry_item/list</route>
                        <action_type>collection</action_type>
                    </route_registry_list>
                    <route_registry_list>
                        <route>/mdg/registry_item/:item_id</route>
                        <action_type>entity</action_type>
                    </route_registry_list>
                </routes>
                <versions>1</versions>
            </giftregistryregistry>
        </resources>
    </api2>
</config>
```

一个重要的事情要注意的是，我们在这个配置文件中定义了一个路由节点。这被 Magento 视为前端路由，用于访问 RESTful `api`函数。还要注意的是，我们不需要为此创建一个新的控制器。

现在，我们还需要包括一个新的类来处理 REST 请求，并实现每个定义的权限：

1.  在`Model/Api/Registry/Rest/Admin`下创建一个名为`V1.php`的新类。

1.  打开`V1.php`类并复制以下代码：

文件位置是`app/code/local/Mdg/Giftregistry/Model/Api/Registry/Rest/Admin/V1.php`。

```php
<?php

class Mdg_Giftregistry_Model_Api_Registry_Rest_Admin_V1 extends Mage_Catalog_Model_Api2_Product_Rest {
    /**
     * @return stdClass
     */
    protected function _retrieve()
    {
        $registryCollection = Mage::getModel('mdg_giftregistry/entity')->getCollection();
        return $registryCollection;
    }
}
```

# 保护 API

保护我们的 API 已经是创建模块过程的一部分，也由配置处理。Magento 限制对其 API 的访问方式是使用 ACL。

正如我们之前学到的，这些 ACL 允许我们设置具有访问 API 不同部分权限的角色。现在，我们要做的是使我们的新自定义功能对 ACL 可用：

1.  打开`api.xml`文件。

1.  在`</v2>`节点之后添加以下代码：

文件位置为`app/code/local/Mdg/Giftregistry/etc/api.xml`。

```php
<acl>
    <resources>
        <giftregistry translate="title" module="mdg_giftregistry">
            <title>MDG Gift Registry</title>
            <sort_order>1</sort_order>
            <registry translate="title" module="mdg_giftregistry">
                <title>MDG Gift Registry</title>
                <list translate="title" module="mdg_giftregistry">
                    <title>List Available Registries</title>
                </list>
                <info translate="title" module="mdg_giftregistry">
                    <title>Retrieve registry data</title>
                </info>
            </registry>
            <item translate="title" module="mdg_giftregistry">
                <title>MDG Gift Registry Item</title>
                <list translate="title" module="mdg_giftregistry">
                    <title>List Available Items inside a registry</title>
                </list>
                <info translate="title" module="mdg_giftregistry">
                    <title>Retrieve registry item data</title>
                </info>
            </item>
        </giftregistry>
    </resources>
</acl>
```

# 总结

在之前的章节中，我们学会了如何扩展 Magento 以为商店所有者和客户添加新功能；了解如何扩展和使用 Magento API 为我们打开了无限的可能性。

通过使用 API，我们可以将 Magento 与 ERP 和销售点等第三方系统集成；既可以导入数据，也可以导出数据。

在下一章中，我们将学习如何为我们迄今为止构建的所有代码正确构建测试，并且我们还将探索多个测试框架。


# 第七章：测试和质量保证

到目前为止，我们已经涵盖了：

+   Magento 基础知识

+   前端开发

+   后端开发

+   扩展和使用 API

然而，我们忽略了任何扩展或自定义代码开发的关键步骤：测试和质量保证。

尽管 Magento 是一个非常复杂和庞大的平台，但在 Magento2 之前的版本中没有包含/集成的单元测试套件。

因此，适当的测试和质量保证经常被大多数 Magento 开发人员忽视，要么是因为缺乏信息，要么是因为一些测试工具的大量开销，虽然没有太多可用于运行 Magento 的适当测试的工具，但现有的工具质量非常高。

在本章中，我们将看看测试 Magento 代码的不同选项，并为我们的自定义扩展构建一些非常基本的测试。

因此，让我们来看看本章涵盖的主题：

+   Magento 可用的不同测试框架和工具

+   测试我们的 Magento 代码的重要性

+   如何设置、安装和使用 Ecomdev PHPUnit 扩展

+   如何设置、安装和使用 Magento Mink 来运行功能测试

# 测试 Magento

在我们开始编写任何测试之前，重要的是我们了解与测试相关的概念，尤其是每种可用方法论。

## 单元测试

单元测试的理念是为我们代码的某些区域（单元）编写测试，以便我们可以验证代码是否按预期工作，并且函数是否返回预期值。

> *单元测试是一种方法，通过该方法测试源代码的单个单元，以确定它们是否适合使用，其中包括一个或多个计算机程序模块以及相关的控制数据、使用程序和操作程序。*

编写单元测试的另一个优势是，通过执行测试，我们更有可能编写更容易测试的代码。

这意味着随着我们不断编写更多的测试，我们的代码往往会被分解成更小但更专业的功能。我们开始构建一个测试套件，可以在引入更改或功能时针对我们的代码库运行；这就是回归测试。

## 回归测试

回归测试主要是指在进行代码更改后重新运行现有测试套件的做法，以检查新功能是否也引入了新错误。

> 回归测试是一种软件测试，旨在在对现有系统的功能和非功能区域进行更改（如增强、补丁或配置更改）后，发现新的软件错误或回归。

在 Magento 商店或任何电子商务网站的特定情况下，我们希望对商店的关键功能进行回归测试，例如结账、客户注册、添加到购物车等。

## 功能测试

功能测试更关注的是根据特定输入返回适当输出的应用程序，而不是内部发生的情况。

> *功能测试是一种基于被测试软件组件的规范的黑盒测试类型。通过向它们提供输入并检查输出来测试功能，很少考虑内部程序结构。*

这对于像我们这样的电子商务网站尤为重要，我们希望测试网站与客户的体验一致。

## TDD

近年来变得越来越受欢迎的一种测试方法，现在也正在 Magento 中出现，被称为**测试驱动开发**（**TDD**）。

> *测试驱动开发（TDD）是一种依赖于非常短的开发周期重复的软件开发过程：首先开发人员编写一个（最初失败的）自动化测试用例，定义所需的改进或新功能，然后生成最少量的代码来通过该测试，最后将新代码重构为可接受的标准。*

TDD 背后的基本概念是首先编写一个失败的测试，然后编写代码来通过测试；这会产生非常短的开发周期，并有助于简化代码。

理想情况下，您希望通过在 Magento 中使用 TDD 来开始开发您的模块和扩展。我们在之前的章节中省略了这一点，因为这会增加不必要的复杂性并使读者困惑。

### 注意

有关从头开始使用 Magento 进行 TDD 的完整教程，请访问`http://magedevguide.com/getting-started-with-tdd`。

# 工具和测试框架

如前所述，有几个框架和工具可用于测试 PHP 代码和 Magento 代码。让我们更好地了解每一个：

+   `Ecomdev_PHPUnit`：这个扩展真是太棒了；Ecomdev 的开发人员创建了一个集成了 PHPUnit 和 Magento 的扩展，还向 PHPUnit 添加了 Magento 特定的断言，而无需修改核心文件或影响数据库。

+   `Magento_Mink`：Mink 是 Behat 框架的 PHP 库，允许您编写功能和验收测试；Mink 允许编写模拟用户行为和浏览器交互的测试。

+   `Magento_TAF`：`Magento_TAF`代表 Magento 测试自动化框架，这是 Magento 提供的官方测试工具。`Magento_TAF`包括超过 1,000 个功能测试，非常强大。不幸的是，它有一个主要缺点；它有很大的开销和陡峭的学习曲线。

## 使用 PHPUnit 进行单元测试

在`Ecomdev_PHPUnit`之前，使用 PHPUnit 测试 Magento 是有问题的，而且从可用的不同方法来看，实际上并不实用。几乎所有都需要核心代码修改，或者开发人员必须费力地设置基本的 PHPUnits。

### 安装 Ecomdev_PHPUnit

安装`Ecomdev_PHPUnit`的最简单方法是直接从 GitHub 存储库获取副本。让我们在控制台上写下以下命令：

```php
**git clone git://github.com/IvanChepurnyi/EcomDev_PHPUnit.git**

```

现在将文件复制到您的 Magento 根目录。

### 注意

Composer 和 Modman 是可用于安装的替代选项。有关每个选项的更多信息，请访问[`magedevguide.com/module-managers`](http://magedevguide.com/module-managers)。

最后，我们需要设置配置，指示 PHPUnit 扩展使用哪个数据库；`local.xml.phpunit`是`Ecomdev_PHPUnit`添加的新文件。这个文件包含所有特定于扩展的配置，并指定测试数据库的名称。

文件位置为`app/etc/local.xml.phpunit`。参考以下代码：

```php
<?xml version="1.0"?>
<config>
    <global>
        <resources>
            <default_setup>
                <connection>
                   <dbname><![CDATA[magento_unit_tests]]></dbname>
                </connection>
            </default_setup>
        </resources>
    </global>
    <default>
        <web>
            <seo>
                <use_rewrites>1</use_rewrites>
            </seo>
            <secure>
                <base_url>[change me]</base_url>
            </secure>
            <unsecure>
                <base_url>[change me]</base_url>
            </unsecure>
            <url>
                <redirect_to_base>0</redirect_to_base>
            </url>
        </web>
    </default>
    <phpunit>
        <allow_same_db>0</allow_same_db>
    </phpunit>
</config>
```

您需要为运行测试创建一个新的数据库，并在`local.xml.phpunit`文件中替换示例配置值。

默认情况下，这个扩展不允许您在同一个数据库上运行测试；将测试数据库与开发和生产数据库分开允许我们有信心地运行我们的测试。

### 为我们的扩展设置配置

现在我们已经安装并设置了 PHPUnit 扩展，我们需要准备我们的礼品注册扩展来运行单元测试。按照以下步骤进行：

1.  打开礼品注册扩展的`config.xml`文件

1.  添加以下代码（文件位置为`app/code/local/Mdg/Giftregistry/etc/config.xml`）：

```php
…
<phpunit>
        <suite>
            <modules>
                    <Mdg_Giftregistry/>
            </modules>
         </suite>
</phpunit>
…
```

这个新的配置节点允许 PHPUnit 扩展识别扩展并运行匹配的测试。

我们还需要创建一个名为`Test`的新目录，我们将用它来放置所有的测试文件。使用`Ecomdev_PHPUnit`相比以前的方法的一个优点是，这个扩展遵循 Magento 的标准。

这意味着我们必须在`Test`文件夹内保持相同的模块目录结构：

```php
Test/
Model/
Block/
Helper/
Controller/
Config/
```

基于此，每个`Test`案例类的命名约定将是`[Namespace]_[Module Name]_Test_[Group Directory]_[Entity Name]`。

每个`Test`类必须扩展以下三个基本`Test`类中的一个：

+   `EcomDev_PHPUnit_Test_Case`：这个类用于测试助手、模型和块

+   `EcomDev_PHPUnit_Test_Case_Config`：这个类用于测试模块配置

+   `EcomDev_PHPUnit_Test_Case_Controller`：这个类用于测试布局渲染过程和控制器逻辑

### 测试案例的解剖

在跳入并尝试创建我们的第一个测试之前，让我们分解`Ecomdev_PHPUnit`提供的一个示例：

```php
<?php
class EcomDev_Example_Test_Model_Product extends EcomDev_PHPUnit_Test_Case
{
    /**
     * Product price calculation test
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
    public function priceCalculation($productId, $storeId)
    {
        $storeId = Mage::app()->getStore($storeId)->getId();
        $product = Mage::getModel('catalog/product')
            ->setStoreId($storeId)
            ->load($productId);
        $expected = $this->expected('%s-%s', $productId, $storeId);
        $this->assertEquals(
            $expected->getFinalPrice(),
            $product->getFinalPrice()
        );
        $this->assertEquals(
            $expected->getPrice(),
            $product->getPrice()
        );
    }
}
```

在示例`test`类中要注意的第一件重要的事情是注释注释：

```php
…
/**
     * Product price calculation test
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
…
```

这些注释被 PHPUnit 扩展用来识别哪些类函数是测试，它们还允许我们为运行每个测试设置特定的设置。让我们来看一下一些可用的注释：

+   `@test`：这个注释将一个类函数标识为 PHPUnit 测试

+   `@loadFixture`：这个注释指定了固定的使用

+   `@loadExpectation`：这个注释指定了期望的使用

+   `@doNotIndexAll`：通过添加这个注释，我们告诉 PHPUnit 测试在加载固定后不应该运行任何索引

+   `@doNotIndex [index_code]`：通过添加这个注释，我们可以指示 PHPUnit 不运行特定的索引

所以现在，你可能有点困惑。固定？期望？它们是什么？

以下是对固定和期望的简要描述：

+   **固定**：固定是**另一种标记语言**（**YAML**）文件，代表数据库或配置实体

+   **期望**：期望对我们的测试中不想要硬编码的值很有用，也是在 YAML 值中指定的

### 注意

有关 YAML 标记的更多信息，请访问`http://magedevguide.com/resources/yaml`。

所以，正如我们所看到的，固定提供了测试处理的数据，期望用于检查测试返回的结果是否是我们期望看到的。

固定和期望存储在每个`Test`类型目录中。按照之前的例子，我们将有一个名为`Product/`的新目录。在里面，我们需要一个期望的新目录和一个我们的固定的新目录。

让我们来看一下修订后的文件夹结构：

```php
Test/
Model/  
  Product.php
  Product/
    expectations/
    fixtures/
Block/
Helper/
Controller/
Config/
```

![测试案例的解剖](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_07_01.jpg)

### 创建一个单元测试

对于我们的第一个单元测试，让我们创建一个非常基本的测试，允许我们测试之前创建的礼品注册模型。

正如我们之前提到的，`Ecomdev_PHPUnit`使用一个单独的数据库来运行所有的测试；为此，我们需要创建一个新的固定，为我们的测试用例提供所有的数据。按照以下步骤：

1.  打开`Test/Model`文件夹。

1.  创建一个名为`Registry`的新文件夹。

1.  在`Registry`文件夹中，创建一个名为`fixtures`的新文件夹。

1.  创建一个名为`registryList.yaml`的新文件，并将以下代码粘贴到其中（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/fixtures/registryList.yaml`）：

```php
  website: # Initialize websites
    - website_id: 2
      code: default
      name: Test Website
      default_group_id: 2
  group: # Initializes store groups
    - group_id: 2
      website_id: 2
      name: Test Store Group
      default_store_id: 2
      root_category_id: 2 # Default Category
  store: # Initializes store views
    - store_id: 2
      website_id: 2
      group_id: 2
      code: default
      name: Default Test Store
      is_active: 1
eav:
   customer_customer:
     - entity_id: 1
       entity_type_id: 3
       website_id: 2
       email: test@magentotest.com
       group_id: 2
       store_id: 2
       is_active: 1
   mdg_giftregistry_entity:
     - entity_id: 1
       customer_id: 1
       type_id: 2
       website_id: 2
       event_date: 12/12/2012
       event_country: Canada
       event_location: Dundas Square
       created_at: 21/12/2012
     - entity_id: 2
       customer_id: 1
       type_id: 3
       website_id: 2
       event_date: 01/01/2013
       event_country: Canada
       event_location: Eaton Center
       created_at: 21/12/2012
```

它可能看起来不像，但我们通过这个固定添加了很多信息。我们将创建以下固定数据：

+   一个网站范围

+   一个商店组

+   一个商店视图

+   一个客户记录

+   两个礼品注册

通过使用固定，我们正在创建可用于我们的测试用例的数据。这使我们能够多次运行相同的数据测试，并灵活地进行更改。

现在，你可能想知道 PHPUnit 扩展如何将`Test`案例与特定的固定配对。

扩展加载固定有两种方式：一种是在注释注释中指定固定，或者如果没有指定固定名称，扩展将搜索与正在执行的`Test`案例函数相同名称的固定。

知道这一点，让我们创建我们的第一个`Test`案例：

1.  导航到`Test/Model`文件夹。

1.  创建一个名为`Registry.php`的新`Test`类。

1.  添加以下基本代码（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/Registry.php`）：

```php
<?php
class Mdg_Giftregistry_Test_Model_Registry extends EcomDev_PHPUnit_Test_Case
{
    /**
     * Listing available registries
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
    public function registryList()
    {

    }
}
```

我们刚刚创建了基本函数，但还没有添加任何逻辑。在这之前，让我们先看看什么构成了一个`Test`案例。

一个`Test`案例通过使用断言来评估和测试我们的代码。断言是我们的`Test`案例从父`TestCase`类继承的特殊函数。在默认可用的断言中，我们有：

+   `assertEquals()`

+   `assertGreaterThan()`

+   `assertGreaterThanOrEqual()`

+   `assertLessThan()`

+   `assertLessThanOrEqual()`

+   `assertTrue()`

现在，如果我们只使用这些类型的断言来测试 Magento 代码，可能会变得困难甚至不可能。这就是`Ecomdev_PHPUnit`发挥作用的地方。

这个扩展不仅将 PHPUnit 与 Magento 整合得很好，遵循他们的标准，还在 PHPUnit 测试中添加了 Magento 特定的断言。让我们来看看扩展添加的一些断言：

+   `assertEventDispatched()`

+   `assertBlockAlias()`

+   `assertModelAlias()`

+   `assertHelperAlias()`

+   `assertModuleCodePool()`

+   `assertModuleDepends()`

+   `assertConfigNodeValue()`

+   `assertLayoutFileExists()`

这些只是可用的一些断言，正如你所看到的，它们为构建全面的测试提供了很大的力量。

现在我们对 PHPUnit 的`Test`案例有了更多了解，让我们继续创建我们的第一个 Magento `Test`案例：

1.  导航到之前创建的`Registry.php`测试案例类。

1.  在`registryList()`函数内添加以下代码（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/Registry.php`）：

```php
    /**
     * Listing available registries
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
    public function registryList()
    {
        $registryList = Mage::getModel('mdg_giftregistry/entity')->getCollection();
        $this->assertEquals(
            2,
            $registryList->count()
        );
    }
```

这是一个非常基本的测试；我们所做的就是加载一个注册表集合。在这种情况下，所有的注册表都是可用的，然后他们运行一个断言来检查集合计数是否匹配。

然而，这并不是很有用。如果我们能够只加载属于特定用户（我们的测试用户）的注册表，并检查集合大小，那将更好。因此，让我们稍微改变一下代码：

文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/Registry.php`。参考以下代码：

```php
    /**
     * Listing available registries
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
    public function registryList()
    {
        $customerId = 1;
        $registryList = Mage::getModel('mdg_giftregistry/entity')
->getCollection()
->addFieldToFilter('customer_id', $customerId);
        $this->assertEquals(
            2,
            $registryList->count()
        );
    }
```

仅仅通过改变几行代码，我们创建了一个测试，可以检查我们的注册表集合是否正常工作，并且是否正确地链接到客户记录。

在你的 shell 中运行以下命令：

```php
**$ phpunit**

```

如果一切如预期般进行，我们应该看到以下输出：

```php
**PHPUnit 3.4 by Sebastian Bergmann**
**.**
**Time: 1 second**
**Tests: 1, Assertions: 1, Failures 0**

```

### 注意

您还可以运行`$phpunit`—colors 以获得更好的输出。

现在，我们只需要一个测试来验证注册表项是否正常工作：

1.  导航到之前创建的`Registry.php`测试案例类。

1.  在`registryItemsList()`函数内添加以下代码（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/Registry.php`）：

```php
    /**
     * Listing available items for a specific registry
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
    public function registryItemsList()
    {
        $customerId = 1;
        $registry   = Mage::getModel('mdg_giftregistry/entity')
->loadByCustomerId($customerId);

        $registryItems = $registry->getItems();
        $this->assertEquals(
            3,
            $registryItems->count()
        );
    }
```

我们还需要一个新的 fixture 来配合我们的新`Test`案例：

1.  导航到`Test/Model`文件夹。

1.  打开`Registry`文件夹。

1.  创建一个名为`registryItemsList.yaml`的新文件（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/fixtures/ registryItemsList.yaml`）：

```php
  website: # Initialize websites
    - website_id: 2
      code: default
      name: Test Website
      default_group_id: 2
  group: # Initializes store groups
    - group_id: 2
      website_id: 2
      name: Test Store Group
      default_store_id: 2
      root_category_id: 2 # Default Category
  store: # Initializes store views
    - store_id: 2
      website_id: 2
      group_id: 2
      code: default
      name: Default Test Store
      is_active: 1
eav:
   customer_customer:
     - entity_id: 1
       entity_type_id: 3
       website_id: 2
       email: test@magentotest.com
       group_id: 2
       store_id: 2
       is_active: 1
   mdg_giftregistry_entity:
     - entity_id: 1
       customer_id: 1
       type_id: 2
       website_id: 2
       event_date: 12/12/2012
       event_country: Canada
       event_location: Dundas Square
       created_at: 21/12/2012
   mdg_giftregistry_item:
     - item_id: 1
       registry_id: 1
       product_id: 1
     - item_id: 2
       registry_id: 1
       product_id: 2
     - item_id: 3
       registry_id: 1
       product_id: 3 
```

让我们运行我们的测试套件：

```php
**$phpunit --colors**

```

我们应该看到两个测试都通过了：

```php
PHPUnit 3.4 by Sebastian Bergmann
.
Time: 4 second
Tests: 2, Assertions: 2, Failures 0
```

最后，让我们用正确的期望值替换我们的硬编码变量：

1.  导航到`Module Test/Model`文件夹。

1.  打开`Registry`文件夹。

1.  在`Registry`文件夹内，创建一个名为`expectations`的新文件夹。

1.  创建一个名为`registryList.yaml`的新文件（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/expectations/registryList.yaml`）。

```php
count: 2
```

是不是很容易？好吧，它是如此容易，以至于我们将再次为`registryItemsList`测试案例做同样的事情：

1.  导航到`Module Test/Model`文件夹。

1.  打开`Registry`文件夹。

1.  在`expectations`文件夹中创建一个名为`registryItemsList.yaml`的新文件（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/expectations/registryItemsList.yaml`）：

```php
count: 3
```

最后，我们需要做的最后一件事是更新我们的`Test`案例类以使用期望。确保更新文件具有以下代码（文件位置为`app/code/local/Mdg/Giftregistry/Test/Model/Registry.php`）：

```php
<?php
class Mdg_Giftregistry_Test_Model_Registry extends EcomDev_PHPUnit_Test_Case
{
    /**
     * Product price calculation test
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
    public function registryList()
    {
        $customerId = 1;
        $registryList = Mage::getModel('mdg_giftregistry/entity')
                ->getCollection()
                ->addFieldToFilter('customer_id', $customerId);
        $this->assertEquals(
            $this->_getExpectations()->getCount(),$this->_getExpectations()->getCount(),
            $registryList->count()
        );
    }
    /**
     * Listing available items for a specific registry
     *
     * @test
     * @loadFixture
     * @doNotIndexAll
     * @dataProvider dataProvider
     */
    public function registryItemsList()
    {
        $customerId = 1;
        $registry   = Mage::getModel('mdg_giftregistry/entity')->loadByCustomerId($customerId);

        $registryItems = $registry->getItems();
        $this->assertEquals(
            $this->_getExpectations()->getCount(),
            $registryItems->count()
        );
    }
}
```

这里唯一的变化是，我们用期望值替换了断言中的硬编码值。如果我们需要进行任何更改，我们不需要更改我们的代码；我们只需更新期望和固定装置。

## 使用 Mink 进行功能测试

到目前为止，我们已经学会了如何对我们的代码运行单元测试，虽然单元测试非常适合测试代码和逻辑的各个部分，但对于像 Magento 这样的大型应用程序来说，从用户的角度进行测试是很重要的。

### 注意

功能测试主要涉及黑盒测试，不关心应用程序的源代码。

为了做到这一点，我们可以使用 Mink。Mink 是一个简单的 PHP 库，可以虚拟化 Web 浏览器。Mink 通过使用不同的驱动程序来工作。它支持以下驱动程序：

+   `GoutteDriver`：这是 Symfony 框架的创建者编写的纯 PHP 无头浏览器

+   `SahiDriver`：这是一个新的 JS 浏览器控制器，正在迅速取代 Selenium

+   `ZombieDriver`：这是一个在`Node.js`中编写的浏览器仿真器，目前只限于一个浏览器（Chromium）

+   `SeleniumDriver`：这是目前最流行的浏览器驱动程序；原始版本依赖于第三方服务器来运行测试

+   `Selenium2Driver`：Selenium 的当前版本在 Python、Ruby、Java 和 C#中得到了充分支持

### Magento Mink 安装和设置

使用 Mink 与 Magento 非常容易，这要归功于 Johann Reinke，他创建了一个 Magento 扩展，方便了 Mink 与 Magento 的集成。

我们将使用 Modgit 来安装这个扩展，Modgit 是一个受 Modman 启发的模块管理器。Modgit 允许我们直接从 GitHub 存储库部署 Magento 扩展，而无需创建符号链接。

安装 Modgit 只需三行代码即可完成：

```php
**wget -O modgit https://raw.github.com/jreinke/modgit/master/modgit**
**chmod +x modgit**
**sudo mv modgit /usr/local/bin**

```

是不是很容易？现在我们可以继续安装 Magento Mink，我们应该感谢 Modgit，因为这样甚至更容易：

1.  转到 Magento 根目录。

1.  运行以下命令：

```php
**modgit init**
**modgit -e README.md clone mink https://github.com/jreinke/magento-mink.git**

```

就是这样。Modgit 将负责直接从 GitHub 存储库安装文件。

# 创建我们的第一个测试

`Mink`测试也存储在`Test`文件夹中。让我们创建`Mink`测试类的基本骨架：

1.  导航到我们模块根目录下的`Test`文件夹。

1.  创建一个名为`Mink`的新目录。

1.  在`Mink`目录中，创建一个名为`Registry.php`的新 PHP 类。

1.  复制以下代码（文件位置为`app/code/local/Mdg/Giftregistry/Test/Mink/Registry.php`）：

```php
<?php
class Mdg_Giftregistry_Test_Mink_Registry extends JR_Mink_Test_Mink 
{   
    public function testAddProductToRegistry()
    {
        $this->section('TEST ADD PRODUCT TO REGISTRY');
        $this->setCurrentStore('default');
        $this->setDriver('goutte');
        $this->context();

        // Go to homepage
        $this->output($this->bold('Go To the Homepage'));
        $url = Mage::getStoreConfig('web/unsecure/base_url');
        $this->visit($url);
        $category = $this->find('css', '#nav .nav-1-1 a');
        if (!$category) {
            return false;
        }

        // Go to the Login page
        $loginUrl = $this->find('css', 'ul.links li.last a');
        if ($loginUrl) {
            $this->visit($loginUrl->getAttribute('href'));
        }

        $login = $this->find('css', '#email');
        $pwd = $this->find('css', '#pass');
        $submit = $this->find('css', '#send2');

        if ($login && $pwd && $submit) {
            $email = 'user@example.com';
            $password = 'password';
            $this->output(sprintf("Try to authenticate '%s' with password '%s'", $email, $password));
            $login->setValue($email);
            $pwd->setValue($password);
            $submit->click();
            $this->attempt(
                $this->find('css', 'div.welcome-msg'),
                'Customer successfully logged in',
                'Error authenticating customer'
            );
        }

        // Go to the category page
        $this->output($this->bold('Go to the category list'));
        $this->visit($category->getAttribute('href'));
        $product = $this->find('css', '.category-products li.first a');
        if (!$product) {
            return false;
        }

        // Go to product view
        $this->output($this->bold('Go to product view'));
        $this->visit($product->getAttribute('href'));
        $form = $this->find('css', '#product_registry_form');
        if ($form) {
            $addToCartUrl = $form->getAttribute('action');
            $this->visit($addToCartUrl);
            $this->attempt(
                $this->find('css', '#btn-add-giftregistry'),
                'Product added to gift registry successfully',
                'Error adding product to gift registry'
            );
        }
    }
}
```

仅仅乍一看，你就可以看出这个功能测试与我们之前构建的单元测试有很大不同，尽管看起来代码很多，但实际上很简单。之前的测试已经在代码块中完成了。让我们分解一下之前的测试在做什么：

+   设置浏览器驱动程序和当前商店

+   转到主页并检查有效的类别链接

+   尝试以测试用户身份登录

+   转到类别页面

+   打开该类别上的第一个产品

+   尝试将产品添加到客户的礼品注册表

### 注意

这个测试做了一些假设，并期望在现有的礼品注册表中有一个有效的客户。

在创建`Mink`测试时，我们必须牢记一些考虑因素：

+   每个测试类必须扩展`JR_Mink_Test_Mink`

+   每个测试函数必须以 test 关键字开头

最后，我们唯一需要做的就是运行我们的测试。我们可以通过进入命令行并运行以下命令来实现这一点：

```php
**$ php shell/mink.php**

```

如果一切顺利，我们应该看到类似以下输出：

```php
---------------------- SCRIPT START ---------------------------------
Found 1 file
-------------- TEST ADD PRODUCT TO REGISTRY -------------------------
Switching to store 'default'
Now using Goutte driver
----------------------------------- CONTEXT ------------------------------------
website: base, store: default
Cache info:
config            Disabled  N/A       Configuration
layout            Disabled  N/A       Layouts
block_html        Disabled  N/A       Blocks HTML output
translate         Disabled  N/A       Translations
collections       Disabled  N/A       Collections Data
eav               Disabled  N/A       EAV types and attributes
config_api        Disabled  N/A       Web Services Configuration
config_api2       Disabled  N/A       Web Services Configuration
ecomdev_phpunit   Disabled  N/A       Unit Test Cases

Go To the Homepage [OK]
Try to authenticate user@example.com with password password [OK]
Go to the category list [OK]
Go to product view [OK]
Product added to gift registry successfully

```

# 总结

在本章中，我们介绍了 Magento 测试的基础知识。本章的目的不是构建复杂的测试或深入讨论，而是让我们初步了解并清楚地了解我们可以做些什么来测试我们的扩展。

本章我们涵盖了几个重要的主题，通过拥有适当的测试套件和工具，可以帮助我们避免未来的头痛，并提高我们代码的质量。

在下一章，我们将学习如何打包和分发自定义代码和扩展。


# 第八章：部署和分发

欢迎来到本书的最后一章；我们已经走了很远，并且在这个过程中学到了很多。到目前为止，您应该清楚地了解了为 Magento 工作和开发自定义扩展所涉及的一切。

嗯，几乎一切，就像其他 Magento 开发人员一样，您的代码最终需要被推广到生产环境，或者可能需要打包进行分发；在本章中，我们将看到可用于我们的不同技术、工具和策略。

本章的最终目标是为您提供工具和技能，使您能够自信地进行部署，几乎没有停机时间。

# 通往零停机部署的道路

对于开发人员来说，将产品部署到生产环境可能是最令人害怕的任务之一，往往情况不会很好。

但是什么是零停机部署？嗯，就是自信地将代码部署到生产环境，知道代码经过了适当的测试并且准备就绪，这是所有 Magento 开发人员应该追求的理想。

这不是通过单一的流程或工具实现的，而是通过一系列技术、标准和工具的组合。在本章中，我们将学习以下内容：

+   通过 Magento Connect 分发我们的扩展

+   版本控制系统在部署中的作用

+   分支和合并更改的正确实践

## 从头开始做对

在上一章中，我们学到了测试不仅可以增强我们的工作流程，还可以避免未来的麻烦。单元测试、集成测试和自动化工具都可以确保我们的代码经过了适当的测试。

编写测试意味着不仅仅是组织一些测试并称之为完成；我们负责考虑可能影响我们代码的所有可能边缘情况，并为每种情况编写测试。

## 确保所见即所得

在本书的第一章中，我们立即开始设置我们的开发环境，这是一项非常重要的任务。为了确保我们交付的代码是质量和经过测试的，我们必须能够在尽可能接近生产环境的环境中开发和测试我们的代码。

我将通过 Magento 早期的一个例子来说明这个环境的重要性。我听说这种情况发生了好几次；开发人员在他们的本地环境中从头开始创建新的扩展，完成开发并在本地暂存环境中进行测试，一切似乎都正常工作。

常见的工作流程之一是：

+   在开发人员的本地机器上开始开发，该机器运行着一个接近生产环境的虚拟机

+   在尽可能接近生产环境的暂存环境上测试和批准更改

+   最后，将更改部署到生产环境

现在是时候将他们的代码推广到生产环境了，他们充满信心地这样做了；当然，在本地是可以工作的，因此它也必须在生产环境中工作，对吧？在这些特定情况下，情况并非如此；相反的是，新代码加载到生产环境后，商店崩溃了，说自动加载程序无法找到该类。

发生了什么？嗯，问题在于开发人员的本地环境是 Windows，扩展文件夹的名称是 CamelCase，例如`MyExtension`，但在类名内部他们使用的是大写文本（`Myextension`）。

现在在 Windows 上这将正常工作，因为文件不区分大写、首字母大写或小写的文件夹名称；而大多数 Web 服务器一样的基于 Unix 的系统会区分文件夹和文件的命名。

尽管这个例子看起来可能很愚蠢，但它很好地说明了标准化开发环境的必要性；Magento 安装中有很多部分和“移动的部件”。PHP 的不同版本或者在生产环境中启用的额外 Apache 模块，但在暂存环境中没有启用，可能会产生天壤之别。

### 注意

在[`www.magedevguide.com/naming-conventions`](http://www.magedevguide.com/naming-conventions)了解更多关于 Magento 命名约定的信息。

## 准备好意味着准备好

但是当我们说我们的代码实际上已经准备好投入生产时，准备好到底意味着什么呢？每个开发者可能对准备好和完成实际上意味着什么有不同的定义。在开发新模块或扩展 Magento 时，我们应该始终定义这个特定功能/代码的准备好意味着什么。

所以我们现在有所进展，我们知道为了将代码传递到生产环境，我们必须做以下事情：

1.  测试我们的代码，并确保我们已经涵盖了所有边缘情况。

1.  确保代码符合标准和指南。

1.  确保它已经在尽可能接近生产环境的环境中进行了测试和开发。

# 版本控制系统和部署

**版本控制系统**（**VCSs**）是任何开发者的命脉，尽管 Git 和 SVN 的支持者之间可能存在一些分歧（没有提到 Mercurial 的人），但基本功能仍然是一样的。

让我们快速了解一下每种版本控制系统之间的区别，以及它们的优势和劣势。

## SVN

这是一个强大的系统，已经存在了相当长的时间，非常有名并且被广泛使用。

**Subversion**（**SVN**）是一个集中式的版本控制系统；这意味着有一个被认为是“好”的单一主要源，所有开发者都从这个中央源检出和推送更改。

尽管这使得更改更容易跟踪和维护，但它也有一个严重的缺点。分散也意味着我们必须与中央仓库保持不断的通信，因此无法远程工作或在没有互联网连接的情况下工作。

![SVN](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_01.jpg)

## Git

Git 是一个更年轻的版本控制系统，由于被开源社区广泛采用和 Github 的流行（[www.github.com](http://www.github.com)），它已经流行了几年。

SVN 和 Git 之间的一个关键区别是，Git 是一个分散式版本控制系统，这意味着没有中央管理机构或主仓库；每个开发者都有完整的仓库副本可供本地使用。

Git 是分散式的，这使得 Git 比其他版本控制系统更快，并且具有更好和更强大的分支系统；此外，可以远程工作或在没有互联网连接的情况下工作。

![Git](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_02.jpg)

无论我们选择哪种版本控制系统，任何版本控制系统最强大（有时被忽视）的功能都是分支或创建分支的能力。

分支允许我们进行实验和开发新功能，而不会破坏我们主干或主代码中的稳定代码；创建分支需要我们对当前主干/主代码进行快照，然后进行任何更改和测试。

现在，分支只是方程式的一部分；一旦我们对我们的代码更改感到满意，并且已经正确测试了每个边缘情况，我们需要一种重新整合这些更改到我们主要代码库的方法。合并通过运行几个命令，使我们能够重新整合所有我们的分支修改。

通过将分支集成和合并更改到我们的工作流程中，我们获得了灵活性和自由，可以在不干扰实验性或正在进行中的代码的情况下，处理不同的更改、功能和错误修复。

此外，正如我们将在下一节中学到的，版本控制可以帮助我们进行无缝的推广，并轻松地在多个 Magento 安装中保持我们的代码最新。

# 分发

您可能希望自由分发您的扩展或将其商业化，但是如何能够保证每次正确安装代码而无需自己操作呢？更新呢？并非所有商店所有者都精通技术或能够自行更改文件。

幸运的是，Magento 自带了自己的包管理器和扩展市场，称为 Magento Connect。

Magento Connect 允许开发人员和解决方案合作伙伴与社区分享其开源和商业贡献，并不仅限于自定义模块；我们可以在 Magento Connect 市场中找到以下类型的资源：

+   模块

+   语言包

+   自定义主题

## 打包我们的扩展

Magento Connect 的核心功能之一是允许我们直接从 Magento 后端打包我们的扩展。

要打包我们的扩展，请执行以下步骤：

1.  登录 Magento 后端。

1.  从后端，选择**系统** | **Magento Connect** | **打包扩展**。![打包我们的扩展](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_03.jpg)

正如我们所看到的，**创建扩展** **包**部分由六个不同的子部分组成，我们将在下面介绍。

### 包信息

**包信息**用于指定一般扩展信息，例如名称、描述和支持的 Magento 版本，如下所示：

+   **名称**：标准做法是保持名称简单，只使用单词

+   **渠道**：这指的是扩展的代码池；正如我们在前几章中提到的，为了分发设计的扩展应该使用“社区”渠道

+   **支持的版本**：选择我们的扩展应该支持的 Magento 版本

+   **摘要**：此字段包含扩展的简要描述，用于扩展审核过程

+   **描述**：这里有扩展和其功能的详细描述

+   **许可证**：这是用于此扩展的许可证；一些可用的选项是：

+   **开放软件许可证**（**OSL**）

+   **Mozilla 公共许可证**（**MPL**）

+   **麻省理工学院许可证**（**MITL**）

+   **GNU 通用公共许可证**（**GPL**）

+   如果您的扩展要进行商业分发，则使用任何其他许可证

+   **许可证 URI**：这是许可证文本的链接

### 注意

有关不同许可类型的更多信息，请访问[`www.magedevguide.com/license-types`](http://www.magedevguide.com/license-types)。

### 发布信息

以下截图显示了**发布信息**屏幕：

![发布信息](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_04.jpg)

**发布信息**部分包含有关当前软件包发布的重要数据：

+   **发布版本**：初始发布可以是任意数字，但是，重要的是每次发布都要递增版本号。Magento Connect 不会允许您两次更新相同的版本。

+   **发布稳定性**：有三个选项 - **稳定**，**Beta**和**Alpha**。

+   **注释**：在这里，我们可以输入所有特定于发布的注释，如果有的话。

### 作者

以下截图显示了**作者**屏幕：

![作者](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_05.jpg)

在此部分，指定了有关作者的信息；每个作者的信息都有以下字段：

+   **名称**：作者的全名

+   **用户**：Magento 用户名

+   **电子邮件**：联系电子邮件地址

### 依赖项

以下截图显示了**依赖项**屏幕：

![依赖项](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_06.jpg)

在打包 Magento 扩展时使用了三种类型的依赖关系：

+   **PHP 版本**：在这里，我们需要在**最小**和**最大**字段中指定此扩展支持的 PHP 的最小和最大版本

+   **软件包**：这用于指定此扩展所需的任何其他软件包

+   **扩展**：在这里，我们可以指定我们的扩展是否需要特定的 PHP 扩展才能工作

如果软件包依赖关系未满足，Magento Connect 将允许我们安装所需的扩展；对于 PHP 扩展，Magento Connect 将抛出错误并停止安装。

### 内容

以下截图显示了**内容**屏幕：

![内容](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_07.jpg)

**内容**部分允许我们指定构成扩展包的每个文件和文件夹。

### 注意

这是扩展打包过程中最重要的部分，也是最容易出错的部分。

每个内容条目都有以下字段：

+   **目标**：这是目标基本目录，用于指定搜索文件的基本路径。以下选项可用：

+   **Magento 核心团队模块文件 - ./app/code/core**

+   **Magento 本地模块文件 - ./app/code/local**

+   **Magento 社区模块文件 - ./app/code/community**

+   **Magento 全局配置 - ./app/etc**

+   **Magento 区域语言文件 - ./app/locale**

+   **Magento 用户界面（布局、模板）- ./app/design**

+   **Magento 库文件 - ./lib**

+   **Magento 媒体库 - ./media**

+   **Magento 主题皮肤（图像、CSS、JS）- ./skin**

+   **Magento 其他可访问的 Web 文件 - ./**

+   **Magento PHPUnit 测试 - ./tests**

+   **Magento 其他 - ./**

+   **路径**：这是相对于我们指定目标的文件名和/或路径

+   **类型**：对于此字段，我们有两个选项 - **文件**或**递归目录**

+   **包括**：此字段采用正则表达式，允许我们指定要包括的文件

+   **忽略**：此字段采用正则表达式，允许我们指定要排除的文件

### 加载本地包

以下屏幕截图显示了**加载本地包**的屏幕：

![加载本地包](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_08.jpg)

此部分将允许我们加载打包的扩展；由于我们尚未打包任何扩展，因此列表目前为空。

让我们继续打包我们的礼品注册扩展。确保填写所有字段，然后单击**保存数据并创建包**；这将在`magento_root/var/connect/`文件夹中打包和保存扩展。

扩展包文件包含所有源文件和所需的源代码；此外，每个包都会创建一个名为`package.xml`的新文件。此文件包含有关扩展的所有信息以及文件和文件夹的详细结构。

# 发布我们的扩展

最后，为了使我们的扩展可用，我们必须在 Magento Connect 中创建一个扩展配置文件。要创建扩展配置文件，请执行以下步骤：

1.  登录[magentocommerce.com](http://magentocommerce.com)。

1.  单击**我的帐户**链接。

1.  单击左侧导航中的**开发人员**链接。

1.  单击**添加新扩展**。

**添加新扩展**窗口看起来像以下屏幕截图：

![发布我们的扩展](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_09.jpg)

重要的是要注意，**扩展标题**字段必须是您在生成包时使用的确切名称。

创建扩展配置文件后，我们可以继续上传我们的扩展包；所有字段应与扩展打包过程中指定的字段匹配。

![发布我们的扩展](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mgt-php-dev-gd/img/3060OS_08_10.jpg)

最后，一旦完成，我们可以单击**提交审批**按钮。扩展可以具有以下状态：

+   **已提交**：这意味着扩展已提交审核

+   **未获批准**：这意味着扩展存在问题，并且您还将收到一封解释为什么扩展未获批准的电子邮件

+   **在线**：这意味着扩展已获批准，并可通过 Magento Connect 获得

+   **离线**：这意味着您可以随时从您的帐户**扩展管理器**中将扩展下线

# 摘要

在本章中，我们学习了如何部署和共享我们的自定义扩展。我们可以使用许多不同的方法来共享和部署我们的代码到生产环境。

这是我们书的最后一章；我们已经学到了很多关于 Magento 开发的知识，虽然我们已经涵盖了很多内容，但这本书只是您漫长旅程的一个起点。

Magento 不是一个容易学习的框架，虽然可能是一次令人生畏的经历，但我鼓励您继续尝试和学习。
