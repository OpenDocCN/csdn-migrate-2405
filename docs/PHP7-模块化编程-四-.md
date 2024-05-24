# PHP7 模块化编程（四）

> 原文：[`zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f`](https://zh.annas-archive.org/md5/ff0acc039cf922de0886cd9283ec3d9f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：构建运输模块

运输模块，以及“支付”模块，为我们的网店提供了进一步的销售功能的基础。当我们到达即将到来的“销售”模块的结账过程时，它将使我们能够选择运输方式。与“支付”类似，`shipment`可能是静态的和动态的。静态可能意味着固定的定价值，甚至是通过一些简单条件计算出来的值，动态通常意味着与外部 API 服务的连接。

在本章中，我们将接触到两种类型，并看看如何为实施`shipment`模块设置基本结构。

在本章中，我们将涵盖`shipment`模块的以下主题：

+   要求

+   依赖关系

+   实施

+   单元测试

+   功能测试

# 要求

应用要求，在第四章中定义，*模块化网店应用的需求规范*，并没有给出我们需要实施的运输方式的具体信息。因此，在本章中，我们将开发两种运输方式：动态费率运输和固定费率运输。动态费率运输用作将运输方式连接到真实运输处理器（如 UPS、FedEx 等）的方式。但是，它实际上不会连接到任何外部 API。

理想情况下，我们希望通过类似以下的接口来实现：

```php
namespace Foggyline\SalesBundle\Interface;

interface Shipment
{
  function getInfo($street, $city, $country, $postcode, $amount, $qty);
  function process($street, $city, $country, $postcode, $amount, $qty);
}
```

然后，`getInfo`方法可以用于获取给定订单信息的可用交付选项，而处理方法将处理所选的交付选项。例如，我们可能会有一个 API 返回“当天送货（$9.99）”和“标准送货（$4.99）”作为动态费率运输方式的交付选项。

拥有这样一个运输接口将要求拥有我们尚未开发的`SalesBundle`模块。因此，我们将继续使用 Symfony 控制器处理过程方法和处理`getInfo`方法的服务来处理我们的运输方式。

与上一章中的支付方式一样，我们将通过标记的 Symfony 服务公开我们的`getInfo`方法。我们将用于运输方式的标记是`shipment_method`。在结账过程中，`SalesBundle`模块将获取所有标记为`shipment_method`的服务，并在内部使用它们来获取可用的运输方式列表。

# 依赖关系

我们正在以另一种方式构建模块。也就是说，我们在了解`SalesBundle`模块的任何信息之前就构建它，这是唯一会使用它的模块。考虑到这一点，`shipment`模块不依赖于任何其他模块。但是，构建`SalesBundle`模块然后公开一些`shipment`模块可能使用的接口可能更方便。

# 实施

我们将首先创建一个名为`Foggyline\ShipmentBundle`的新模块。我们将通过运行以下命令来使用控制台完成：

```php
**php bin/console generate:bundle --namespace=Foggyline/ShipmentBundle**

```

该命令触发一个交互式过程，沿途询问我们几个问题，如下所示：

![实施](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_10_01.jpg)

完成后，文件`app/AppKernel.php`和`app/config/routing.yml`将自动修改。在`$bundles`数组下添加了`AppKernel`类的`registerBundles`方法：

```php
new Foggyline\PaymentBundle\FoggylineShipmentBundle(),
```

`routing.yml`文件已更新为以下条目：

```php
foggyline_payment:
  resource: "@FoggylineShipmentBundle/Resources/config/routing.xml"
  prefix:   /
```

为了避免与核心应用程序代码冲突，我们需要将`prefix: /`更改为`prefix: /shipment/`。

## 创建固定费率运输服务

定价运输服务将提供固定的运输方式，我们的“销售”模块将在结账过程中使用。它的作用是提供运输方式标签、代码、交付选项和处理 URL。

我们将首先在`src/Foggyline/ShipmentBundle/Resources/config/services.xml`文件的`services`元素下定义以下服务：

```php
<service id="foggyline_shipment.dynamicrate_shipment"class="Foggyline\ShipmentBundle\Service\DynamicRateShipment">
  <argument type="service" id="router"/>
  <tag name="shipment_method"/>
</service>
```

这个`service`只接受一个参数：`router`。`tagname`的值设置为`shipment_method`，因为我们的`SalesBundle`模块将根据分配给服务的`shipment_method`标签来寻找运输方法。

我们现在将在`src/Foggyline/ShipmentBundle/Service/FlatRateShipment.php`文件中创建实际的`service`类，如下所示：

```php
namespace Foggyline\ShipmentBundle\Service;
class FlatRateShipment
{
  private $router;

  public function __construct(
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->router = $router;
  }

  public function getInfo($street, $city, $country, $postcode, $amount, $qty)
  {
    return array(
      'shipment' => array(
        'title' =>'Foggyline FlatRate Shipment',
        'code' =>'flat_rate',
        'delivery_options' => array(
        'title' =>'Fixed',
        'code' =>'fixed',
        'price' => 9.99
      ),
      'url_process' => $this->router->generate('foggyline_shipment_flat_rate_process'),
    )
  ;
  }
}
```

`getInfo`方法将为我们未来的`SalesBundle`模块提供必要的信息，以便它构建结账过程的`shipment`步骤。它接受一系列参数：`$street`、`$city`、`$country`、`$postcode`、`$amount`和`$qty`。我们可以将这些视为统一的运输接口的一部分。在这种情况下，`delivery_options`返回一个固定值。`url_process`是我们将插入所选运输方法的 URL。我们未来的`SalesBundle`模块将仅仅对这个 URL 进行一个 AJAX POST，期望得到一个成功或错误的 JSON 响应，这与我们想象中使用支付方法的方式非常相似。

## 创建固定费率运输控制器和路由

我们通过向`src/Foggyline/ShipmentBundle/Resources/config/routing.xml`文件添加以下路由定义来编辑它：

```php
<route id="foggyline_shipment_flat_rate_process"path="/flat_rate/process">
  <default key="_controller">FoggylineShipmentBundle:FlatRate:process
  </default>
</route>
```

然后我们创建一个`src/Foggyline/ShipmentBundle/Controller/FlatRateController.php`文件，内容如下：

```php
namespace Foggyline\ShipmentBundle\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class FlatRateController extends Controller
{
  public function processAction(Request $request)
  {
    // Simulating some transaction id, if any
    $transaction = md5(time() . uniqid());

    return new JsonResponse(array(
      'success' => $transaction
    ));
  }
}
```

我们现在应该能够访问一个 URL，比如`/app_dev.php/shipment/flat_rate/process`，并看到`processAction`的输出。这里给出的实现是虚拟的。对我们来说重要的是，`sales`模块将在其结账过程中，通过`shipment_method`标记的服务的`getInfo`方法推送任何可能的`delivery_options`。这意味着结账过程应该显示固定费用运输作为一个选项。结账的行为将被编码，如果没有选择`shipment`方法，它将阻止结账过程继续进行。当我们到达`SalesBundle`模块时，我们将更详细地讨论这一点。

## 创建动态费率支付服务

除了固定费用运输方法，让我们继续定义另一种动态运输，称为动态费率。

我们将首先在`src/Foggyline/ShipmentBundle/Resources/config/services.xml`文件的`services`元素下定义以下服务：

```php
<service id="foggyline_shipment.dynamicrate_shipment"class="Foggyline\ShipmentBundle\Service\DynamicRateShipment">
  <argument type="service" id="router"/>
  <tag name="shipment_method"/>
</service>
```

在这里定义的`service`只接受一个`router`参数。`tag name`属性与固定费用运输服务相同。

然后我们将创建`src/Foggyline/ShipmentBundle/Service/DynamicRateShipment.php`文件，内容如下：

```php
namespace Foggyline\ShipmentBundle\Service;

class DynamicRateShipment
{
  private $router;

  public function __construct(
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->router = $router;
  }

  public function getInfo($street, $city, $country, $postcode, $amount, $qty)
  {
    return array(
      'shipment' => array(
        'title' =>'Foggyline DynamicRate Shipment',
        'code' =>'dynamic_rate_shipment',
        'delivery_options' => $this->getDeliveryOptions($street, $city, $country, $postcode, $amount, $qty),
        'url_process' => $this->router->generate('foggyline_shipment_dynamic_rate_process'),
      )
    );
  }

  public function getDeliveryOptions($street, $city, $country, $postcode, $amount, $qty)
  {
    // Imagine we are hitting the API with: $street, $city, $country, $postcode, $amount, $qty
    return array(
      array(
        'title' =>'Same day delivery',
        'code' =>'dynamic_rate_sdd',
        'price' => 9.99
      ),
      array(
        'title' =>'Standard delivery',
        'code' =>'dynamic_rate_sd',
        'price' => 4.99
      ),
    );
  }
}
```

与固定费用运输不同，这里`getInfo`方法的`delivery_options`键是由`getDeliveryOptions`方法的响应构建的。该方法是服务内部的，不被想象为公开或作为接口的一部分。我们可以很容易地想象在其中进行一些 API 调用，以便为我们的动态运输方法获取计算费率。

## 创建动态费率运输控制器和路由

一旦动态费率运输服务就位，我们就可以为其创建必要的路由。我们将首先在`src/Foggyline/ShipmentBundle/Resources/config/routing.xml`文件中添加以下路由定义：

```php
<route id="foggyline_shipment_dynamic_rate_process" path="/dynamic_rate/process">
  <default key="_controller">FoggylineShipmentBundle:DynamicRate:process
  </default>
</route>
```

然后我们创建`src/Foggyline/ShipmentBundle/Controller/DynamicRateController.php`文件，内容如下：

```php
namespace Foggyline\ShipmentBundle\Controller;

use Foggyline\ShipmentBundle\Entity\DynamicRate;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;

class DynamicRateController extends Controller
{
  public function processAction(Request $request)
  {
    // Just a dummy string, simulating some transaction id
    $transaction = md5(time() . uniqid());

    if ($transaction) {
      return new JsonResponse(array(
'success' => $transaction
      ));
    }

    return new JsonResponse(array(
      'error' =>'Error occurred while processing DynamicRate shipment.'
    ));
  }
}
```

与固定费率运输类似，这里我们添加了一个简单的虚拟实现过程和方法。传入的`$request`应该包含与服务`getInfo`方法相同的信息，也就是说，它应该有以下参数可用：`$street`、`$city`、`$country`、`$postcode`、`$amount`和`$qty`。方法的响应将在后面的`SalesBundle`模块中使用。我们可以很容易地从这些方法中实现更健壮的功能，但这超出了本章的范围。

# 单元测试

`FoggylineShipmentBundle`模块非常简单。通过提供两个简单的服务和两个简单的控制器，很容易进行测试。

我们将首先在`phpunit.xml.dist`文件的`testsuites`元素下添加以下行：

```php
<directory>src/Foggyline/ShipmentBundle/Tests</directory>
```

有了这个文件，从商店的根目录运行`phpunit`命令应该会检测到我们在`src/Foggyline/ShipmentBundle/Tests/`目录下定义的任何测试。

现在，让我们继续为我们的`FlatRateShipment`服务创建一个测试。我们将创建一个`src/Foggyline/ShipmentBundle/Tests/Service/FlatRateShipmentTest.php`文件，内容如下：

```php
namespace Foggyline\ShipmentBundle\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class FlatRateShipmentTest extends KernelTestCase
{
  private $container;
  private $router;

  private $street = 'Masonic Hill Road';
  private $city = 'Little Rock';
  private $country = 'US';
  private $postcode = 'AR 72201';
  private $amount = 199.99;
  private $qty = 7;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
    $this->router = $this->container->get('router');
  }

  public function testGetInfoViaService()
  {
    $shipment = $this->container->get('foggyline_shipment.flat_rate');

    $info = $shipment->getInfo(
      $this->street, $this->city, $this->country, $this->postcode, $this->amount, $this->qty
    );

    $this->validateGetInfoResponse($info);
  }

  public function testGetInfoViaClass()
  {
    $shipment = new \Foggyline\ShipmentBundle\Service\FlatRateShipment($this->router);

    $info = $shipment->getInfo(
      $this->street, $this->city, $this->country, $this->postcode, $this->amount, $this->qty
    );

    $this->validateGetInfoResponse($info);
  }

  public function validateGetInfoResponse($info)
  {
    $this->assertNotEmpty($info);
    $this->assertNotEmpty($info['shipment']['title']);
    $this->assertNotEmpty($info['shipment']['code']);
    $this->assertNotEmpty($info['shipment']['delivery_options']);
    $this->assertNotEmpty($info['shipment']['url_process']);
  }
}
```

这里运行了两个简单的测试。一个是检查我们是否可以通过容器实例化一个服务，另一个是检查我们是否可以直接这样做。一旦实例化，我们只需调用服务的`getInfo`方法，向其传递一个虚拟地址和订单信息。虽然我们实际上并没有在`getInfo`方法中使用这些数据，但我们需要传递一些东西，否则测试将失败。该方法预期返回一个包含在 shipment 键下的几个关键字的响应，最重要的是`title`、`code`、`delivery_options`和`url_process`。

现在，让我们继续为我们的`DynamicRateShipment`服务创建一个测试。我们将创建一个`src/Foggyline/ShipmentBundle/Tests/Service/DynamicRateShipmentTest.php`文件，内容如下：

```php
namespace Foggyline\ShipmentBundle\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
class DynamicRateShipmentTest extends KernelTestCase
{
  private $container;
  private $router;

  private $street = 'Masonic Hill Road';
  private $city = 'Little Rock';
  private $country = 'US';
  private $postcode = 'AR 72201';
  private $amount = 199.99;
  private $qty = 7;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
    $this->router = $this->container->get('router');
  }

  public function testGetInfoViaService()
  {
    $shipment = $this->container->get('foggyline_shipment.dynamicrate_shipment');
    $info = $shipment->getInfo(
      $this->street, $this->city, $this->country, $this->postcode, $this->amount, $this->qty
    );
    $this->validateGetInfoResponse($info);
  }

  public function testGetInfoViaClass()
  {
    $shipment = new \Foggyline\ShipmentBundle\Service\DynamicRateShipment($this->router);
    $info = $shipment->getInfo(
      $this->street, $this->city, $this->country, $this->postcode, $this->amount, $this->qty
    );

    $this->validateGetInfoResponse($info);
  }

  public function validateGetInfoResponse($info)
  {
    $this->assertNotEmpty($info);
    $this->assertNotEmpty($info['shipment']['title']);
    $this->assertNotEmpty($info['shipment']['code']);

    // Could happen that dynamic rate has none?!
    //$this->assertNotEmpty($info['shipment']['delivery_options']);

    $this->assertNotEmpty($info['shipment']['url_process']);
  }
}
```

这个测试几乎与`FlatRateShipment`服务的测试相同。在这里，我们也有两个简单的测试：一个通过容器获取支付方法，另一个通过类直接获取。不同之处在于我们不再断言`delivery_options`的存在。这是因为真实的 API 请求可能不会根据给定的地址和订单信息返回任何交付选项。

# 功能测试

我们整个模块只有两个控制器类，我们要测试它们的响应。我们要确保`FlatRateController`和`DynamicRateController`类的`process`方法是可访问且有效的。

首先，我们将创建一个`src/Foggyline/ShipmentBundle/Tests/Controller/FlatRateControllerTest.php`文件，内容如下：

```php
namespace Foggyline\ShipmentBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
class FlatRateControllerTest extends WebTestCase
{
  private $client;
  private $router;

  public function setUp()
  {
    $this->client = static::createClient();
    $this->router = $this->client->getContainer()->get('router');
  }

  public function testProcessAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_shipment_flat_rate_process'));
    $this->assertSame(200, $this->client->getResponse()->getStatusCode());
    $this->assertSame('application/json', $this->client->getResponse()->headers->get('Content-Type'));
    $this->assertContains('success', $this->client->getResponse()->getContent());
    $this->assertNotEmpty($this->client->getResponse()->getContent());
  }
}
```

然后，我们将创建一个`src/Foggyline/ShipmentBundle/Tests/Controller/DynamicRateControllerTest.php`文件，内容如下：

```php
namespace Foggyline\ShipmentBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class DynamicRateControllerTest extends WebTestCase
{
  private $client;
  private $router;

  public function setUp()
  {
    $this->client = static::createClient();
    $this->router = $this->client->getContainer()->get('router');
  }

  public function testProcessAction()
  {
    $this->client->request('GET', $this->router->generate('foggyline_shipment_dynamic_rate_process'));
    $this->assertSame(200, $this->client->getResponse()->getStatusCode());
    $this->assertSame('application/json', $this->client->getResponse()->headers->get('Content-Type'));
    $this->assertContains('success', $this->client->getResponse()->getContent());
    $this->assertNotEmpty($this->client->getResponse()->getContent());
  }
}
```

这两个测试几乎是相同的。它们包含一个单一过程操作方法的测试。目前，控制器过程操作方法只是返回一个固定的成功 JSON 响应。我们可以很容易地扩展它以返回不仅仅是一个固定的响应，并且可以伴随着更健壮的功能测试。

# 总结

在本章中，我们构建了一个具有两种运输方法的`shipment`模块。每种运输方法都提供了可用的交付选项。固定费率运输方法在其交付选项下只有一个固定值，而动态费率方法从`getDeliveryOptions`方法中获取其值。我们可以很容易地在`getDeliveryOptions`中嵌入一个真实的运输 API，以提供真正动态的运输选项。

显然，我们在这里缺少官方接口，就像我们在支付方法中一样。然而，这是我们可以随时回来并在我们最终的`final`模块中重构的内容。

与支付方式类似，这里的想法是创建一个最小的结构，展示如何开发一个简单的装运模块以供进一步定制。通过使用`shipment_methodservice`标签，我们有效地为未来的“销售”模块暴露了装运方法。

在接下来的章节中，我们将构建一个“销售”模块，最终将利用我们的“支付”和“装运”模块。


# 第十一章：构建销售模块

销售模块是我们将构建的一系列模块中的最后一个，以便提供一个简单但功能齐全的网络商店应用程序。我们将在目录的基础上添加购物车和结账功能来实现这一点。结账本身最终将利用在前几章中定义的运输和付款服务。这里的整体重点将放在绝对基础上，因为真正的购物车应用程序会采用更加健壮的方法。然而，了解如何以简单的方式将所有内容联系在一起是打开以后实现更加健壮的网络商店应用程序的第一步。

在本章中，我们将介绍销售模块的以下主题：

+   要求

+   依赖关系

+   实施

+   单元测试

+   功能测试

# 要求

应用要求，在第四章中定义，*模块化网络商店应用的需求规范*，为我们提供了一些关于购物车和结账的线框图。基于这些线框图，我们可以推测出我们需要创建哪些类型的实体来实现功能。

以下是所需模块实体的列表：

+   购物车

+   购物车项目

+   订单

+   订单项目

`Cart`实体包括以下属性及其数据类型：

+   `id`：整数，自动递增

+   `customer_id`：字符串

+   `created_at`：日期时间

+   `modified_at`：日期时间

`Cart Item`实体包括以下属性：

+   `id`：整数，自动递增

+   `cart_id`：整数，外键，引用类别`表 id`列

+   `product_id`：整数，外键，引用产品`表 id`列

+   `qty`：字符串

+   `unit_price`：十进制

+   `created_at`：日期时间

+   `modified_at`：日期时间

`Order`实体包括以下属性：

+   `id`：整数，自动递增

+   `customer_id`：整数，外键，引用客户`表 id`列

+   `items_price`：十进制

+   `shipment_price`：十进制

+   `total_price`：十进制

+   `状态`：字符串

+   `customer_email`：字符串

+   `customer_first_name`：字符串

+   `customer_last_name`：字符串

+   `address_first_name`：字符串

+   `address_last_name`：字符串

+   `address_country`：字符串

+   `address_state`：字符串

+   `address_city`：字符串

+   `address_postcode`：字符串

+   `address_street`：字符串

+   `address_telephone`：字符串

+   `payment_method`：字符串

+   `shipment_method`：字符串

+   `created_at`：日期时间

+   `modified_at`：日期时间

`Order Item`实体包括以下属性：

+   `id`：整数，自动递增

+   `sales_order_id`：整数，外键，引用订单`表 id`列

+   `product_id`：整数，外键，引用产品`表 id`列

+   `title`：字符串

+   `qty`：整数

+   `unit_price`：十进制

+   `total_price`：十进制

+   `created_at`：日期时间

+   `modified_at`：日期时间

除了添加这些实体和它们的 CRUD 页面之外，我们还需要覆盖一个负责构建类别菜单和特价商品的核心模块服务。

# 依赖关系

销售模块将在代码中有几个依赖项。这些依赖项指向客户和目录模块。

# 实施

我们首先创建一个名为`Foggyline\SalesBundle`的新模块。我们可以通过控制台运行以下命令来实现：

```php
**php bin/console generate:bundle --namespace=Foggyline/SalesBundle**

```

该命令触发一个交互式过程，在此过程中向我们提出了几个问题，如下所示：

![实施](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_01.jpg)

完成后，`app/AppKernel.php`和`app/config/routing.yml`文件将自动修改。`AppKernel`类的`registerBundles`方法已添加到`$bundles`数组下的以下行：

```php
new Foggyline\PaymentBundle\FoggylineSalesBundle(),
```

`routing.yml`文件已更新，添加了以下条目：

```php
foggyline_payment:
  resource: "@FoggylineSalesBundle/Resources/config/routing.xml"
  prefix:   /
```

为了避免与核心应用程序代码发生冲突，我们需要将`prefix: /`更改为`prefix: /sales/`。

## 创建购物车实体

让我们继续创建一个`Cart`实体。我们可以通过控制台来实现，如下所示：

```php
**php bin/console generate:doctrine:entity**

```

触发交互式生成器，如下所示的屏幕截图：

![创建购物车实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_02.jpg)

这将在`src/Foggyline/SalesBundle/`目录中创建`Entity/Cart.php`和`Repository/CartRepository.php`文件。之后，我们需要更新数据库，以便通过运行以下命令引入`Cart`实体：

```php
**php bin/console doctrine:schema:update --force**

```

有了`Cart`实体，我们可以继续生成`CartItem`实体。

## 创建购物车项目实体

让我们继续创建`CartItem`实体。我们通过使用现在众所周知的`console`命令来完成：

```php
**php bin/console generate:doctrine:entity**

```

触发交互式生成器，如下所示的屏幕截图：

![创建购物车项目实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_03.jpg)

这将在`src/Foggyline/SalesBundle/`目录中创建`Entity/CartItem.php`和`Repository/CartItemRepository.php`。自动生成完成后，我们需要返回并编辑`CartItem`实体，以更新`cart`字段关系如下：

```php
/**
 * @ORM\ManyToOne(targetEntity="Cart", inversedBy="items")
 * @ORM\JoinColumn(name="cart_id", referencedColumnName="id")
 */
private $cart;
```

在这里，我们定义了所谓的*双向一对多*关联。一对多关联中的外键在这种情况下是在多方上定义的，也就是`CartItem`实体。双向映射需要在`OneToMany`关联上使用`mappedBy`属性，在`ManyToOne`关联上使用`inversedBy`属性。在这种情况下，`OneToMany`方是`Cart`实体，因此我们返回`src/Foggyline/SalesBundle/Entity/Cart.php`文件，并添加以下内容：

```php
/**
 * @ORM\OneToMany(targetEntity="CartItem", mappedBy="cart")
 */
private $items;

public function __construct() {
  $this->items = new \Doctrine\Common\Collections\ArrayCollection();
}
```

然后，我们需要更新数据库，以便通过运行以下命令引入`CartItem`实体：

```php
**php bin/console doctrine:schema:update --force**

```

有了`CartItem`实体，我们可以继续生成`Order`实体。

## 创建订单实体

让我们继续创建`Order`实体。我们通过控制台这样做：

```php
**php bin/console generate:doctrine:entity**

```

如果我们尝试提供`FoggylineSalesBundle:Order`作为实体快捷方式名称，生成的输出将会抛出错误，如下所示的屏幕截图：

![创建订单实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_04.jpg)

相反，我们将使用`SensioGeneratorBundle:SalesOrder`作为实体快捷方式名称，并按照以下方式跟随生成器：

![创建订单实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_05.jpg)

接下来是与客户信息相关的其余字段。要更好地了解，请查看以下屏幕截图：

![创建订单实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_06.jpg)

接下来是与订单地址相关的其余字段，如下所示：

![创建订单实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_07.jpg)

值得注意的是，通常我们希望将地址信息提取到自己的表中，即将其作为自己的实体。但是，为了保持简单，我们将继续将其作为`SalesOrder`实体的一部分。

完成后，在`src/Foggyline/SalesBundle/`目录中创建`Entity/SalesOrder.php`和`Repository/SalesOrderRepository.php`文件。之后，我们需要更新数据库，以便通过运行以下命令引入`SalesOrder`实体：

```php
**php bin/console doctrine:schema:update --force**

```

有了`SalesOrder`实体，我们可以继续生成`SalesOrderItem`实体。

## 创建 SalesOrderItem 实体

让我们继续创建`SalesOrderItem`实体。我们通过使用以下`console`命令启动代码生成器：

```php
**php bin/console generate:doctrine:entity**

```

当要求实体快捷方式名称时，我们提供`FoggylineSalesBundle:SalesOrderItem`，然后按照以下屏幕截图中显示的生成器字段定义：

![创建 SalesOrderItem 实体](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/mdl-prog-php7/img/B05460_11_08.jpg)

这将在`src/Foggyline/SalesBundle/`目录中创建`Entity/SalesOrderItem.php`和`Repository/SalesOrderItemRepository.php`文件。自动生成完成后，我们需要返回并编辑`SalesOrderItem`实体，以更新`SalesOrder`字段关系如下：

```php
/**
 * @ORM\ManyToOne(targetEntity="SalesOrder", inversedBy="items")
 * @ORM\JoinColumn(name="sales_order_id", referencedColumnName="id")
 */
private $salesOrder;

/**
 * @ORM\OneToOne(targetEntity="Foggyline\CatalogBundle\Entity\Product")
 * @ORM\JoinColumn(name="product_id", referencedColumnName="id")
 */
private $product;
```

在这里，我们定义了两种类型的关系。第一种是与`$salesOrder`相关的双向一对多关联，这是我们在`Cart`和`CartItem`实体中看到的。第二种是与`$product`相关的单向一对一关联。引用被称为单向，因为`CartItem`引用`Product`，而`Product`不会引用`CartItem`，因为我们不想改变属于另一个模块的东西。

我们仍然需要回到`src/Foggyline/SalesBundle/Entity/SalesOrder.php`文件，并添加以下内容：

```php
/**
 * @ORM\OneToMany(targetEntity="SalesOrderItem", mappedBy="salesOrder")
 */
private $items;

public function __construct() {
  $this->items = new \Doctrine\Common\Collections\ArrayCollection();
}
```

然后我们需要更新数据库，以便通过运行以下命令引入`SalesOrderItem`实体：

```php
**php bin/console doctrine:schema:update --force**

```

有了`SalesOrderItem`实体，我们现在可以开始构建购物车和结账页面。

## 覆盖`add_to_cart_url`服务

`add_to_cart_url`服务最初是在`FoggylineCustomerBundle`中声明的，带有虚拟数据。这是因为在销售功能可用之前，我们需要一种构建产品的添加到购物车 URL 的方法。虽然肯定不是理想的方式，但这是一种可能的方式。

现在我们将使用我们在销售模块中声明的服务来覆盖该服务，以提供正确的添加到购物车 URL。我们首先通过在`src/Foggyline/SalesBundle/Resources/config/services.xml`中定义服务来开始，如下所示：

```php
<service id="foggyline_sales.add_to_cart_url" class="Foggyline\SalesBundle\Service\AddToCartUrl">
  <argument type="service" id="doctrine.orm.entity_manager"/>
  <argument type="service" id="router"/>
</service>
```

然后创建`src/Foggyline/SalesBundle/Service/AddToCartUrl.php`，内容如下：

```php
namespace Foggyline\SalesBundle\Service;

class AddToCartUrl
{
  private $em;
  private $router;

  public function __construct(
    \Doctrine\ORM\EntityManager $entityManager,
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->em = $entityManager;
    $this->router = $router;
  }

  public function getAddToCartUrl($productId)
  {
    return $this->router->generate('foggyline_sales_cart_add', array('id' => $productId));
  }
}
```

这里的`router`服务期望名为`foggyline_sales_cart_add`的路由，但这个路由还不存在。我们通过在`src/Foggyline/SalesBundle/Resources/config/routing.xml`文件的`routes`元素下添加以下条目来创建该路由，如下所示：

```php
<route id="foggyline_sales_cart_add" path="/cart/add/{id}">
  <default key="_controller">FoggylineSalesBundle:Cart:add</default>
</route>
```

路由定义期望在`src/Foggyline/SalesBundle/Controller/CartController.php`文件中的购物车控制器中找到`addAction`函数，我们定义如下：

```php
namespace Foggyline\SalesBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class CartController extends Controller
{
  public function addAction($id)
  {
    if ($customer = $this->getUser()) {
      $em = $this->getDoctrine()->getManager();
      $now = new \DateTime();

      $product = $em->getRepository('FoggylineCatalogBundle:Product')->find($id);

      // Grab the cart for current user
      $cart = $em->getRepository('FoggylineSalesBundle:Cart')->findOneBy(array('customer' => $customer));

      // If there is no cart, create one
      if (!$cart) {
        $cart = new \Foggyline\SalesBundle\Entity\Cart();
        $cart->setCustomer($customer);
        $cart->setCreatedAt($now);
        $cart->setModifiedAt($now);
      } else {
        $cart->setModifiedAt($now);
      }

      $em->persist($cart);
      $em->flush();

      // Grab the possibly existing cart item
      // But, lets find it directly
      $cartItem = $em->getRepository('FoggylineSalesBundle:CartItem')->findOneBy(array('cart' => $cart, 'product' => $product));

      if ($cartItem) {
        // Cart item exists, update it
        $cartItem->setQty($cartItem->getQty() + 1);
        $cartItem->setModifiedAt($now);
      } else {
        // Cart item does not exist, add new one
        $cartItem = new \Foggyline\SalesBundle\Entity\CartItem();
        $cartItem->setCart($cart);
        $cartItem->setProduct($product);
        $cartItem->setQty(1);
        $cartItem->setUnitPrice($product->getPrice());
        $cartItem->setCreatedAt($now);
        $cartItem->setModifiedAt($now);
      }

      $em->persist($cartItem);
      $em->flush();

      $this->addFlash('success', sprintf('%s successfully added to cart', $product->getTitle()));

      return $this->redirectToRoute('foggyline_sales_cart');
    } else {
      $this->addFlash('warning', 'Only logged in users can add to cart.');
      return $this->redirect('/');
    }
  }
}
```

在`addAction`方法中有相当多的逻辑。我们首先检查当前用户是否已经在数据库中有购物车条目；如果没有，我们就创建一个新的。然后添加或更新现有的购物车条目。

为了使我们的新`add_to_cart`服务实际上覆盖`Customer`模块中的服务，我们仍然需要添加一个编译器。我们通过定义`src/Foggyline/SalesBundle/DependencyInjection/Compiler/OverrideServiceCompilerPass.php`文件来实现这一点，内容如下：

```php
namespace Foggyline\SalesBundle\DependencyInjection\Compiler;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

class OverrideServiceCompilerPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container)
    {
        // Override 'add_to_cart_url' service
        $container->removeDefinition('add_to_cart_url');
        $container->setDefinition('add_to_cart_url', $container->getDefinition('foggyline_sales.add_to_cart_url'));

        // Override 'checkout_menu' service
        // Override 'foggyline_customer.customer_orders' service
        // Override 'bestsellers' service
        // Pickup/parse 'shipment_method' services
        // Pickup/parse 'payment_method' services
    }
}
```

稍后，我们将在此文件中添加其余的覆盖。为了暂时解决问题，并使`add_to_cart`服务覆盖生效，我们需要在`src/Foggyline/SalesBundle/FoggylineSalesBundle.php`文件的`build`方法中注册*编译器*，如下所示：

```php
public function build(ContainerBuilder $container)
{
    parent::build($container);;
    $container->addCompilerPass(new OverrideServiceCompilerPass());
}
```

覆盖现在应该生效了，我们的`Sales`模块现在应该提供有效的添加到购物车链接。

## 覆盖`checkout_menu`服务

`Customer`模块中定义的结账菜单服务有一个简单的目的，即提供到购物车和结账流程的第一步的链接。由于当时还不知道销售模块，`Customer`模块提供了一个虚拟链接，现在我们将覆盖它。

首先，在`src/Foggyline/SalesBundle/Resources/config/services.xml`文件的`services`元素下添加以下服务条目：

```php
<service id="foggyline_sales.checkout_menu" class="Foggyline\SalesBundle\Service\CheckoutMenu">
<argument type="service" id="doctrine.orm.entity_manager"/>
<argument type="service" id="security.token_storage"/>
<argument type="service" id="router"/>
</service>
```

然后添加`src/Foggyline/SalesBundle/Service/CheckoutMenu.php`文件，内容如下：

```php
namespace Foggyline\SalesBundle\Service;

class CheckoutMenu
{
  private $em;
  private $token;
  private $router;

  public function __construct(
    \Doctrine\ORM\EntityManager $entityManager,
    $tokenStorage,
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->em = $entityManager;
    $this->token = $tokenStorage->getToken();
    $this->router = $router;
  }

  public function getItems()
  {
    if ($this->token
      && $this->token->getUser() instanceof \Foggyline\CustomerBundle\Entity\Customer
    ) {
      $customer = $this->token->getUser();

      $cart = $this->em->getRepository('FoggylineSalesBundle:Cart')->findOneBy(array('customer' => $customer));

      if ($cart) {
        return array(
          array('path' => $this->router->generate('foggyline_sales_cart'), 'label' =>sprintf('Cart (%s)', count($cart->getItems()))),
          array('path' => $this->router->generate('foggyline_sales_checkout'), 'label' =>'Checkout'),
        );
      }
    }

    return array();
  }
}
```

该服务期望两个路由，`foggyline_sales_cart`和`foggyline_sales_checkout`，因此我们需要通过向`src/Foggyline/SalesBundle/Resources/config/routing.xml`文件添加以下路由定义来修改它：

```php
<route id="foggyline_sales_cart" path="/cart/">
  <default key="_controller">FoggylineSalesBundle:Cart:index</default>
</route>

<route id="foggyline_sales_checkout" path="/checkout/">
  <default key="_controller">FoggylineSalesBundle:Checkout:index</default>
</route>
```

新添加的路由期望`cart`和`checkout`控制器。`cart`控制器已经就位，所以我们只需要添加`indexAction`。此时，让我们添加一个空的如下：

```php
public function indexAction(Request $request)
{
}
```

类似地，让我们创建一个`src/Foggyline/SalesBundle/Controller/CheckoutController.php`文件，内容如下：

```php
namespace Foggyline\SalesBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\CountryType;

class CheckoutController extends Controller
{
  public function indexAction()
  {
  }
}
```

稍后，我们将回到这两个`indexAction`方法，并添加适当的方法体实现。

为了完成服务覆盖，我们现在通过用以下内容替换`src/Foggyline/SalesBundle/DependencyInjection/Compiler/OverrideServiceCompilerPass.php`文件中先前创建的`// Override 'checkout_menu'`服务注释来修改它：

```php
$container->removeDefinition('checkout_menu');
$container->setDefinition('checkout_menu', $container->getDefinition('foggyline_sales.checkout_menu'));
```

我们新定义的服务现在应该覆盖`Customer`模块中定义的服务，从而提供正确的结账和购物车（带有购物车中的商品数量）URL。

## 覆盖客户订单服务

`foggyline_customer.customer_orders`服务是为当前登录的客户提供以前创建的订单集合。`Customer`模块为此目的定义了一个虚拟服务，这样我们就可以继续构建**我的账户**页面下的**我的订单**部分。现在我们需要覆盖此服务，使其返回正确的订单。

我们首先在`src/Foggyline/SalesBundle/Resources/config/services.xml`文件的服务下添加以下`service`元素：

```php
<service id="foggyline_sales.customer_orders" class="Foggyline\SalesBundle\Service\CustomerOrders">
  <argument type="service" id="doctrine.orm.entity_manager"/>
  <argument type="service" id="security.token_storage"/>
  <argument type="service" id="router"/>
</service>
```

然后，我们添加`src/Foggyline/SalesBundle/Service/CustomerOrders.php`文件，内容如下：

```php
namespace Foggyline\SalesBundle\Service;

class CustomerOrders
{
  private $em;
  private $token;
  private $router;

  public function __construct(
    \Doctrine\ORM\EntityManager $entityManager,
    $tokenStorage,
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->em = $entityManager;
    $this->token = $tokenStorage->getToken();
    $this->router = $router;
  }

  public function getOrders()
  {
    $orders = array();

    if ($this->token
    && $this->token->getUser() instanceof \Foggyline\CustomerBundle\Entity\Customer
    ) {
      $salesOrders = $this->em->getRepository('FoggylineSalesBundle:SalesOrder')
      ->findBy(array('customer' => $this->token->getUser()));

      foreach ($salesOrders as $salesOrder) {
        $orders[] = array(
          'id' => $salesOrder->getId(),
          'date' => $salesOrder->getCreatedAt()->format('d/m/Y H:i:s'),
          'ship_to' => $salesOrder->getAddressFirstName() . '' . $salesOrder->getAddressLastName(),
'         'order_total' => $salesOrder->getTotalPrice(),
          'status' => $salesOrder->getStatus(),
          'actions' => array(
            array(
              'label' =>'Cancel',
              'path' => $this->router->generate('foggyline_sales_order_cancel', array('id' => $salesOrder->getId()))
            ),
            array(
              'label' =>'Print',
              'path' => $this->router->generate('foggyline_sales_order_print', array('id' => $salesOrder->getId()))
            )
          )
        );
      }
    }
    return $orders;
  }
}
```

`route generate`方法期望找到两个路由，`foggyline_sales_order_cancel`和`foggyline_sales_order_print`，这两个路由尚未创建。

让我们继续通过在`src/Foggyline/SalesBundle/Resources/config/routing.xml`文件的`route`元素下添加以下内容来创建它们：

```php
<route id="foggyline_sales_order_cancel"path="/order/cancel/{id}">
  <default key="_controller">FoggylineSalesBundle:SalesOrder:cancel</default>
</route>

<route id="foggyline_sales_order_print" path="/order/print/{id}">
  <default key="_controller">FoggylineSalesBundle:SalesOrder:print</default>
</route>
```

路由定义又期望`SalesOrderController`被定义。由于我们的应用程序需要管理员用户能够列出和编辑订单，我们将使用以下 Symfony 命令自动生成我们的`Sales Order`实体的 CRUD：

```php
**php bin/console generate:doctrine:crud**

```

当要求实体快捷名称时，我们只需提供`FoggylineSalesBundle:SalesOrder`并继续，允许创建写操作。此时，已经为我们创建了几个文件，以及`Sales`包之外的一些条目。其中一个条目是`app/config/routing.yml`文件中的路由定义，如下所示：

```php
foggyline_sales_sales_order:
  resource: "@FoggylineSalesBundle/Controller/SalesOrderController.php"
  type:     annotation
```

我们应该已经在那里有一个`foggyline_sales`条目。不同之处在于`foggyline_sales`指向我们的`router.xml`文件，而新创建的`foggyline_sales_sales_order`指向刚创建的`SalesOrderController`。为了简单起见，我们可以保留它们两者。

自动生成器还在`app/Resources/views/`目录下创建了一个`salesorder`目录，我们需要将其移动到我们的包中，作为`src/Foggyline/SalesBundle/Resources/views/Default/salesorder/`目录。

现在我们可以通过将以下内容添加到`src/Foggyline/SalesBundle/Controller/SalesOrderController.php`文件中来处理我们的打印和取消操作：

```php
public function cancelAction($id)
{
  if ($customer = $this->getUser()) {
    $em = $this->getDoctrine()->getManager();
    $salesOrder = $em->getRepository('FoggylineSalesBundle:SalesOrder')
    ->findOneBy(array('customer' => $customer, 'id' => $id));

    if ($salesOrder->getStatus() != \Foggyline\SalesBundle\Entity\SalesOrder::STATUS_COMPLETE) {
      $salesOrder->setStatus(\Foggyline\SalesBundle\Entity\SalesOrder::STATUS_CANCELED);
      $em->persist($salesOrder);
      $em->flush();
    }
  }

  return $this->redirectToRoute('customer_account');
}

public function printAction($id)
{
  if ($customer = $this->getUser()) {
    $em = $this->getDoctrine()->getManager();
    $salesOrder = $em->getRepository('FoggylineSalesBundle:SalesOrder')
    ->findOneBy(array('customer' => $customer, 'id' =>$id));

    return $this->render('FoggylineSalesBundle:default:salesorder/print.html.twig', array(
      'salesOrder' => $salesOrder,
      'customer' => $customer
    ));
  }

  return $this->redirectToRoute('customer_account');
}
```

`cancelAction`方法仅仅检查所涉及的订单是否属于当前登录的客户；如果是，允许更改订单状态。`printAction`方法仅仅加载订单，如果它属于当前登录的客户，并将其传递给`print.html.twig`模板。

然后，我们创建了`src/Foggyline/SalesBundle/Resources/views/Default/salesorder/print.html.twig`模板，内容如下：

```php
{% block body %}
<h1>Printing Order #{{ salesOrder.id }}</h1>
  {#<p>Just a dummy Twig dump of entire variable</p>#}
  {{ dump(salesOrder) }}
{% endblock %}
```

显然，这只是一个简化的输出，我们可以根据需要进一步自定义。重要的是，我们已经将`order`对象传递给我们的模板，并且现在可以从中提取所需的任何信息。

最后，我们将`src/Foggyline/SalesBundle/DependencyInjection/Compiler/OverrideServiceCompilerPass.php`文件中的`// Override 'foggyline_customer.customer_orders'`服务注释替换为以下代码：

```php
$container->removeDefinition('foggyline_customer.customer_orders');
$container->setDefinition('foggyline_customer.customer_orders', $container->getDefinition('foggyline_sales.customer_orders'));
```

这将使服务覆盖生效，并引入我们刚刚进行的所有更改。

## 覆盖畅销服务

在`Customer`模块中定义的`bestsellers`服务应该为首页显示的畅销产品提供虚拟数据。其目的是展示商店中五个畅销产品。`Sales`模块现在需要覆盖此服务，以便提供正确的实现，实际销售的产品数量将影响所显示的畅销产品的内容。

我们首先在`src/Foggyline/SalesBundle/Resources/config/services.xml`文件的`service`元素下添加以下定义：

```php
<service id="foggyline_sales.bestsellers" class="Foggyline\SalesBundle\Service\BestSellers">
  <argument type="service" id="doctrine.orm.entity_manager"/>
  <argument type="service" id="router"/>
</service>
```

然后我们按以下内容定义`src/Foggyline/SalesBundle/Service/BestSellers.php`文件：

```php
namespace Foggyline\SalesBundle\Service;

class BestSellers
{
  private $em;
  private $router;

  public function __construct(
    \Doctrine\ORM\EntityManager $entityManager,
    \Symfony\Bundle\FrameworkBundle\Routing\Router $router
  )
  {
    $this->em = $entityManager;
    $this->router = $router;
  }

  public function getItems()
  {
    $products = array();
    $salesOrderItem = $this->em->getRepository('FoggylineSalesBundle:SalesOrderItem');
    $_products = $salesOrderItem->getBestsellers();

    foreach ($_products as $_product) {
      $products[] = array(
        'path' => $this->router->generate('product_show', array('id' => $_product->getId())),
        'name' => $_product->getTitle(),
        'img' => $_product->getImage(),
        'price' => $_product->getPrice(),
        'id' => $_product->getId(),
      );
    }
    return $products;
  }
}
```

在这里，我们获取`SalesOrderItemRepository`类的实例，并在其上调用`getBestsellers`方法。这个方法还没有被定义。我们通过将其添加到`src/Foggyline/SalesBundle/Repository/SalesOrderItemRepository.php`文件中来定义它：

```php
public function getBestsellers()
{
  $products = array();

  $query = $this->_em->createQuery('SELECT IDENTITY(t.product), SUM(t.qty) AS HIDDEN q
  FROM Foggyline\SalesBundle\Entity\SalesOrderItem t
  GROUP BY t.product ORDER BY q DESC')
  ->setMaxResults(5);

  $_products = $query->getResult();

  foreach ($_products as $_product) {
    $products[] = $this->_em->getRepository('FoggylineCatalogBundle:Product')
    ->find(current($_product));
  }

  return $products;
}
```

在这里，我们使用**Doctrine 查询语言**（**DQL**）来构建五个畅销产品的列表。最后，我们需要用以下代码替换`src/Foggyline/SalesBundle/DependencyInjection/Compiler/OverrideServiceCompilerPass.php`文件中的`// Override 'bestsellers'`服务注释：

```php
$container->removeDefinition('bestsellers');
$container->setDefinition('bestsellers', $container->getDefinition('foggyline_sales.bestsellers'));
```

通过覆盖`bestsellers`服务，我们公开了基于实际销售的畅销产品列表，供其他模块获取。

## 创建购物车页面

购物车页面是顾客可以通过首页、分类页面或产品页面的**加入购物车**按钮看到已添加到购物车的产品列表的地方。我们之前创建了`CartController`和一个空的`indexAction`函数。现在让我们继续编辑`indexAction`函数如下：

```php
public function indexAction()
{
  if ($customer = $this->getUser()) {
    $em = $this->getDoctrine()->getManager();

    $cart = $em->getRepository('FoggylineSalesBundle:Cart')->findOneBy(array('customer' => $customer));
    $items = $cart->getItems();
    $total = null;

    foreach ($items as $item) {
      $total += floatval($item->getQty() * $item->getUnitPrice());
    }

    return $this->render('FoggylineSalesBundle:default:cart/index.html.twig', array(
        'customer' => $customer,
        'items' => $items,
        'total' => $total,
      ));
  } else {
    $this->addFlash('warning', 'Only logged in customers can access cart page.');
    return $this->redirectToRoute('foggyline_customer_login');
  }
}
```

在这里，我们正在检查用户是否已登录；如果是，我们会向他们显示带有所有项目的购物车。未登录用户将被重定向到客户登录 URL。`indexAction`函数期望`src/Foggyline/SalesBundle/Resources/views/Default/cart/index.html.twig`文件，我们定义其内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<h1>Shopping Cart</h1>
<div class="row">
  <div class="large-8 columns">
    <form action="{{ path('foggyline_sales_cart_update') }}"method="post">
    <table>
      <thead>
        <tr>
          <th>Item</th>
          <th>Price</th>
          <th>Qty</th>
          <th>Subtotal</th>
        </tr>
      </thead>
      <tbody>
        {% for item in items %}
        <tr>
          <td>{{ item.product.title }}</td>
          <td>{{ item.unitPrice }}</td>
          <td><input name="item[{{ item.id }}]" value="{{ item.qty }}"/></td>
          <td>{{ item.qty * item.unitPrice }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <button type="submit" class="button">Update Cart</button>
  </form>
</div>
<div class="large-4 columns">
  <div>Order Total: {{ total }}</div>
  <div><a href="{{ path('foggyline_sales_checkout') }}"class="button">Go to Checkout</a></div>
  </div>
</div>
{% endblock %}
```

模板渲染时，将在每个添加的产品下显示数量输入元素，以及**更新购物车**按钮。**更新购物车**按钮提交表单，其操作指向`foggyline_sales_cart_update`路由。

让我们继续创建`foggyline_sales_cart_update`，通过在`src/Foggyline/SalesBundle/Resources/config/routing.xml`文件的`route`元素下添加以下条目：

```php
<route id="foggyline_sales_cart_update" path="/cart/update">
  <default key="_controller">FoggylineSalesBundle:Cart:update</default>
</route>
```

新定义的路由期望在`src/Foggyline/SalesBundle/Controller/CartController.php`文件中找到一个`updateAction`函数，我们添加如下：

```php
public function updateAction(Request $request)
{
  $items = $request->get('item');

  $em = $this->getDoctrine()->getManager();
  foreach ($items as $_id => $_qty) {
    $cartItem = $em->getRepository('FoggylineSalesBundle:CartItem')->find($_id);
    if (intval($_qty) > 0) {
      $cartItem->setQty($_qty);
      $em->persist($cartItem);
    } else {
      $em->remove($cartItem);
    }
  }
  // Persist to database
  $em->flush();

  $this->addFlash('success', 'Cart updated.');

  return $this->redirectToRoute('foggyline_sales_cart');
}
```

要从购物车中删除产品，我们只需将数量值插入为`0`，然后点击**更新购物车**按钮。这完成了我们简单的购物车页面。

## 创建支付服务

为了从购物车到结账的过程中，我们需要解决支付和运输服务的问题。先前的`Payment`和`Shipment`模块公开了它们的一些`Payment`和`Shipment`服务，现在我们需要将它们聚合成一个单一的`Payment`和`Shipment`服务，供我们的结账流程使用。

我们开始用以下代码替换`src/Foggyline/SalesBundle/DependencyInjection/Compiler/OverrideServiceCompilerPass.php`文件中先前添加的`// Pickup/parse 'payment_method'`服务注释：

```php
$container->getDefinition('foggyline_sales.payment')
  ->addArgument(
  array_keys($container->findTaggedServiceIds('payment_method'))
);
```

`findTaggedServiceIds`方法返回一个带有`payment_method`标签的所有服务的键值列表，然后我们将其作为参数传递给我们的`foggyline_sales.payment`服务。这是在 Symfony 编译时获取服务列表的唯一方法。

然后我们通过在`service`元素下添加以下内容来编辑`src/Foggyline/SalesBundle/Resources/config/services.xml`文件：

```php
<service id="foggyline_sales.payment" class="Foggyline\SalesBundle\Service\Payment">
  <argument type="service" id="service_container"/>
</service>
```

最后，我们按以下方式在`src/Foggyline/SalesBundle/Service/Payment.php`文件中创建`Payment`类：

```php
namespace Foggyline\SalesBundle\Service;

class Payment
{
  private $container;
  private $methods;

  public function __construct($container, $methods)
  {
    $this->container = $container;
    $this->methods = $methods;
  }

  public function getAvailableMethods()
  {
    $methods = array();

    foreach ($this->methods as $_method) {
      $methods[] = $this->container->get($_method);
    }

    return $methods;
  }
}
```

根据`services.xml`文件中的服务定义，我们的服务接受两个参数，一个是`$container`，另一个是`$methods`。`$methods`参数在编译时传递，我们能够获取所有`payment_method`标记的服务列表。这有效地意味着我们的`getAvailableMethods`现在能够返回任何模块中标记为`payment_method`的服务。

## 创建装运服务

`Shipment`服务的实现方式与`Payment`服务类似。总体思路是相似的，只是在途中有一些不同。我们首先用以下代码替换之前添加的`// Pickup/parse shipment_method'`服务注释，放在`src/Foggyline/SalesBundle/DependencyInjection/Compiler/OverrideServiceCompilerPass.php`文件中：

```php
$container->getDefinition('foggyline_sales.shipment')
  ->addArgument(
  array_keys($container->findTaggedServiceIds('shipment_method'))
);
```

然后，我们通过在`src/Foggyline/SalesBundle/Resources/config/services.xml`文件的`service`元素下添加以下内容来编辑：

```php
<service id="foggyline_sales.shipment"class="Foggyline\SalesBundle\Service\Payment">
  <argument type="service" id="service_container"/>
</service>
```

最后，我们按照以下方式在`src/Foggyline/SalesBundle/Service/Shipment.php`文件中创建`Shipment`类：

```php
namespace Foggyline\SalesBundle\Service;

class Shipment
{
  private $container;
  private $methods;

  public function __construct($container, $methods)
  {
    $this->container = $container;
    $this->methods = $methods;
  }

  public function getAvailableMethods()
  {
    $methods = array();
    foreach ($this->methods as $_method) {
      $methods[] = $this->container->get($_method);
    }

    return $methods;
  }
}
```

现在，我们能够通过我们统一的`Payment`和`Shipment`服务获取所有的`Payment`和`Shipment`服务，从而使结账流程变得简单。

## 创建结账页面

结账页面将由两个结账步骤构成，第一个是收集装运信息，第二个是收集支付信息。

我们从装运步骤开始，通过更改`src/Foggyline/SalesBundle/Controller/CheckoutController.php`文件及其`indexAction`如下：

```php
public function indexAction()
{
  if ($customer = $this->getUser()) {

    $form = $this->getAddressForm();

    $em = $this->getDoctrine()->getManager();
    $cart = $em->getRepository('FoggylineSalesBundle:Cart')->findOneBy(array('customer' => $customer));
    $items = $cart->getItems();
    $total = null;

    foreach ($items as $item) {
      $total += floatval($item->getQty() * $item->getUnitPrice());
    }

    return $this->render('FoggylineSalesBundle:default:checkout/index.html.twig', array(
      'customer' => $customer,
      'items' => $items,
      'cart_subtotal' => $total,
      'shipping_address_form' => $form->createView(),
      'shipping_methods' => $this->get('foggyline_sales.shipment')->getAvailableMethods()
    ));
  } else {
    $this->addFlash('warning', 'Only logged in customers can access checkout page.');
    return $this->redirectToRoute('foggyline_customer_login');
  }
}
private function getAddressForm()
{
  return $this->createFormBuilder()
  ->add('address_first_name', TextType::class)
  ->add('address_last_name', TextType::class)
  ->add('company', TextType::class)
  ->add('address_telephone', TextType::class)
  ->add('address_country', CountryType::class)
  ->add('address_state', TextType::class)
  ->add('address_city', TextType::class)
  ->add('address_postcode', TextType::class)
  ->add('address_street', TextType::class)
  ->getForm();
}
```

在这里，我们获取当前登录的客户购物车，并将其传递到`checkout/index.html.twig`模板，还有其他几个在装运步骤中需要的变量。`getAddressForm`方法简单地为我们构建了一个地址表单。还有一个调用我们新创建的`foggyline_sales.shipment`服务，它使我们能够获取所有可用的装运方式列表。

然后，我们创建`src/Foggyline/SalesBundle/Resources/views/Default/checkout/index.html.twig`，内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<h1>Checkout</h1>

<div class="row">
  <div class="large-8 columns">
    <form action="{{ path('foggyline_sales_checkout_payment') }}" method="post" id="shipping_form">
      <fieldset>
        <legend>Shipping Address</legend>
        {{ form_widget(shipping_address_form) }}
      </fieldset>

      <fieldset>
        <legend>Shipping Methods</legend>
        <ul>
          {% for method in shipping_methods %}
          {% set shipment = method.getInfo('street', 'city', 'country', 'postcode', 'amount', 'qty')['shipment'] %}
          <li>
            <label>{{ shipment.title }}</label>
            <ul>
              {% for delivery_option in shipment.delivery_options %}
              <li>
                <input type="radio" name="shipment_method"
                  value="{{ shipment.code }}____{{ delivery_option.code }}____{{ delivery_option.price }}"> {{ delivery_option.title }}
                  ({{ delivery_option.price }})
                <br>
              </li>
              {% endfor %}
            </ul>
          </li>
          {% endfor %}
        </ul>
      </fieldset>
    </form>
  </div>
  <div class="large-4 columns">
    {% include 'FoggylineSalesBundle:default:checkout/order_sumarry.html.twig' 
    %}
    <div>Cart Subtotal: {{ cart_subtotal }}</div>
    <div><a id="shipping_form_submit" href="#" class="button">Next</a>
    </div>
  </div>
</div>

<script type="text/javascript">
  var form = document.getElementById('shipping_form');
  document.getElementById('shipping_form_submit').addEventListener('click', function () {
    form.submit();
  });
</script>
{% endblock %}
```

模板列出了所有与地址相关的表单字段，以及可用的装运方式。JavaScript 部分处理了**下一步**按钮的点击，基本上是将表单提交到`foggyline_sales_checkout_payment`路由。

然后，我们通过在`src/Foggyline/SalesBundle/Resources/config/routing.xml`文件的`routes`元素下添加以下条目来定义`foggyline_sales_checkout_payment`路由：

```php
<route id="foggyline_sales_checkout_payment" path="/checkout/payment">
  <default key="_controller">FoggylineSalesBundle:Checkout:payment</default>
</route>
```

路由条目期望在`CheckoutController`中找到`paymentAction`，我们定义如下：

```php
public function paymentAction(Request $request)
{
  $addressForm = $this->getAddressForm();
  $addressForm->handleRequest($request);

  if ($addressForm->isSubmitted() && $addressForm->isValid() && $customer = $this->getUser()) {

    $em = $this->getDoctrine()->getManager();
    $cart = $em->getRepository('FoggylineSalesBundle:Cart')->findOneBy(array('customer' => $customer));
    $items = $cart->getItems();
    $cartSubtotal = null;

    foreach ($items as $item) {
      $cartSubtotal += floatval($item->getQty() * $item->getUnitPrice());
    }

    $shipmentMethod = $_POST['shipment_method'];
    $shipmentMethod = explode('____', $shipmentMethod);
    $shipmentMethodCode = $shipmentMethod[0];
    $shipmentMethodDeliveryCode = $shipmentMethod[1];
    $shipmentMethodDeliveryPrice = $shipmentMethod[2];

    // Store relevant info into session
    $checkoutInfo = $addressForm->getData();
    $checkoutInfo['shipment_method'] = $shipmentMethodCode . '____' . $shipmentMethodDeliveryCode;
    $checkoutInfo['shipment_price'] = $shipmentMethodDeliveryPrice;
    $checkoutInfo['items_price'] = $cartSubtotal;
    $checkoutInfo['total_price'] = $cartSubtotal + $shipmentMethodDeliveryPrice;
    $this->get('session')->set('checkoutInfo', $checkoutInfo);

    return $this->render('FoggylineSalesBundle:default:checkout/payment.html.twig', array(
      'customer' => $customer,
      'items' => $items,
      'cart_subtotal' => $cartSubtotal,
      'delivery_subtotal' => $shipmentMethodDeliveryPrice,
      'delivery_label' =>'Delivery Label Here',
      'order_total' => $cartSubtotal + $shipmentMethodDeliveryPrice,
      'payment_methods' => $this->get('foggyline_sales.payment')->getAvailableMethods()
    ));
  } else {
    $this->addFlash('warning', 'Only logged in customers can access checkout page.');
    return $this->redirectToRoute('foggyline_customer_login');
  }
}
```

前面的代码从结账流程的装运步骤中获取提交的内容，将相关数值存储到会话中，获取支付步骤所需的变量，并渲染`checkout/payment.html.twig`模板。

我们定义了`src/Foggyline/SalesBundle/Resources/views/Default/checkout/payment.html.twig`文件的内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<h1>Checkout</h1>
<div class="row">
  <div class="large-8 columns">
    <form action="{{ path('foggyline_sales_checkout_process') }}"method="post" id="payment_form">
      <fieldset>
        <legend>Payment Methods</legend>
        <ul>
          {% for method in payment_methods %}
          {% set payment = method.getInfo()['payment'] %}
          <li>
            <input type="radio" name="payment_method"
              value="{{ payment.code }}"> {{ payment.title }}
            {% if payment['form'] is defined %}
            <div id="{{ payment.code }}_form">
              {{ form_widget(payment['form']) }}
            </div>
            {% endif %}
          </li>
          {% endfor %}
        </ul>
      </fieldset>
    </form>
  </div>
  <div class="large-4 columns">
    {% include 'FoggylineSalesBundle:default:checkout/order_sumarry.html.twig' %}
    <div>Cart Subtotal: {{ cart_subtotal }}</div>
    <div>{{ delivery_label }}: {{ delivery_subtotal }}</div>
    <div>Order Total: {{ order_total }}</div>
    <div><a id="payment_form_submit" href="#" class="button">Place Order</a>
    </div>
  </div>
</div>
<script type="text/javascript">
  var form = document.getElementById('payment_form');
  document.getElementById('payment_form_submit').addEventListener('click', function () {
    form.submit();
  });
</script>
{% endblock %}
```

与装运步骤类似，这里还有可用支付方式的渲染，以及一个由 JavaScript 处理的**下订单**按钮，因为按钮位于提交表单之外。下订单后，提交将发送到`foggyline_sales_checkout_process`路由，我们在`src/Foggyline/SalesBundle/Resources/config/routing.xml`文件的`routes`元素下定义如下：

```php
<route id="foggyline_sales_checkout_process"path="/checkout/process">
  <default key="_controller">FoggylineSalesBundle:Checkout:process</default>
</route>
```

路由指向`CheckoutController`中的`processAction`函数，我们定义如下：

```php
public function processAction()
{
  if ($customer = $this->getUser()) {

    $em = $this->getDoctrine()->getManager();
    // Merge all the checkout info, for SalesOrder
    $checkoutInfo = $this->get('session')->get('checkoutInfo');
    $now = new \DateTime();

    // Create Sales Order
    $salesOrder = new \Foggyline\SalesBundle\Entity\SalesOrder();
    $salesOrder->setCustomer($customer);
    $salesOrder->setItemsPrice($checkoutInfo['items_price']);
    $salesOrder->setShipmentPrice
      ($checkoutInfo['shipment_price']);
    $salesOrder->setTotalPrice($checkoutInfo['total_price']);
    $salesOrder->setPaymentMethod($_POST['payment_method']);
    $salesOrder->setShipmentMethod($checkoutInfo['shipment_method']);
    $salesOrder->setCreatedAt($now);
    $salesOrder->setModifiedAt($now);
    $salesOrder->setCustomerEmail($customer->getEmail());
    $salesOrder->setCustomerFirstName($customer->getFirstName());
    $salesOrder->setCustomerLastName($customer->getLastName());
    $salesOrder->setAddressFirstName($checkoutInfo['address_first_name']);
    $salesOrder->setAddressLastName($checkoutInfo['address_last_name']);
    $salesOrder->setAddressCountry($checkoutInfo['address_country']);
    $salesOrder->setAddressState($checkoutInfo['address_state']);
    $salesOrder->setAddressCity($checkoutInfo['address_city']);
    $salesOrder->setAddressPostcode($checkoutInfo['address_postcode']);
    $salesOrder->setAddressStreet($checkoutInfo['address_street']);
    $salesOrder->setAddressTelephone($checkoutInfo['address_telephone']);
    $salesOrder->setStatus(\Foggyline\SalesBundle\Entity\SalesOrder::STATUS_PROCESSING);

    $em->persist($salesOrder);
    $em->flush();

    // Foreach cart item, create order item, and delete cart item
    $cart = $em->getRepository('FoggylineSalesBundle:Cart')->findOneBy(array('customer' => $customer));
    $items = $cart->getItems();

    foreach ($items as $item) {
      $orderItem = new \Foggyline\SalesBundle\Entity\SalesOrderItem();

      $orderItem->setSalesOrder($salesOrder);
      $orderItem->setTitle($item->getProduct()->getTitle());
      $orderItem->setQty($item->getQty());
      $orderItem->setUnitPrice($item->getUnitPrice());
      $orderItem->setTotalPrice($item->getQty() * $item->getUnitPrice());
      $orderItem->setModifiedAt($now);
      $orderItem->setCreatedAt($now);
      $orderItem->setProduct($item->getProduct());

      $em->persist($orderItem);
      $em->remove($item);
    }

    $em->remove($cart);
    $em->flush();

    $this->get('session')->set('last_order', $salesOrder->getId());
    return $this->redirectToRoute('foggyline_sales_checkout_success');
  } else {
    $this->addFlash('warning', 'Only logged in customers can access checkout page.');
    return $this->redirectToRoute('foggyline_customer_login');
  }
}
```

一旦提交到控制器，就会创建一个新订单以及所有相关的项目。同时，购物车和购物车项目将被清除。最后，客户将被重定向到订单成功页面。

## 创建订单成功页面

订单成功页面在完整的网络商店应用程序中起着重要作用。这是我们感谢客户购买并可能提供一些更多相关或交叉相关的购物选项，以及一些可选的折扣的地方。虽然我们的应用程序很简单，但构建一个简单的订单成功页面是值得的。

我们首先在`src/Foggyline/SalesBundle/Resources/config/routing.xml`文件的`routes`元素下添加以下路由定义：

```php
<route id="foggyline_sales_checkout_success" path="/checkout/success">
  <default key="_controller">FoggylineSalesBundle:Checkout:success</default>
</route>
```

路由指向`CheckoutController`中的`successAction`函数，我们定义如下：

```php
public function successAction()
{

  return $this->render('FoggylineSalesBundle:default:checkout/success.html.twig', array(
    'last_order' => $this->get('session')->get('last_order')
  ));
}
```

在这里，我们只是简单地获取当前登录客户的最后创建的订单 ID，并将完整的订单对象传递给`src/Foggyline/SalesBundle/Resources/views/Default/checkout/success.html.twig`模板，内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<h1>Checkout Success</h1>
<div class="row">
  <p>Thank you for placing your order #{{ last_order }}.</p>
  <p>You can see order details <a href="{{ path('customer_account') }}">here</a>.</p>
</div>
{% endblock %}
```

通过这一步，我们为我们的网络商店完成了整个结账流程。虽然它非常简单，但它为更强大的实现奠定了基础。

## 创建商店管理仪表板

现在我们已经完成了结账`Sales`模块，让我们快速回到我们的核心模块`AppBundle`。根据我们的应用程序要求，让我们继续创建一个简单的商店管理仪表板。

我们首先添加`src/AppBundle/Controller/StoreManagerController.php`文件，内容如下：

```php
namespace AppBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

class StoreManagerController extends Controller
{
  /**
  * @Route("/store_manager", name="store_manager")
  */
  public function indexAction()
  {
    return $this->render('AppBundle:default:store_manager.html.twig');
  }
}
```

`indexAction`函数简单地返回`src/AppBundle/Resources/views/default/store_manager.html.twig`文件，我们定义其内容如下：

```php
{% extends 'base.html.twig' %}
{% block body %}
<h1>Store Manager</h1>
<div class="row">
  <div class="large-6 columns">
    <div class="stacked button-group">
      <a href="{{ path('category_new') }}" class="button">Add new Category</a>
      <a href="{{ path('product_new') }}" class="button">Add new Product</a>
      <a href="{{ path('customer_new') }}" class="button">Add new Customer</a>
    </div>
  </div>
  <div class="large-6 columns">
    <div class="stacked button-group">
      <a href="{{ path('category_index') }}" class="button">List & Manage Categories</a>
      <a href="{{ path('product_index') }}" class="button">List & Manage Products</a>
      <a href="{{ path('customer_index') }}" class="button">List & Manage Customers</a>
      <a href="{{ path('salesorder_index') }}" class="button">List & Manage Orders</a>
    </div>
  </div>
</div>
{% endblock %}
```

模板仅仅渲染类别、产品、客户和订单管理链接。对这些链接的实际访问由防火墙控制，如前几章所述。

# 单元测试

`Sales`模块比以前的任何模块都更强大。有几件事情我们可以进行单元测试。但是，作为本章的一部分，我们不会涵盖完整的单元测试。我们只会把注意力转向单个单元测试，即`CustomerOrders`服务的单元测试。

我们首先在`phpunit.xml.dist`文件的`testsuites`元素下添加以下行：

```php
<directory>src/Foggyline/SalesBundle/Tests</directory>
```

有了这些，从商店的根目录运行`phpunit`命令应该会执行我们在`src/Foggyline/SalesBundle/Tests/`目录下定义的任何测试。

现在，让我们继续为我们的`CustomerOrders`服务创建一个测试。我们通过定义`src/Foggyline/SalesBundle/Tests/Service/CustomerOrdersTest.php`文件并填写以下内容来实现这一点：

```php
namespace Foggyline\SalesBundle\Test\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class CustomerOrdersTest extends KernelTestCase
{
  private $container;

  public function setUp()
  {
    static::bootKernel();
    $this->container = static::$kernel->getContainer();
  }

  public function testGetOrders()
  {
    $firewall = 'foggyline_customer';

    $em = $this->container->get('doctrine.orm.entity_manager');

    $user = $em->getRepository('FoggylineCustomerBundle:Customer')->findOneByUsername
      ('ajzele@gmail.com');
    $token = new UsernamePasswordToken($user, null, $firewall, array('ROLE_USER'));

    $tokenStorage = $this->container->get('security.token_storage');
    $tokenStorage->setToken($token);

    $orders = new \Foggyline\SalesBundle\Service\CustomerOrders(
      $em,
      $tokenStorage,
      $this->container->get('router')
    );

    $this->assertNotEmpty($orders->getOrders());
  }
}
```

在这里，我们使用`UsernamePasswordToken`函数来模拟客户登录。然后将密码令牌传递给`CustomerOrders`服务。`CustomerOrders`服务然后在内部检查令牌存储是否分配了令牌，将其标记为已登录用户并返回其订单列表。能够模拟客户登录对于我们可能为销售模块编写的任何其他测试都是必不可少的。

# 功能测试

与单元测试类似，我们只关注单个功能测试，因为做任何更强大的测试都超出了本章的范围。我们将编写一个简单的代码，将产品添加到购物车并访问结账页面。为了将商品添加到购物车，我们还需要模拟用户登录。

我们按照以下方式编写`src/Foggyline/SalesBundle/Tests/Controller/CartControllerTest.php`测试：

```php
namespace Foggyline\SalesBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class CartControllerTest extends WebTestCase
{
  private $client = null;

  public function setUp()
  {
    $this->client = static::createClient();
  }

  public function testAddToCartAndAccessCheckout()
  {
    $this->logIn();

    $crawler = $this->client->request('GET', '/');
    $crawler = $this->client->click($crawler->selectLink('Add to Cart')->link());
    $crawler = $this->client->followRedirect();

    $this->assertTrue($this->client->getResponse()->isSuccessful());
    $this->assertGreaterThan(0, $crawler->filter('html:contains("added to cart")')->count());

    $crawler = $this->client->request('GET', '/sales/cart/');
    $crawler = $this->client->click($crawler->selectLink('Go to Checkout')->link());

    $this->assertTrue($this->client->getResponse()->isSuccessful());
    $this->assertGreaterThan(0, $crawler->filter('html:contains("Checkout")')->count());
  }

  private function logIn()
  {
    $session = $this->client->getContainer()->get('session');
    $firewall = 'foggyline_customer'; // firewall name
    $em = $this->client->getContainer()->get('doctrine')->getManager();
    $user = $em->getRepository('FoggylineCustomerBundle:Customer')->findOneByUsername('ajzele@gmail.com');

    $token = new UsernamePasswordToken($user, null, $firewall, array('ROLE_USER'));
    $session->set('_security_' . $firewall, serialize($token));
    $session->save();

    $cookie = new Cookie($session->getName(), $session->getId());
    $this->client->getCookieJar()->set($cookie);
  }
}
```

一旦运行，测试将模拟客户登录，将商品添加到购物车，并尝试访问结账页面。根据我们数据库中实际的客户，我们可能需要更改前面测试中提供的客户电子邮件。

现在运行`phpunit`命令应该成功执行我们的测试。

# 总结

在本章中，我们构建了一个简单但功能齐全的“销售”模块。仅使用四个简单的实体（`Cart`、`CartItem`、`SalesOrder`和`SalesOrderItem`），我们成功实现了简单的购物车和结账功能。通过这样做，我们赋予了客户实际购买产品的能力，而不仅仅是浏览产品目录。销售模块利用了前几章定义的付款和发货服务。虽然付款和发货服务是作为虚构的、虚拟的实现的，但它们提供了一个基本的框架，我们可以用于真正的付款和发货 API 实现。

此外，在本章中，我们通过创建一个简单的界面来处理管理员仪表板，该界面仅仅聚合了一些现有的 CRUD 界面。对仪表板和管理链接的访问受到`app/config/security.yml`中的条目的保护，只允许`ROLE_ADMIN`访问。

到目前为止，我们编写的模块构成了一个简化的应用程序。编写健壮的网络商店应用程序通常会包括现代电子商务平台中发现的数十种其他功能，例如 Magento。这些功能包括多语言、货币和网站支持；健壮的类别、产品和产品库存管理；购物车和目录销售规则；以及许多其他功能。模块化我们的应用程序使开发和维护过程更加简单。

在最后一章中，我们将探讨如何分发我们的模块。
