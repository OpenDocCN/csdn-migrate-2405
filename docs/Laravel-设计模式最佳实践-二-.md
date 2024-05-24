# Laravel 设计模式最佳实践（二）

> 原文：[`zh.annas-archive.org/md5/c21d87a1a56234879b851abfda164e5a`](https://zh.annas-archive.org/md5/c21d87a1a56234879b851abfda164e5a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Laravel 最佳实践

在本章中，我们将看到在 Laravel 中使用各种先前描述的设计模式的示例。

本章将讨论的主题如下：

+   基本和高级实践

+   在 Laravel 中使用的设计模式的现实生活示例

+   这些设计模式在示例中使用的原因

# 基本实践

作为开发人员，当您在应用程序上工作时，应该有一种系统化的顺序，以防止混乱并允许灵活性。例如，在 MVC 架构中，控制器应该只包含逻辑，模型应该只包含与数据流相关的内容。您不应该在视图文件中编写数据库查询。这样，任何在项目上工作的人都可以轻松找到他们正在寻找的内容，并可以更轻松地进行更改、分支或改进。如果不遵循这一点，随着项目的不断扩大，项目将变得一团糟。

一个基本的良好实践是避免重复。如果您多次使用代码片段或条件，最好为该操作准备一个方法或范围。这样，您就不必一遍又一遍地重复自己。例如，假设我们有一个虚构的控制器如下：

```php
<?php

class UserController extends BaseController {

   //An imaginary method that lists all active users
   public function listUsers() {

      $users = User::where('active', 1)->get();

      return View::make('frontend.users.list')
         ->with('users', $users);
   }

   //An imaginary method that finds a specific user
   public function fetch($id) {

      $user = User::where('active', 1)->find($id);

       return View::make('frontend.users.single')
         ->with('user', $user);

   }

}
```

正如您所看到的，`where()`条件检查`active`是否重复两次。在现实世界的例子中，它可能会被更多地使用。

为了避免这种情况，在 Laravel 中，您可以使用查询范围。查询范围是帮助您在模型中重用逻辑的单个函数。让我们在模型中定义一个查询范围，并将控制器方法更改如下：

```php
<?php

//Model File
Class User extends Eloquent {

   //We've defined a Query scope called active
   public function scopeActive($query) {
      return $query->where('active', 1);
   }

}

//Controller File
class UserController extends BaseController {

   //An imaginary method that lists all active users
   public function listUsers() {

      $users = User::active()->get();

      return View::make('frontend.users.list')
         ->with('users', $users);
   }

   //An imaginary method that finds a specific user
   public function fetch($id) {

      $user = User::active()->find($id);

      return View::make('frontend.users.single')
         ->with('user', $user);

   }

}
```

如您所见，我们在模型中定义了一个名为`scopeActive()`的方法，它以`scope`开头并使用驼峰命名法。这样，Laravel 可以理解它是一个查询范围，并且您可以直接使用该范围。如您所见，控制器中的条件也已更改。它们已从`where('active', 1)`更改为`active()`。

设计模式是高级实践，可以使用各种方法使代码整洁和系统化。

# 高级实践

在本小节中，我们将看到 Laravel 中各种设计模式的使用。如果您测试包含在本书中提供的设计模式的自定义类，它们应该会自动加载到您的应用程序中。这可以通过将它们添加到`global.php`文件的`ClassLoader::addDirectories()`数组中（可以通过导航到`app/start`找到）或`bootstrap`文件夹中的`start.php`文件中来完成。或者，我们可以在`composer.json`中添加一个`psr-0`自动加载。

要从`app/start/global.php`中添加目录，首先找到以下代码：

```php
ClassLoader::addDirectories(array(

   app_path().'/commands',
   app_path().'/controllers',
   app_path().'/models',
   app_path().'/database/seeds',

));
```

然后在下面添加您的文件夹。生成的代码将如下所示：

```php
ClassLoader::addDirectories(array(

   app_path().'/commands',
   app_path().'/controllers',
   app_path().'/models',
   app_path().'/database/seeds',

   //our custom directory that holds classes
   app_path().'/acme',
));
```

如果您想使用`psr-0`自动加载从`composer.json`文件中自动加载类或文件，您必须将命名空间和目录添加到`composer.json`中。键将是命名空间，值将是包含要自动加载的文件和类的文件夹的路径。看一下以下代码：

```php
"autoload": {

    "psr-0": {
        "Acme": "app/lib"
    }
}
```

在这个例子中，如果我们的`composer.json`文件没有一个`psr-0`对象，首先我们会创建它，然后在里面添加命名空间和路径值。您可以看到我们有一个名为`Acme`的命名空间，它位于`app/lib`文件夹下。

如果您不想自动加载整个文件夹，而只想加载一些单个文件，您也可以在`composer.json`中使用`files`对象。这是一个只包含文件路径的单个对象。

```php
"autoload": {
    "files": [
        "app/acme/myFunctions.php"
    ]
},
```

添加这些值后，您需要转储自动加载文件并让 Laravel 理解它们。要做到这一点，在编辑`composer.json`文件后，只需运行以下命令：

```php
composer dump-autoload
```

如果您的环境中没有安装 composer，您也可以运行以下命令：

```php
php composer.phar dump-autoload
```

在此之后，您刚刚添加的类或文件将被自动加载，并可用于您的项目。

## 工厂模式

正如你可能从第五章中所记得的，工厂模式是基于创建模板方法对象来实现算法的。假设我们正在开发以下应用程序：

![工厂模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00012.jpg)

假设**Toyota**品牌只生产 C 级红色汽车，而**Suzuki**品牌只生产 B 级绿色汽车。假设我们有一个为此目的定义的模型，如下所示：

```php
<?php

class CarFactoryModel extends BaseModel{

    public static function createCar($manufacturer)
    {
        switch ($manufacturer)
        {

        }

        throw new \InvalidArgumentException("Unsupported manufacturer [$manufacturer]");
    }

    public static function createCarFromColor($color)
    {
        switch ($color)
        {
            case 'Red':

            return static::createCar('Toyota');

            case 'Green':

            return static::createCar('Suzuki');

        }

        throw new \InvalidArgumentException("Unsupported color [$color]");
    }

    public static function createCarFromClass($class)
    {
        switch ($class)
        {
            case 'B':

            return static::createCar('Suzuki');

            case 'C':

            return static::createCar('Toyota');
        }

        throw new \InvalidArgumentException("Unsupported car class [$class]");

    }
}
```

正如你所看到的，在这种方法中，相同的`carFactory()`类被用于`Suzuki`和`Toyota`，因为在这个例子中，这两个品牌都会有相同的流程来创建汽车的核心。质量类和颜色是在汽车核心生产后设置的。设置了这些之后，对于颜色和质量类的选择，我们可以直接调用相应品牌的类。假设我们要购买 B 级车。现在，因为代码知道哪个品牌生产 B 级车，它将直接调用`Suzuki`。这个模型可以有一个控制器，就像下面的代码中所看到的那样：

```php
<?php

class CarController extends BaseController{

    public function showCarsByManufacturer($manufacturerName){

        return CarFactory::createCar($manufacturerName);

    }

    public function showCarsByColor($color){

        return CarFactory::createCarFromColor($color);

    }

    public function showCarsByClass($className){

        return CarFactory::createCarFromClass($className);

    }

}
```

这种方法的三条不同路线如下：

```php
Route::get(
'cars/{manufacturer}', 
array(
'as'    => 'cars_by_manufacturer', 
'uses' => 'CarController@showCarsbyManufacturer'
)
);

Route::get(
'cars/color/{color}', 
array(
'as' => 'cars_by_color',
'uses' => 'CarController@showCarsbyColor'
)
);

Route::get(
'cars/class/{class}',
array(
'as' => 'cars_by_class',
'uses' => 'CarController@showCarsbyClass'
)
);
```

在这种情况下，除了工厂模式，像这三条路线一样的方法对于 URL 的丰富性，易用性和网站的搜索引擎优化都是很好的实践。

## 建造者模式

我们在第五章中讨论了* Laravel 中的设计模式*，在某种程度上，建造者模式是将较大的对象分解为较小对象并使它们可重用的一种方法。

在这个小节中，就像在第五章的例子中一样，让我们假设我们正在烘烤一种具有特定属性的比萨，比如意大利比萨和小/大比萨：

![建造者模式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/lrv-dsn-ptn-best-prac/img/Image00013.jpg)

假设我们有一个自动加载的类如下：

```php
<?php

class PizzaDelivery
{
    protected $pizza;

    protected $config = array();

    public function __construct(array $config)
    {
        $this->pizza = new PizzaBuilder();
        $this->setConfig($config);
    }

    /**
    * Process some configuration parameters
    *
    * @param array $config
    */
    protected function setConfig(array $config)
    {
        $defaults = array(
            'spice' => true,
            'type' => 'Italian',
            'size' => 'Small',
        );

        $config =  array_replace($defaults, $config);
        $this->config = $config;
    }

    /**
    * Build the pizza using the supplied configuration parameters
    * From the constructor that is set using setConfig() method.
    *

    * @return null
    */
    public function build()
    {
        foreach ($this->config as $option => $value) {
            $method = sprintf('set%s', ucfirst($option));
            if (method_exists($this->pizza, $method) === true) {
                call_user_func(array($this->pizza, $method), $value);
            }
        }
    }

    /**
    * @return Pizza
    */
    public function getPizza()
    {
        return $this->pizza;
    }
}
```

正如你所看到的，我们注入了一个建造者，`PizzaBuilder`类，其中包括两位厨师：一个是意大利比萨制作人，另一个是亚洲比萨制作人。在这种方法中，`PizzaBuilder`类可以编码如下：

```php
<?php
class PizzaBuilder
{
    protected $type = '';
    protected $size = '';
    protected $spice = '';
    public function setSpice($spice)
    {
        $this->spice = $spice;
    }

    public function setSize($size)
    {
        $this->size = $size;
    }

    public function setType($type)
    {
        $this->type = $type;
    }
}
```

正如你所看到的，它包含了烘烤比萨所需的所有基本材料，但属性是通过模型类外部定义的，使用诸如`setType()`和`setSize()`之类的方法。通过这种方法，只需定义属性，而不用考虑其他方面，我们就可以直接从服务员(`PizzaDelivery`)那里制作并获得我们的比萨。如果我们需要获得亚洲比萨，我们可以在应用程序的任何地方调用以下代码：

```php
$myFavoritePizza = new PizzaDelivery(array('type' => 'Asian'));
$myFavoritePizza ->build();
return $myFavoritePizza->get();
```

## 策略模式

正如你可能从第五章中所记得的，策略模式用于根据其任务将逻辑分成较小的部分，以便这些部分可以被重用。

在我们为这种方法编写的示例应用程序中，我们将为不同的包裹承运人制作一个包裹运输计算应用程序。假设我们有一个如下所示的类：

```php
<?php

interface ShipmentPricingStrategy {

    function shipmentPrice();

}

abstract class ShippingPriceStrategy implements ShipmentPricingStrategy {
    function __construct() {}
    abstract function shipmentPrice();
}

class FedexPriceStrategy extends ShippingPriceStrategy {

    function shipmentPrice() {
        return 4.95;
    }
}

class UpsPriceStrategy extends ShippingPriceStrategy {

    function shipmentPrice() {
        return 3.75;
    }
}

class Shipping {

    public $shipping_pricing_structure;

    function __construct(ShippingPriceStrategy $shipment_pricing_strategy) {

        $this->shipping_pricing_structure = $shipment_pricing_strategy;

    }
}
```

正如你在代码中所看到的，在`Shipping`类中，我们已经注入了`ShippingPriceStrategy`。这种策略模式对于每个承运人（在我们的例子中是`shipmentPrice()`）都有特点。通过这种方法，对于不同的运输承运人，我们可以显示不同的运输价格，并将它们包括在我们的运输过程中，这将在我们的`Shipping`类中定义。这样，我们在显示运输价格和计算运输过程的总和时都使用了策略模式中设置的价格。

假设类是自动加载的，我们可以在示例中使用具有策略模式的类，如下所示：

```php
<?php

$cart_total = 77.90;

$fedex_price = new Shipping(new FedexPriceStrategy());

$ups_price = new Shipping(new UpsPriceStrategy());

$ups_price_with_cart = $cart_total+$ups_price->shipping_pricing_structure->shipmentPrice();

$fedex_price_with_cart = $cart_total+$fedex_price->shipping_pricing_structure->shipmentPrice();

echo 'The cost of this order with Fedex is: '.$fedex_price_with_cart."\n";

echo 'The cost of this order with UPS is: '.$ups_price_with_cart."\n";
```

正如你所看到的，对于相同的运输过程（`Shipping`类），通过为两个品牌注入不同的运输策略，我们成功地因为策略的不同而获得了不同的运输价格。

## 存储库模式

使用存储库模式的主要原因是提供抽象和灵活性。例如，假设你要从数据库中获取产品。在 Laravel 中，默认情况下，在控制器中使用 Eloquent ORM，并将其传递给视图。这样，你的控制器知道你正在使用 Eloquent ORM 从数据源/数据库中获取数据。对于小型应用程序，这应该没有问题，但在更大的应用程序中，可能会出现问题。将来，由于某种原因，你可能想要放弃使用 Eloquent ORM 的 MySQL，并可能需要在 MongoDB 中使用另一个 ORM。当发生这种情况时，因为控制器知道你正在使用 Eloquent ORM，你将不得不逐个查找每个控制器（或任何其他层）并进行更改。另一个限制是你无法对这段代码进行单元测试。

如果你使用存储库，这种情况就不会发生。如果你这样做，控制器将只与存储库连接，而存储库将处理其他相关层。因此，控制器不会知道数据是如何获取的（抽象）。这样，在更大的应用程序中，管理或测试应该更容易。

要理解这种方法，首先假设我们有`ProductsController`和`Product`模型，并且我们想要获取给定 ID 的产品以及另一个方法来转储所有产品。控制器会看起来像这样：

```php
<?php

Class ProductsController extends \BaseController {

   public function findProduct($id) {
      $product = Product::find($id);
      return View::make('product')
         ->with('product', $product);
   }

   public function allProducts() {
      $products = Product::all();
      return View::make('all_products')
         ->with('products', $products);
   }

}
```

这种方法存在一个缺陷。如果你正在测试这样编写的代码，并且出现错误，除非`Whoops`（Laravel 中使用的错误处理程序库）处于活动状态，否则你无法直接检测错误的来源。在这种情况下，存储库是有帮助的，因为它们提取了逻辑。注入存储库的一种方法是在控制器的构造方法中定义并设置它。

让我们将这个存储库命名为`EloquentProductRepository`，它是`\Acme\Repositories`命名空间的一部分。我们的控制器将变成以下内容：

```php
<?php

//We use the repository in our class
use Acme\Repositories\EloquentProductRepository;

Class ProductsController extends \BaseController {

   //A protected variable to hold the Repository
   protected $product;

   //Let's define a constructor class, and assigning to the variable $product 
   public function __construct(EloquentProductRepository $product) {
      $this->product = $product;
   }

   public function findProduct($id) {
      //$product = Product::find($id);
      $product = $this->product->find($id);
      return View::make('product')
         ->with('product', $product);
   }

   public function allProducts() {
      //$products = Product::orderBy('id', 'desc')->get();
      //let's give it a unique method name
      $products = $this->product->getNewest();
      return View::make('all_products')
         ->with('products', $products);
   }

}
```

请注意，我们不再使用`orderBy('id', 'desc')->get()`，而是给出了一个新的方法名`getNewest()`。现在让我们创建这个存储库。假设我们在`Acme\Repositories`文件夹中有一个名为`EloquentProductRepository.php`的文件。看一下以下代码：

```php
<?php namespace Acme\Repositories;

Class EloquentProductRepository {

   public function getNewest() {

      return \Order::orderBy('id', 'desc')->get();

   }

   public function find($id) {
      return \Order::find($id);
   }

}
```

对于使用的每个方法，一旦在存储库中，你需要定义函数。这种方法的一个主要优势是它带来了灵活性。假设你将使用模拟，或者将来从 Eloquent ORM 切换到具有完全不同方法名称的其他 ORM。如果你使用了存储库，只需要在控制器中更改使用的存储库，其他什么都不需要改变。你不需要深入所有的控制器、模型或其他组件。

这里仍然存在一个缺陷。我们的控制器仍然知道我们正在使用特定于 Eloquent 的存储库。为了更好的方法和抽象，我们的控制器不应该知道我们正在使用什么样的存储库。为了确保这一点，我们将不得不为此编写一个接口。

现在，在相同的命名空间路径中创建一个接口（不是强制的；只要加载了就可以创建在任何地方），名为`ProductInterface`。然后我们的控制器会像这样：

```php
<?php

//We use the interface in our class
use Acme\Repositories\ProductInterface;

Class ProductsController extends \BaseController {

   //A protected variable to hold the Interface
   protected $product;

   //Let's define a constructor class, and inject the interface as $product variable
   public function __construct(ProductInterface $product) {
      $this->product = $product;
   }

   public function findProduct($id) {
      //$product = Product::find($id);
      $product = $this->product->find($id);
      return View::make('product')
         ->with('product', $product);
   }

   public function allProducts() {
      //$products = Product::orderBy('id', 'desc')->get();
      //let's give it a unique method name
      $products = $this->product->getNewest();
      return View::make('all_products')
         ->with('products', $products);
   }

}
```

接口被注入并使用，而不是存储库。现在让我们编写`ProductInterface`接口：

```php
<?php namespace Acme\Repositories;

interface ProductInterface {

   public function getNewest();
   public function find();

}
```

正如你所看到的，接口保存了方法名称，这些方法实际上是实现存储库的可用方法。现在让我们将这个接口实现到我们的存储库中来连接它们：

```php
<?php namespace Acme\Repositories;

Class EloquentProductRepository implements ProductInterface {

   public function getNewest() {
      return \Order::orderBy('id', 'desc')->get();

   }

   public function find($id) {
       return \Order::find($id);
   }

}
```

这种实现有一个优势。假设您在存储库中实现了一个接口，但缺少`getNewest()`自定义方法。由于这种实现，接口将直接告诉您它需要特定的方法并且缺少它。

最后，我们需要将接口绑定到存储库。其中一种方法是使用 Laravel 内置的`App:bind();`方法。要将我们刚刚创建的存储库绑定到接口，将这行代码添加到您的`app/routes.php`文件或任何其他自动加载的文件中。

```php
App::bind(
'Acme\Repositories\ProductInterface', 
'Acme\Repositories\EloquentProductRepository'
);
```

另一种将这两者绑定在一起的方法是创建一个服务提供者。让我们编写一个如下的服务提供者：

```php
<?php namespace Acme\Repositories;

use Illuminate\Support\ServiceProvider;

class UserServiceProvider extends ServiceProvider {

    public function register()
    {
        $this->app::bind('Acme\\Repositories\\ProductInterface', 'Acme\Repositories\EloquentProductRepository');
    }
}
```

我们假设这个提供者在`namespace Acme\Repositories`文件夹中。我们还使用了`Illuminate\Support\ServiceProvider`来扩展我们的类。在公共方法 register 中，我们将接口绑定到我们的产品存储库。

将来，如果您想切换到 MongoDB 或您编码的任何其他接口，您只需将`EloquentRepositoryInterface`切换到新的接口。它将在应用程序的所有位置进行更新。

# 摘要

在本章中，我们看到了在 Laravel 和一般开发过程中使用的设计模式和架构的基本和高级实践示例。我们学习了各种设计模式的优点，并为每一种设计模式引用了真实世界的例子。

设计模式的存在是为了让你的生活更轻松。如果开发没有遵循任何模式或架构，随着应用程序的增长，每次重构和实现功能都会变得更加困难。此外，如果另一个开发人员加入项目，他或她首先需要了解各个方面。这可能会导致膨胀、性能不佳、缺乏灵活性以及一系列难以修复的错误。应用程序将成为一个随时准备爆炸的定时炸弹。设计和架构模式的存在是为了帮助您预防这些问题。不仅在您的 Laravel 应用程序中，在您开发的任何东西中，随着应用程序的增长，为了保持一切都在控制之下，您必须使用设计模式或它们的组合。最终，总有一天你会感谢自己使用这些模式。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享
