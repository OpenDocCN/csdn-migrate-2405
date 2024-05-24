# Angular .NET 开发学习手册（二）

> 原文：[`zh.annas-archive.org/md5/1D7CD4769EDA3E96BB350F0A5265564A`](https://zh.annas-archive.org/md5/1D7CD4769EDA3E96BB350F0A5265564A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第四章：使用 TypeScript 与 Angular

本章讨论了 TypeScript 的基本原理以及使用 TypeScript 编写 Angular 应用程序的好处。

在这一章中，我们将涵盖以下主题：

+   什么是 TypeScript？

+   基本类型

+   接口

+   类

+   模块

+   函数

+   泛型

+   装饰器

+   TypeScript 和 Angular

## 什么是 TypeScript？

* * *

TypeScript 是由微软开发和维护的开源编程语言。它是 JavaScript 的超集，并且方便编写面向对象的编程。它应该与 JavaScript 一起编译，以在任何浏览器上运行。

TypeScript 提供了最好的工具和高级的自动完成、导航和重构功能。它用于开发客户端和服务器端的 JavaScript 应用程序。借助类、模块和接口，我们可以使用 TypeScript 构建强大的组件。

它相对于 JavaScript 提供的主要优势在于，它能够在编译时进行类型检查以避免错误。由于类型转换问题，可以避免意外的运行时错误。此外，它提供了写面向对象编程的语法糖。

## 基本类型

* * *

在编程语言中，我们处理各种小单位的数据，比如`numbers`、`sting`和布尔值。TypeScript 支持这些类型的数据，与 JavaScript 一样，支持枚举和结构类型。

### 布尔值

布尔数据类型可以保存`true`或`false`。声明和初始化这种数据类型非常简单，如下所示：

```ts
let isSaved: boolean = false; 
```

在这里，`isSaved`变量被声明为`boolean`类型，并赋值为`false`。如果开发人员错误地将一个字符串值赋给`isSaved`变量，TypeScript 会显示错误并突出显示该语句。

### 数字

数字数据类型保存浮点值。与 JavaScript 类似，TypeScript 将所有数字视为浮点值。声明和初始化数字数据类型变量可以使用以下方法：

```ts
let price: number = 101; 
```

在这里，`price`变量被声明为`number`类型，并赋值为 101。Number 类型可以包含十进制、二进制、十六进制和八进制等不同的值，如下所示：

```ts
let decimal: number = 6; 
let hex: number = 0xf00d; 
let binary: number = 0b1010; 
let octal: number = 0o744; 
```

### 字符串

字符串数据类型可以保存一系列字符。声明和初始化`string`变量非常简单，如下所示：

```ts
let authorName: string = "Rajesh Gunasundaram"; 
```

在这里，我们声明了一个名为`authorName`的变量，类型为`string`，并赋值为"`Rajesh Gunasundaram`"。TypeScript 支持使用双引号(")或单引号(')括起来的`string`值。

### 数组

数组数据类型用于保存特定类型的值的集合。在 TypeScript 中，我们可以以两种方式定义`array`，如下所示：

```ts
var even:number[] = [2, 4, 6, 8, 10]; 
```

这个语句声明了一个`number`类型的数组变量，使用`number`数据类型后的方括号([])，并赋值为从 2 到 10 的一系列偶数。定义数组的第二种方法是这样的：

```ts
let even:Array<number> = [2, 4, 6, 8, 10]; 
```

这个语句使用了泛型的数组类型，它使用了`Array`关键字后面跟着包裹`number`数据类型的尖括号（<>）。

### 枚举

枚举数据类型将具有一组命名的值。我们使用枚举器为识别某些值的常量提供友好名称：

```ts
enum Day {Mon, Tue, Wed, Thu, Fri, Sat, Sun}; 
let firstDay: Day = Day.Mon; 
```

在这里，我们有`enum`类型`Day`变量，它包含代表一周中每一天的值的系列。第二个语句展示了如何访问一天中的特定`enum`值并将其赋值给另一个变量。

### 任意

`Any`数据类型是一个可以容纳`任何`值的动态数据类型。如果将 string 类型的变量赋给整数类型的变量，TypeScript 会抛出编译时错误。如果您不确定变量将持有什么值，并且希望在赋值时免除编译器对类型的检查，您可以使用`Any`数据类型：

```ts
let mixedList:any[] = [1, "I am string", false]; 
mixedList [2] = "no you are not"; 
```

在这里，我们使用了任意类型的数组，因此它可以容纳任何类型，比如`number`，`string`和`boolean`。

### 任何

Void 实际上是什么都没有。它可用作函数的返回类型，声明这个函数不会返回任何值：

```ts
function alertMessage(): void { 
    alert("This function does not return any value"); 
} 
```

## 接口

* * *

接口是定义类行为的抽象类型。它为可以在客户端之间交换的对象提供类型定义。这使得客户端只能交换符合接口类型定义的对象；否则，我们会得到编译时错误。

在 TypeScript 中，接口定义了您代码内部和项目外部的对象的约束。让我们看一个示例，介绍如何在 TypeScript 中使用：

```ts
function addCustomer(customerObj: {name: string}) { 
  console.log(customerObj.name); 
} 
let customer = {id: 101, name: "Rajesh Gunasundaram"}; 
addCustomer(customer); 
```

类型检查器验证了`addCustomer`方法调用并检查了其参数。`addCustomer`期望一个具有`string`类型的`name`属性的对象。然而，调用`addCustomer`的客户端传递了一个具有`id`和`name`两个参数的对象。

然而，编译器会忽略对`id`属性的检查，因为它不在`addCustomer`方法的参数类型中。对于编译器来说，重要的是所需的属性是否存在。

让我们演示将`interface`作为参数类型重写方法：

```ts
interface Customer { 
  name: string; 
} 
function addCustomer(customerObj: Customer) { 
  console.log(customerObj.name); 
}  
let customer = {id: 101, name: "Rajesh Gunasundaram"}; 
addCustomer(customer); 
Customer interface. It only looks for the name property of the string type in the parameter and then allows it if present.
```

### 可选属性

在某些情况下，我们可能只想为最小的参数传递值。在这种情况下，我们可以将接口中的属性定义为可选属性，如下所示：

```ts
interface Customer { 
  id: number; 
  name: string; 
  bonus?: number; 
}  
function addCustomer(customer: Customer) {  
  if (customer.bonus) { 
    console.log(customer.bonus); 
  } 
}  
addCustomer({id: 101, name: "Rajesh Gunasundaram"}); 
```

在这里，`bonus`属性通过在`name`属性末尾添加问号（?）来定义为可选属性。

### 函数类型接口

我们刚刚看到了如何在接口中定义属性。类似地，我们也可以在接口中定义函数类型。我们可以通过给出带有返回类型的函数签名来在接口中定义函数类型。请注意，在下面的代码片段中，我们没有添加函数名：

```ts
interface AddCustomerFunc { 
  (firstName: string, lastName: string); void 
} 
```

现在，`AddCustomerFunc`准备好了。让我们定义一个函数类型变量，`AddCustomerFunc`，并将具有相同签名的函数赋值给它，如下所示：

```ts
let addCustomer: AddCustomerFunc; 
addCustomer = function(firstName: string, lastName: string) { 
  console.log('Full Name: ' + firstName + ' ' + lastName); 
} 
```

函数签名中的参数名可以变化，但数据类型不能变化。例如，我们可以修改字符串类型的`fn`和`ln`函数参数，如下所示：

```ts
addCustomer = function(fn: string, ln: string) {
console.log('Full Name: ' + fn + ' ' + ln);
} 
```

因此，如果我们改变此处参数的数据类型或函数的返回类型，编译器将抛出关于参数不匹配或返回类型不匹配`AddCustomerFunc`接口的错误。

### **数组类型接口**

我们还可以为数组类型定义一个接口。我们可以指定`index`数组的数据类型和数组项的数据类型，如下所示：

```ts
interface CutomerNameArray { 
  [index: number]: string; 
}  
let customerNameList: CutomerNameArray; 
customerNameList = ["Rajesh", "Gunasundaram"]; 
```

TypeScript 支持`number`和`string`两种类型的`index`。此数组类型接口还强制数组的返回类型与声明匹配。

### **类类型接口**

类型接口定义了类的约定。实现接口的类应满足接口的要求：

```ts
interface CustomerInterface { 
    id: number; 
    firstName: string; 
    lastName: string; 
    addCustomer(firstName: string, lastName: string); 
    getCustomer(id: number): Customer; 
}  
class Customer implements CustomerInterface { 
    id: number; 
    firstName: string; 
    lastName: string; 
    constructor() { } 
    addCustomer(firstName: string, lastName: string): void { 
        // code to add customer 
    } 
    getCustomer(id: number): Customer { 
        // code to return customer where the id match with id parameter 
    } 
}  
```

类类型接口只处理类的公共成员。因此，不可能向接口添加私有成员。

### **扩展接口**

接口可以进行扩展；扩展一个接口使其共享另一个接口的属性，如下所示：

```ts
interface Manager { 
    hasPower: boolean; 
}
interface Employee extends Manager { 
    name: string; 
} 
let employee = <Employee>{}; 
employee.name = "Rajesh Gunasundaram"; 
employee.hasPower = true; 
```

这里，`Employee`接口扩展了`Manager`接口，并将`hasPower`与`Employee`接口共享。

### **混合类型接口**

当我们希望将对象既作为函数又作为对象使用时，就会使用混合类型接口。如果对象实现了混合类型接口，我们可以像调用函数一样调用对象，或者我们可以将其作为对象使用并访问其属性。这种类型的接口使您能够将一个接口用作对象和函数，如下所示：

```ts
interface Customer { 
    (name: string): string; 
    name: string; 
    deleteCustomer(id: number): void; 
} 
let c: Customer; 
c('Rajesh Gunasundaram'); 
c.name = 'Rajesh Gunasundaram'; 
c.deleteCustomer(101); 
```

## **Classes**

* * *

类是一个可扩展的模板，用于创建具有成员变量以保存对象状态和处理对象行为的成员函数的对象。

当前版本的 JavaScript 仅支持基于函数和基于原型的继承来构建可重用组件。JavaScript 的下一个版本 ECMAScript 6 支持面向对象编程，通过添加原型化类定义和继承的语法糖。然而，TypeScript 使开发人员能够使用面向对象编程技术编写代码，并将代码编译为与所有浏览器和平台兼容的 JavaScript：

```ts
class Customer { 
    name: string; 
    constructor(name: string) { 
        this.name = name; 
    } 
    logCustomer() { 
        console.log('customer name is ' + this.name); 
    } 
}  
let customer = new Customer("Rajesh Gunasundaram"); 
```

此`Customer`类有三个成员：`name`属性、构造函数和`logCustomer`方法。`Customer`类外的最后一条语句使用`new`关键字创建`customer`类的一个实例。

## **Inheritance**

* * *

继承是指继承另一个类或对象的一些行为的概念。它有助于实现代码的可重用性，并建立类或对象之间的关系层次结构。此外，继承可以帮助您对相似的类进行强制转换。

ES5 标准的 JavaScript 不支持类，因此在 JavaScript 中无法进行类继承。但是，我们可以通过原型继承来实现类继承。让我们看看 ES5 中的继承示例。

首先，创建一个名为`Animal`的函数，如下所示。在这里，我们创建一个名为`Animal`的函数，其包含两个方法：`sleep`和`eat`：

```ts
var Animal = function() { 
    this.sleep = function() { 
       console.log('sleeping'); 
    } 
    this.eat = function() { 
       console.log('eating'); 
    } 
} 
```

现在，让我们使用原型扩展这个`Animal`函数，如下所示：

```ts
Animal.prototype.bark = function() { 
    console.log('barking'); 
} 
```

现在，我们可以创建`Animal`的实例并调用扩展函数 bark，如下所示：

```ts
var a = new Animal(); 
a.bark(); 
```

我们可以使用`Object.Create`方法来克隆父级原型并创建一个子对象。然后，我们可以通过添加方法来扩展子对象。让我们创建一个名为`Dog`的对象，并从`Animal`继承它：

```ts
var Dog = function() { 
    this.bark = new function() { 
       console.log('barking'); 
    } 
} 
```

现在，让我们克隆`Animal`的原型，并继承`Dog`函数中的所有行为。然后，我们可以使用`Dog`实例调用`Animal`方法，如下所示：

```ts
Dog.prototype = Object.create(animal.prototype); 
var d = new Dog(); 
d.sleep(); 
d.eat(); 
```

### TypeScript 中的继承

我们刚刚看到了如何使用原型在 JavaScript 中实现继承。现在，我们将看到如何在 TypeScript 中实现继承。

在 TypeScript 中，类接口可以扩展，而且我们也可以通过继承另一个类来扩展一个类，如下所示：

```ts
class SimpleCalculator { 
    z: number; 
    constructor() { } 
    addition(x: number, y: number) { 
        z = x + y; 
    } 
    subtraction(x: number, y: number) { 
        z = x - y; 
    } 
}  
class ComplexCalculator extends SimpleCalculator { 
    constructor() { super(); } 
    multiplication(x: number, y: number) { 
        z = x * y; 
    } 
    division(x: number, y: number) { 
        z = x / y; 
    } 
} 
var calculator = new ComplexCalculator(); 
calculator.addition(10, 20); 
calculator.Substraction(20, 10); 
calculator.multiplication(10, 20); 
calculator.division(20, 10); 
```

在这里，我们能够通过扩展`SimpleCalculator`的实例来访问`SimpleCalculator`的方法，因为`ComplexCalculator`扩展了`SimpleCalculator`。

### 私有/公共修饰符

在 TypeScript 中，类中的所有成员默认都是`public`的。我们必须明确添加`private`关键字来控制成员的可见性：

```ts
class SimpleCalculator { 
    private x: number; 
    private y: number; 
    z: number; 
    constructor(x: number, y: number) { 
       this.x = x; 
       this.y = y; 
    } 
    addition() { 
        z = x + y; 
    } 
    subtraction() { 
        z = x - y; 
    } 
} 
class ComplexCalculator { 
    z: number; 
    constructor(private x: number, private y: number) { } 
    multiplication() { 
        z = this.x * this.y; 
    } 
    division() { 
        z = this.x / this.y; 
    } 
} 
```

请注意，在`SimpleCalculator`类中，我们将`x`和`y`定义为`private`属性，这将不会在类外可见。在`ComplexCalculator`中，我们使用参数属性定义了`x`和`y`。这些参数属性将使我们能够在一个语句中创建和初始化成员。在这里，`x`和`y`在构造函数中创建并初始化，而不需要在其中写任何其他语句。同时，`x`和`y`是私有的，以便将它们隐藏起来以避免被外部类或模块访问。

### 访问器

我们还可以对属性实现`getters`和`setters`，以控制客户端对它们的访问。我们可以在设置属性变量的值之前或获取属性变量值之前拦截一些过程：

```ts
var updateCustomerNameAllowed = true; 
Class Customer { 
    Private _name: string; 
    get name: string { 
          return this._name; 
    } 
    set name(newName: string) { 
          if (updateCustomerNameAllowed == true) { 
                this._name = newName; 
          } 
          else { 
                alert("Error: Updating Customer name not allowed!"); 
          } 
    } 
} 
```

这里，`name`属性的`setter`确保顾客的`name`可以更新。否则，它将显示一个不可能的警报消息。

### 静态属性

这些类型的属性不是特定于实例的，并且通过类名而不是使用`this`关键字来访问：

```ts
class Customer { 
     static bonusPercentage = 20; 
     constructor(public salary: number) {  } 
      calculateBonus() { 
          return this.salary * Customer.bonusPercentage/100; 
     } 
} 
var customer = new Customer(10000); 
var bonus = customer.calculateBonus(); 
```

在这里，我们声明了一个`static`变量`bonusPercentage`，在`calculateBonus`方法中使用`Customer`类名访问它。`bonusPercentage`属性不是特定于实例的。

## 模块

* * *

JavaScript 是一种强大而动态的语言。由于根据 ES5 和更早的标准在 JavaScript 中进行动态编程的自由，我们有责任结构化和组织代码。这将使代码的可维护性更容易，并且还可以使我们轻松地定位特定功能的代码。我们可以通过应用模块化模式来组织代码。代码可以分为各种模块，并且相关代码可以放在每个模块中。

TypeScript 使得按照 ECMAScript 6 规范实现模块化编程变得更容易。模块使您能够控制变量的范围，代码的重用性和封装性。TypeScript 支持两种类型的模块：内部和外部。

### 命名空间

我们可以使用 `namespace` 关键字在 TypeScript 中创建命名空间，如下所示。在命名空间下定义的所有类都将在该特定命名空间下使用，并且不会附加到全局范围下：

```ts
namespace Inventory { 
      Class Product { 
             constructor (public name: string, public quantity: number) {   } 
      } 
      // product is accessible 
      var p = new Product('mobile', 101); 
} 
// Product class is not accessible outside namespace 
var p = new Inventory.Product('mobile', 101); 
```

要使 `Product` 类在命名空间外部可用，我们在定义 `Product` 类时需要添加 `export` 关键字，如下所示：

```ts
namespace Inventory { 
      export Class Product { 
             constructor (public name: string, public quantity: number) {   } 
      } 
} 
// Product class is now accessible outside Inventory namespace 
var p = new Inventory.Product('mobile', 101); 
```

我们也可以通过在引用文件的代码开头添加 `reference` 语句来跨文件共享命名空间，如下所示：

```ts
/// <reference path="Inventory.ts" /> 
```

### 模块

TypeScript 也支持模块。由于我们处理大量的外部 JavaScript 库，这个模块将帮助我们引用和组织我们的代码。使用 `import` 语句，我们可以导入外部模块，如下所示：

```ts
Import { inv } from "./Inventory"; 
var p = new inv.Product('mobile', 101); 
```

在这里，我们只是导入了先前创建的模块 `Inventory`，并创建了一个分配给变量 `p` 的 `Product` 实例。

### 函数

遵循 ES5 规范的 JavaScript 不支持类和模块。但是，我们尝试使用 JavaScript 中的函数式编程来实现变量的作用域和模块化。函数是 JavaScript 应用程序的构建块。

尽管 TypeScript 支持类和模块，但函数在定义特定逻辑方面起着关键作用。我们可以在 JavaScript 中定义`function`和`匿名`函数，如下所示：

```ts
//Named function 
function multiply(a, b) { 
    return a * b; 
} 
//Anonymous function 
var result = function(a, b) { return a * b; }; 
```

在 TypeScript 中，我们使用函数箭头符号定义参数的类型和返回类型，这也适用于 ES6；表示如下：

```ts
var multiply(a: number, b: number) => number =  
          function(a: number, b: number): number { return a * b; }; 
```

### 可选和默认参数

假设我们有一个具有三个参数的函数，并且有时在函数中可能只为前两个参数传递值。在 TypeScript 中，我们可以使用可选参数处理这种情况。我们可以将前两个参数定义为正常参数，将第三个参数定义为可选参数，如下面的代码片段所示：

```ts
function CutomerName(firstName: string, lastName: string, middleName?: string) { 
    if (middleName) 
        return firstName + " " + middleName + " " + lastName; 
    else 
        return firstName + " " + lastName; 
} 
//ignored optional parameter middleName 
var customer1 = customerName("Rajesh", "Gunasundaram");  
//error, supplied too many parameters  
var customer2 = customerName("Scott", "Tiger", "Lion", "King");   
//supplied values for all 
var customer3 = customerName("Scott", "Tiger", "Lion");   
```

在这里，`middleName` 是可选参数，在调用函数时可以忽略它。

现在，让我们看看如何在函数中设置默认参数。如果没有为参数提供值，我们可以定义它为配置的默认值：

```ts
function CutomerName(firstName: string, lastName: string, middleName: string = 'No Middle Name') { 
    if (middleName) 
        return firstName + " " + middleName + " " + lastName; 
    else 
        return firstName + " " + lastName; 
} 
```

在这里，`middleName`是默认参数，如果调用者未提供值，则默认值为`'No Middle Name'`。

### 剩余参数

使用剩余参数，可以将值的数组传递给函数。这在您不确定将向函数提供多少值的场景中可以使用：

```ts
function clientName(firstClient: string, ...restOfClient: string[]) { 
   console.log(firstClient + " " + restOfClient.join(" ")); 
} 
clientName ("Scott", "Steve", "Bill", "Sergey", "Larry"); 
```

在这里，注意`restOfClient`剩余参数前缀带有省略号（...），它可以保存一个字符串数组。在函数的调用者中，只有提供的第一个参数的值将被赋给`firstClient`参数，并且剩余的值将被分配给`restOfClient`作为数组值。

## 泛型

* * *

当开发可对抗任何数据类型的可重用组件时，泛型非常有用。因此，使用此组件的客户端将决定它应该对哪种类型的数据进行操作。让我们创建一个简单的函数，该函数返回传递给它的任何数据类型：

```ts
function returnNumberReceived(arg: number): number { 
    return arg; 
} 
function returnStringReceived(arg: string): string { 
    return arg; 
} 
```

正如你所见，我们需要个别方法来处理每种数据类型。我们可以使用`any`数据类型在单个函数中实现相同的功能，如下所示：

```ts
function returnAnythingReceived (arg: any): any { 
    return arg; 
} 
```

这与泛型类似。然而，我们对返回类型没有控制。如果我们传递一个数字，并且无法预测函数是否会返回该数字，函数的返回类型可以是任意类型。

泛型提供了`T`类型的特殊变量。将此类型应用到函数中，如所示，使客户端能够传递他们希望该函数处理的数据类型：

```ts
function returnWhatReceived<T>(arg: T): T { 
    return arg; 
} 
```

因此，客户端可以为各种数据类型调用此函数，如所示：

```ts
var stringOutput = returnWhatReceived<string>("return this"); // type of output will be 'string' 
var numberOutput = returnWhatReceived<number>(101); // type of output will be number 
```

请注意，在函数调用中，应该将要处理的数据类型通过尖括号（`<>`）进行包裹传递。

### 泛型接口

我们还可以使用类型变量`T`来定义泛型接口，如下所示：

```ts
interface GenericFunc<T> { 
    (arg: T): T; 
} 
function func<T>(arg: T): T { 
    return arg; 
} 
var myFunc: GenericFunc<number> = func; 
```

在这里，我们定义了一个泛型接口和`myFunc`变量的`GenericFunc`类型，将数字数据类型传递给类型变量`T`。然后，将该变量分配给名为`func`的函数。

### 泛型类

与泛型接口类似，我们也可以定义泛型类。我们使用尖括号（`<>`）中的泛型类型来定义类，如下所示：

```ts
class GenericClass<T> { 
    add: (a: T, b: T) => T; 
}  
var myGenericClass = new GenericClass<number>(); 
myGenericClass.add = function(a, b) { return a + b; }; 
```

在这里，通过将泛型数据类型传递为`number`，实例化了泛型类。因此，`add`函数将处理并加上作为参数传递的两个数字。

## 装饰器

* * *

装饰器使我们能够通过添加行为来扩展类或对象，而无需修改代码。装饰器用额外功能包装类。它们可以附加到类、属性、方法、参数和访问器。在 ECMAScript 2016 中，装饰器被提议用于修改类的行为。装饰器用`@`符号和解析为在`runtime`调用的函数的装饰器名称进行前缀。

```ts
@authorize decorator on any other class:
```

```ts
function authorize(target) { 
    // check the authorization of the use to access the "target" 
} 
```

### 类装饰器

类装饰器是在类声明之前声明的。类装饰器可以通过应用于该类的构造函数来观察、修改和替换类的定义。TypeScript 中`ClassDecorator`的签名如下所示：

```ts
declare type ClassDecorator = <TFunction extends Function>(target: TFunction) => TFunction | void; 
```

假设有一个`Customer`类，我们希望该类被冻结。其现有属性不应被移除，也不应添加新属性。

我们可以创建一个单独的类，可以接受任何对象并将其冻结。然后，我们可以使用`@freezed`装饰器来装饰`Customer`类，以防止从类中添加新属性或移除现有属性：

```ts
@freezed 
class Customer {  
  public firstName: string; 
  public lastName: string; 
  constructor(firstName : string, lastName : string) {  
    this.firstName = firstName; 
    this.lastName = lastName; 
  } 
} 
freezed decorator:
```

```ts
function freezed(target: any) { 
    Object.freeze(target); 
} 
```

在这里，`freezed`装饰器获取`target`，即正在被装饰的`Customer`类，并在执行时将其冻结。

### 方法装饰器

方法装饰器是在方法声明之前声明的。此装饰器用于修改、观察或替换方法定义，并且应用于方法的属性描述符。下面的示例代码显示了一个应用了方法装饰器的简单类：

```ts
class Hello { 
    @logging 
    increment(n: number) { 
        return n++; 
    } 
} 
logging function:
```

```ts
function logging(target: Object, key: string, value: any) { 
            value = function (...args: any[]) { 
            var result = value.apply(this, args); 
            console.log(JSON.stringify(args)) 
            return result; 
        } 
    }; 
} 
```

方法装饰器函数接受三个参数：`target`，`key`和`value`。`target`参数保存了正在被装饰的方法；`key`保存了被装饰方法的名称，`value`是指定对象上存在的特定属性的属性描述符。

当调用`increment`方法时，`logging`装饰器被调用，并且`values`参数被传递给它。`logging`方法将在控制台上记录有关传递的参数的详细信息。

### 访问器装饰器

Accessor decorators are prefixed before the accessor declaration. These decorators are used to observe, modify, or replace an accessor definition and are applied to the property descriptor. The following code snippet shows a simple class with the accessor decorator applied:

```ts
class Customer {  
  private _firstname: string; 
  private _lastname: string; 
  constructor(firstname: string, lastname: string) { 
        this._firstname = firstname; 
        this._lastname = lastname; 
  } 
  @logging(false) 
  get firstname() { return this._firstname; } 
  @logging(false) 
  get lastname() { return this._lastname; } 
} 
@logging decorator:
```

```ts
function logging(value: boolean) { 
    return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) { 
        descriptor.logging = value; 
    }; 
} 
```

`logging`函数将`Boolean`值设置为`logging`属性描述符。

### 属性装饰器

属性装饰器是前缀到属性声明。在 TypeScript 源代码中，`PropertyDecorator`的签名是这样的：

```ts
declare type PropertyDecorator = (target: Object, propertyKey: string | symbol) => void; 
firstname property is decorated with the @hashify property decorator:
```

```ts
class Customer {  
  @hashify 
  public firstname: string; 
  public lastname: string; 
  constructor(firstname : string, lastname : string) {  
    this.firstname = firstname; 
    this.lastname = lastname; 
  } 
} 
@hashify property decorator function:
```

```ts
function hashify(target: any, key: string)
 { 
  var _value = this[key];
  var getter = function ()
    { 
        return '#' + _value; 
    }; 
  var setter = function (newValue)
   { 
      _value = newValue; 
    }; 
  if (delete this[key])
 { 
    Object.defineProperty(target, key,
 { 
      get: getter, 
      set: setter, 
      enumerable: true, 
      configurable: true 
    }); 
  } 
} 
```

`_value`变量保存了被装饰的属性的值。`getter`和`setter`函数都可以访问`_value`变量，在这里，我们可以通过添加额外行为来操纵`_value`变量。我在`getter`中连接了`#`来返回标记的名字。然后，使用`delete`操作符从类原型中删除原始属性。然后，一个新属性将会被创建，拥有原始属性名和额外的行为。

### 参数装饰器

参数装饰器是前缀到参数声明，并且它们应用于类构造函数或方法声明的函数。这是`ParameterDecorator`的签名：

```ts
declare type ParameterDecorator = (target: Object, propertyKey: string | symbol, parameterIndex: number) => void; 
```

现在，让我们定义`Customer`类，并使用参数装饰器来装饰一个参数，以使其必需，并验证其是否被提供：

```ts
class Customer { 
    constructor() {    } 
    getName(@logging name: string) { 
        return name; 
    } 
} 
```

在这里，name 参数已经被 `@logging` 装饰器修饰。参数装饰器隐式接收三个输入，即带有该装饰器的类的原型，带有该装饰器的方法的名称，以及被装饰的参数的索引。参数装饰器 `logging` 的实现如下所示：

```ts
function logging(target: any, key : string, index : number) {  
  console.log(target); 
  console.log(key); 
  console.log(index); 
} 
```

在这里，`target` 是带有装饰器的类，`key` 是函数名，`index` 包含参数索引。这段代码仅将 `target`、`key` 和 `index` 记录在控制台中。

## TypeScript 和 Angular

* * *

正如你在本章中所见，TypeScript 具有强大的类型检查能力，并支持面向对象编程。由于这些优势，Angular 团队选择了 TypeScript 来构建 Angular。Angular 完全重写了核心代码，使用 TypeScript，并且它的架构和编码模式完全改变了，就像你在 第二章 和 第三章 中看到的，*Angular 基本构件部分 1* 和 *Angular 基本构件部分 2*。因此，使用 TypeScript 编写 Angular 应用是最佳选择。

我们可以在 Angular 中实现类似 TypeScript 中的模块。Angular 应用中的组件实际上是一个带有 `@Component` 装饰器的 TypeScript 类。使用 import 语句可以将模块导入到当前的类文件中。`export` 关键字用于指示该组件可以在另一个模块中被导入和访问。使用 TypeScript 开发的示例组件代码如下所示：

```ts
import {Component} from '@angular/core' 
@Component({ 
  selector: 'my-component', 
  template: '<h1>Hello my Component</h1>' 
}) 
export class MyComponent { 
  constructor() {  } 
} 
```

## 总结

* * *

Voila! 现在你已经学会了 TypeScript 语言的基础知识。我们首先讨论了 TypeScript 是什么以及它的优势。然后，你学习了 TypeScript 中各种数据类型，并附有示例。我们还深入讲解了 TypeScript 中的面向对象编程和接口、类、模块、函数和泛型，并提供了示例。接下来，你学习了各种类型的装饰器及其实现方法，并给出了示例。最后，我们看到了为什么我们应该使用 TypeScript 来编写 Angular 应用以及使用 TypeScript 编写 Angular 应用的好处。

在下一章中，我们将讨论如何使用 Visual Studio 创建 Angular 单页面应用程序。


## 第五章：在 Visual Studio 中创建 Angular 单页应用程序

本章将指导您通过使用 Visual Studio 创建 Angular **单页应用程序** （**SPA**）的过程。

在本章中，我们将涵盖以下主题：

+   创建一个 ASP.NET Core web 应用程序

+   使用 NPM 软件包管理器添加客户端软件包

+   使用 Gulp 运行任务

+   添加 Angular 组件和模板

## 创建一个 ASP.NET Core web 应用程序

* * *

让我们从创建 ASP.NET Core web 应用程序开始这一章。我假设您在开发环境中已经安装了 Visual Studio 2017 或更新版本。按照以下步骤创建应用程序：

1.  打开 Visual Studio，然后通过导航到 `File` | `New` | `Project` 来点击菜单项。

1.  从安装模板中导航到 **`Visual C#`**，然后选择 **`Web`**。

1.  然后，选择 **`ASP.NET Core Web Application`** 并输入应用程序名称为 `My Todo`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_001.png)

创建名为 My Todo 的项目

1.  选择 **`ASP.NET Core Empty`** 模板，然后点击 **`Ok`** 创建项目，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_002.png)

选择一个空的 ASP.NET Core 模板

我们创建的 `My Todo` 应用程序的解决方案结构如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_003.png)

My Todo 的默认解决方案结构

`Startup` 类是 ASP.NET Core web 应用程序的入口点。 `Startup` 类中的 `Configure` 方法用于设置用于处理应用程序中所有请求的请求管道。在这里，`Startup` 类的默认代码被配置为默认返回 `Hello World!` 文本：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_004.png)

`Startup` 类的默认代码

所以，当您运行应用程序时，您将在浏览器中获得以下输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_005.png)

'My Todo' 项目的默认输出

现在，让我们让应用程序为任何请求提供默认页面。按照以下步骤进行操作：

1.  选择 `My Todo` 项目下的 `wwwroot` 文件夹。右键单击选择项目，转到 **`Add`**，然后点击 **`New Item`**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_006.png)

转到添加新项目菜单

1.  在 **`Add New Item`** 窗口中，点击 **`Web`** 下的 **`Content`**，然后从中心窗格中选择 **`HTML Page`**。输入 `index.html` 作为文件名，然后点击 **`Add`**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_007.png)

将 HTML 文件命名为 index.html

1.  更新 `index.html` 文件的内容如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_008.png)

index.html 的更新代码

1.  打开 `Startup` 类并删除以下代码片段，该代码片段将 `Hello World` 默认文本写入每个请求的响应中：

```ts
      app.Run(async (context) =>   
      {   
            await   context.Response.WriteAsync("Hello  
            World!");   
      });   
```

1.  将以下代码添加到 `Configure` 方法中，以便管道为请求提供默认和静态文件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_009.png)

启用管道为静态和默认文件提供服务的代码

1.  你需要添加 `Microsoft.AspNetCore.StaticFiles` NuGet 软件包，如图所示，以使用这些扩展:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_010.png)

如有需要，请向命名空间添加引用

1.  现在，在 `wwwroot` 文件夹下添加一个 `index.html` 文件，并通过按下 *F5* 运行应用程序。你会注意到应用程序为请求提供了 `index.html` 文件作为默认文件。在这里，我已经添加了一个内容为 **`My Todo Landing Page`** 的 `h1` 标签:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_011.png)

在添加了 index.html 后的应用程序输出

## 使用 NPM 软件包管理器添加客户端软件包

* * *

在我们开发应用程序时，我们将很多框架和库添加为依赖项的引用。在 Visual Studio 中，我们有 NuGet 软件包管理工具来管理应用程序中的所有这些软件包。

在前端网络社区中，使用 Bower、Grunt、Gulp 和 NPM 来管理软件包和运行构建任务，开发现代 Web 应用已经变得广泛流行。由于这个生态系统非常丰富并且得到了广泛接受，Visual Studio 2015 已经采用了这些系统来管理客户端框架和库，如图所示。NuGet 是管理服务器端软件包的理想选择:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_012.png)

各种软件包管理工具

我们看到如何在 Visual Studio Code 中使用 NPM 管理客户端软件包。类似地，我们在 Visual Studio 2015 或更高版本中使用 NPM 来管理项目中的前端框架和库。让我们通过以下步骤使用 NPM 将 Angular 框架和其他所需的 JavaScript 库作为项目的依赖项添加到我们的项目中：

1.  首先，让我们向我们的项目添加 **`NPM 配置文件`**。右键单击项目节点，导航到 `Add` | `New Item`。从左侧窗格中选择 **`Web`** 下的 **`General`**，并且从中间窗格选择 **`NPM 配置文件`**。

然后，点击 **`Add`**，将默认名称保留为 `package.json`:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_013.png)

名为 package.json 的 NPM 配置文件

`package.json` 文件将被添加到您的项目中，其默认 JSON 代码如下:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_014.png)

package.json 的代码片段

1.  将 `name` 字段更新为 `my-todo` 并将所需的依赖项添加到 `package.json` 文件中，如图所示:

```ts
        "version": "1.0.0",   
        "name": "my-todo",   
        "private": true,   
        "dependencies":
        {   
          "@angular/common": "~4.0.0",   
          "@angular/compiler": "~4.0.0",   
          "@angular/core": "~4.0.0",   
          "@angular/forms": "~4.0.0",   
          "@angular/platform-browser": "~4.0.0",   
          "@angular/platform-browser-dynamic":   "~4.0.0",   

          "systemjs": "0.19.40",   
          "core-js": "².4.1",   
          "rxjs": "5.0.1",   
          "zone.js": "⁰.8.4"   
        },   
          "devDependencies": 
        {   
          "@types/node": "⁶.0.46",   
          "typescript": "~2.1.0"   
        }   
      }   
```

1.  当我们保存了带有所有依赖信息的 `package.json` 文件时，Visual Studio 将所需的软件包添加到我们的项目下的 `node_modules` 隐藏文件夹中，你可以通过导航到 `Dependencies` 节点下的 `npm` 文件夹来查看加载的依赖项列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_015.png)

具有依赖库的 NPM 文件夹

我们的项目依赖节点中已经有了我们需要的所有客户端框架和库。但是，我们需要将依赖库添加到我们的 `wwwroot` 文件夹中，以便我们的应用程序引用和消耗。我们将在下一节中讨论这一点。

## 使用 Gulp 运行任务

* * *

Gulp 是一个在`node.js`上运行的任务运行器。使用 Gulp，我们可以自动化活动，如移动或复制文件，以及捆绑和最小化。在 ASP.NET Core 中，微软还将 Gulp 与 Visual Studio 集成在一起，因为它已被 Web 社区广泛接受，可以非常轻松地运行和管理复杂的任务。您可以访问官方网站了解更多信息：[`gulpjs.com/`](http://gulpjs.com/)

让我们使用 Gulp 将解决方案中隐藏的`node_modules`文件夹中所需的 JavaScript 框架和库推送到项目`wwwroot`下的`libs`文件夹中。在 Visual Studio 中安装 Gulp 很容易。执行以下步骤来安装和运行 Gulp 任务：

1.  在`package.json`的 NPM 配置文件中添加 Gulp 作为开发依赖项，如图所示，并保存文件：

```ts
      {   
            "version": "1.0.0",   
            "name": "my-todo",   
            "private": true,   
            "dependencies": {   
            "@angular/common": "~4.0.0",   
            "@angular/compiler": "~4.0.0",   
            "@angular/core": "~4.0.0",   
            "@angular/forms": "~4.0.0",   
            "@angular/platform-browser": "~4.0.0",   
            "@angular/platform-browser-dynamic":   
            "~4.0.0",   
            "systemjs": "0.19.40",   
            "core-js": "².4.1",   
            "rxjs": "5.0.1",   
            "zone.js": "⁰.8.4"   
      },   
      "devDependencies": {   
      "@types/node": "⁶.0.46",   
      "gulp": "³.9.1",   
      "typescript": "~2.1.0"   
      }   
    }   
```

当我们在`package.json`文件中添加了 Gulp 作为开发依赖项并保存时，Visual Studio 会将该包安装到我们的应用程序中的`node` Dependencies` | `npm`文件夹下，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_016.png)

添加的 npm 文件夹下的 Gulp 依赖项

我们的应用程序中有 Gulp 包。现在，我们需要在 JavaScript 中编写一个任务，从隐藏在解决方案中的`node_modules`文件夹中复制所需的 JavaScript 库，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_017.png)

某个`node_modules`隐藏文件夹

1.  现在，让我们将**`Gulp 配置文件`**添加到我们的项目中。右键单击项目，导航到`添加` | `新建项`。在左侧窗格中选择**`Web`**下的**`General`**，然后在中间窗格中选择**`Gulp 配置文件`**。然后，单击**`添加`**，保持默认名称为`gulpfile.js`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_018.png)

添加 Gulp 配置文件

以下是 Gulp 配置文件`gulpfile.js`的默认内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_019.png)

Gulp 配置文件的默认代码片段

1.  让我们再写一个任务，将隐藏在解决方案中的`node_modules`文件夹中所需的 JavaScript 库复制到项目`wwwroot`节点下的`libs`文件夹中。将以下代码片段添加到新任务的`gulpfile.js`中：

```ts
      var paths = {   
          sourcePath: "./node_modules",   
          targetPath: "./wwwroot/libs"   
      }   
          var librariesToMove = [   
          paths.sourcePath + '/core-
          js/client/shim.min.js',   
          paths.sourcePath + '/zone.js/dist/zone.min.js',   
          paths.sourcePath +   
         '/systemjs/dist/system.src.js',   
      ];   
          var gulp = require('gulp');   
          gulp.task('librariesToMove',   function () {   
          return           
          gulp.src(librariesToMove).pipe      
          (gulp.dest(paths.targetPath));   
      });
```

`paths`变量保存要移动的库的源和目标文件夹，`librariesToMove`变量保存要移动到`libs`文件夹的库列表。文件中的最后一条语句是在运行时将所需的 JavaScript 库复制到`libs`文件夹的新任务。

1.  我们已经准备好了 Gulp 任务的代码，现在，我们需要运行 Gulp 任务来复制这些库。所以，要运行任务，右键单击`gulpfile.js`并打开**`任务运行器资源管理器`**，如下截图中所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_020.png)

打开任务运行器资源管理器

任务运行器资源管理器将在**`Tasks`**下列出在`gulpfile.js`中编写的可用任务，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_021.png)

gulpfile.js 中可用的任务列表

1.  在 ****`Task Runner Explorer`**** 中右键点击列表中的 `librariesToMove` 任务，然后从菜单中选择 **`Run`**，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_022.png)

在 gulpfile.js 中运行 librariesToMove 任务

您可以在 **`Task Runner Explorer`** 的右侧窗格中看到执行该任务的命令：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_023.png)

任务完成时没有错误

注意，库会被复制到 `wwwroot` 下的 `libs` 文件夹，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_024.png)

创建了包含所需 JavaScript 库的 libs 文件夹

1.  现在，我们已经在 `wwwroot` 节点下的 `libs` 文件夹中拥有了所需的库，请按照以下示例更新 `index.html`，向其中添加对 `libs` 文件夹中库的脚本引用以及配置 `SystemJS` 的代码：

```ts
      <!DOCTYPE html>   
      <html>   
      <head>   
          <title>My   Todo</title>   
          <script>document.write('<base   href="' + 
          document.location + 
          '" />');</script>   
          <meta charset="UTF-8">   
          <!-- Polyfills -->   
          <script src="img/shim.min.js"></script>   
          <script src="img/zone.min.js"></script>   
          <script src="img/system.src.js"></script>   
          <script src="img/systemjs.config.js"></script>   
          <script>   
            System.import('main.js').catch(function(err){          
            console.error(err); });   
          </script>   
      </head>   
      <body>   
          <my-app>Loading My Todo   App...</my-app>   
      </body>   
      </html>
```

1.  添加 `system.js` 配置文件 `systemjs.config.js`，并更新其中的以下内容。这包含了运行应用程序时加载 Angular 库的映射信息：

```ts
      (function (global) {
      System.config({
      paths: {
      'npm:': 'node_modules/'
      },
      map: {
      'app': 'app',
      '@angular/common': 
      'npm:@angular/common/bundles/common.umd.js',
      '@angular/compiler':       
      'npm:@angular/compiler/bundles/compiler.umd.js',
      '@angular/core': 
      'npm:@angular/core/bundles/core.umd.js',
      '@angular/forms': 
      'npm:@angular/forms/bundles/forms.umd.js',
      '@angular/platform-browser': 'npm:@angular/platform-
      browser/bundles/platform-browser.umd.js',
      '@angular/platform-browser-dynamic': 
      'npm:@angular/platform-
      browser-dynamic/bundles/platform-browser-
      dynamic.umd.js',
      'rxjs': 'npm:rxjs'
      },
      packages: 
      {app: {
      main: './main.js',
      defaultExtension: 'js'
      },
      rxjs: {
      defaultExtension: 'js'
      }
      }
      });
      })(this);
```

我们创建了一个项目来开发`My Todo` 应用程序，并使用 NPM 包管理器管理所有客户端依赖项。我们还使用了 Gulp 运行一个任务，将 JavaScript 库复制到 `wwwroot` 节点。在下一节中，让我们为我们的应用程序创建所需的 Angular 组件。

## 添加 Angular 组件和模板

* * *

我们将使用 TypeScript 为我们的应用程序编写 Angular 组件。TypeScript 文件应该编译为 ECMAScript 5 目标的 JavaScript。

### 配置 TypeScript 编译器选项

我们需要告知 Visual Studio 编译 TypeScript 所需的编译器选项，以便在运行时消耗我们的应用程序。通过 TypeScript 配置文件，我们可以使用以下步骤配置编译器选项和其他详细信息：

1.  在项目上右键点击，然后导航到 `Add | New Item`，保持文件名默认，添加 **`TypeScript Configuration File`**，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_025.png)

添加 TypeScript 配置文件

将一个名为 `tsconfig.json` 的文件添加到项目根目录。

1.  用以下配置替换 TypeScript 配置文件的内容：

```ts
      {   
            "compilerOptions": 
            {   
            "diagnostics": true,   
            "emitDecoratorMetadata":   true,   
            "experimentalDecorators":   true,   
            "lib": ["es2015", "dom"],   
            "listFiles": true,   
            "module": "commonjs",   
            "moduleResolution": "node",   
            "noImplicitAny": true,   
            "outDir": "wwwroot",   
            "removeComments": false,   
            "rootDir": "wwwroot",   
            "sourceMap": true,   
            "suppressImplicitAnyIndexErrors":   true,   
            "target": "es5"   
            },   
            "exclude": [   
            "node_modules"   
          ]   
      }
```

### 添加 Angular 组件

我们已经配置了 TypeScript 编译器选项。现在，让我们为我们的应用程序添加一个 Angular 根组件。按照以下步骤操作：

1.  首先，通过右键点击 `wwwroot`，然后导航到 `Add | New Folder`，在 `wwwroot` 下创建一个 `app` 文件夹，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_026.png)

为 Angular 应用程序文件夹添加一个名为 app 的新文件夹

1.  我们已经准备好了`app`文件夹。让我们通过右键单击`app`文件夹并导航到`Add` | `New Item`来添加 TypeScript 文件，以创建一个根组件。从左侧面板下选择**`Web`**下的**`Scripts`**，并在中间面板选择**`TypeScript File`**。将文件命名为`app.component.ts`，然后单击**`Add`**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_027.png)

添加名为 app.component.ts 的根组件

1.  将以下代码片段添加到`app.component.ts`：

```ts
      import { Component } from '@angular/core';   
      @Component({   
          selector: 'my-app',   
          template: `<h1>Hello   {{name}}</h1>`   
      })   
      export class AppComponent { name   = 'My Todo App';  
      }
```

创建了一个名为`AppComponent`的根组件，并用组件元数据`selector`和`templateUrl`进行修饰。

### 添加应用程序模块

在前面的部分中，我们创建了一个名为`AppComponent`的 Angular 组件。现在我们需要引导这个`AppComponent`，这样 Angular 才会将其视为应用程序的根组件。我们可以通过在`AppModule`类上添加`NgModule`元数据并将其分配给`AppComponent`来引导一个组件。按照以下步骤创建`AppModule`：

1.  通过右键单击`app`文件夹并导航到`Add` | `New Item`来创建一个`TypeScript`文件。在左侧面板下选择**`Web`**下的**`Scripts`**，并在中间面板选择**`TypeScript File`**。添加一个名为`app.module.ts`的文件，然后单击**`Add`**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_028.png)

添加名为`app.module.ts`的 TypeScript 文件

1.  将以下代码片段添加到`app.module.ts`：

```ts
      import { NgModule } from '@angular/core';
      import { BrowserModule } from '@angular/platform-
      browser';
      import { FormsModule } from '@angular/forms';
      import { AppComponent } from './app.component';
      @NgModule({
      imports: [
      BrowserModule,
      FormsModule
      ],
      declarations: [AppComponent],
      bootstrap: [AppComponent]
      })
      export class AppModule { }
```

在这里，我们将`AppComponent`添加为根组件，并导入`BrowserModule`，因为我们的应用将通过浏览器消耗，还有`FormsModule`两个绑定。

### 添加一个 Angular 组件

现在我们需要引导前面部分中创建的`AppModule`。执行以下步骤：

1.  让我们创建一个`TypeScript`文件，`main.ts`，用于引导`AppModule`。在`wwwroot`文件夹上右键单击并导航到`Add` | `New Item`。从左侧面板下选择**`Web`**下的**`Scripts`**，并在中间面板选择**`TypeScript File`**。将文件命名为`main.ts`，然后单击**`Add`**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_029.png)

添加名为 main.ts 的 TypeScript 文件

1.  使用这段代码更新`main.ts`文件：

```ts
      import { platformBrowserDynamic }   from 
      '@angular/platform-
      browser-dynamic';   
      import { AppModule } from './app/app.module';   
      platformBrowserDynamic().bootstrapModule(AppModule);
```

在这里，平台浏览器动态包含使应用在浏览器中运行的 Angular 功能。如果我们的应用程序不是针对在浏览器上运行的话，可以忽略这一点。

我们已经准备好验证我们的 Angular 应用程序是否正常运行。请注意 Visual Studio 如何在解决方案资源管理器中整齐地组织了模板文件、TypeScript 文件以及它们各自的已编译 JavaScript 文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_030.png)

编译 TypeScript 文件到 JavaScript 文件

*请注意，Visual Studio 在对 app 文件夹中的 TypeScript 文件进行编译并进行更改并保存文件时，将自动生成 JavaScript 文件。*

1.  通过按下*F5*键来运行应用程序，如果成功构建，您将看到浏览器中的输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_031.png)

应用的输出

### 注意

请注意`<my-app>`标签的内部文本是使用`app.component.html`中的内容插入的。

### 添加 Todo 类

我们的应用处理`Todo`项目。因此，让我们创建一个名为`Todo`的类，并向其添加`title`和`completed`属性，如下所示：

```ts
export class Todo {   
    title: string;   
    completed: boolean;   
    constructor(title: string) {   
        this.title = title;   
        this.completed = false;   
    }   
    set isCompleted(value:   boolean) {   
        this.completed = value;   
    }   
}   
```

这个`Todo`类还有一个以`title`为参数的构造函数和一个设置`todo`项目为`completed`状态的方法。

### 添加一个 TodoService 类

```ts
todo.service.ts file:
```

```ts
import { Todo } from './todo'    
export class TodoService {   
    todos: Array<Todo>   
    constructor() {   
        this.todos = [new Todo('First   item'),   
        new Todo('Second item'),   
        new Todo('Third item')];   
    }   
    getPending() {   
        return   this.todos.filter((todo: Todo) => todo.completed === 
        false);   
    }   
    getCompleted() {   
        return   this.todos.filter((todo: Todo) => todo.completed === 
        true);   
    }   
    remove(todo: Todo) {   
          this.todos.splice(this.todos.indexOf(todo), 1);   
    }   

    add(title: string) {   
        this.todos.push(new   Todo(title));   
    }   
    toggleCompletion(todo: Todo)   {   
        todo.completed =   !todo.completed;   
    }   
    removeCompleted() {   
        this.todos =   this.getPending();   
    }   
}
```

我们创建了`TodoService`类，其中包含各种方法来添加、删除和返回`todo`项目的集合。

### 更新 AppComponent 类

现在我们已经拥有了`TodoService`类，让我们更新`AppComponent`类，如下所示，来消费`TodoService`类：

```ts
import { Component } from '@angular/core';   
import { Todo } from './todo'   
import { TodoService } from './todo.service'     
@Component({   
    selector: 'my-app',   
    templateUrl: './app/app.component.html'   
})   
export class AppComponent {   
    todos: Array<Todo>;   
    todoService: TodoService;   
    newTodoText = '';   
    constructor(todoService:   TodoService) {   
        this.todoService =   todoService;   
        this.todos =   todoService.todos;   
    }   
    removeCompleted() {   
        this.todoService.removeCompleted();   
    }   
    toggleCompletion(todo: Todo)   {   
          this.todoService.toggleCompletion(todo);   
    }   
    remove(todo: Todo) {   
          this.todoService.remove(todo);   
    }  
    addTodo() {   
        if   (this.newTodoText.trim().length) {   
              this.todoService.add(this.newTodoText);   
            this.newTodoText = '';   
        }   
    }   
}   
```

请注意`@Component`里的 metadata `template`已被替换为`templateUrl`，并且指定了一个`AppComponent`模板文件`app.component.html`。由于模板内容现在比较复杂，我们需要为`AppComponent`视图引入一个 HTML 文件。

### 更新 AppModule

```ts
app.module.ts file:
```

```ts
import { NgModule } from '@angular/core';   
import { BrowserModule } from '@angular/platform-browser';   
import { FormsModule } from '@angular/forms';   
import { AppComponent } from './app.component';   
import { TodoService } from './todo.service'   
@NgModule({   
    imports: [   
        BrowserModule,   
        FormsModule   
    ],   
    declarations: [AppComponent],   
    providers: [TodoService],   
    bootstrap: [AppComponent]   
})   
export class AppModule { }
```

### 添加 AppComponent 模板

```ts
AppComponent with all the mentioned features:
```

```ts
<section>   
    <header>   
          <h1>todos</h1>   
        <input placeholder="Add   new todo" autofocus="" [(ngModel)]="newTodoText">   
        <button type="button"   (click)="addTodo()">Add</button>   
    </header>   
    <section *ngIf="todoService.todos.length   > 0">   
        <ul>   
            <li *ngFor="let   todo of todoService.todos">   
                <input type="checkbox"   (click)="toggleCompletion(todo)" [checked]="todo.completed">   
                  <label>{{todo.title}}</label>   
                <button   (click)="remove(todo)">X</button>   
            </li>   
        </ul>   
    </section>   
    <footer *ngIf="todoService.todos.length   > 0">   
          <span><strong>{{todoService.getPending().length}}</strong>   {{todoService.getPending().length == 1 ? 'item' : 'items'}} left</span>   
        <button *ngIf="todoService.getCompleted().length   > 0" (click)="removeCompleted()">Clear completed</button>   
    </footer>   
</section>   
```

如你所见，我们使用`ngModel`在输入控件上应用了双向绑定来绑定新的`todo`项目`title`。我们将`addTodo`方法分配给`Add`按钮的点击事件，以将新的`todo`项目添加到`todoService`中的内存中的`Todo`项目集合。我们对`<li>`标签应用了`ngFor`来迭代`todoService`中的每个`Todo`项目。为每个`Todo`项目呈现的复选框有其自己的`click`事件，`checked`属性与`toggleCompletion`方法，以及`Todo`项目的`completed`属性分别映射。接下来，删除按钮将其`click`事件映射为`AppComponent`中的`remove`方法。

footer 标签有一个显示待办`todo`项目数量的 span，以及一个按钮来从列表中删除已完成的`todo`项目。该按钮的`click`事件与`AppComponent`中的`removeCompleted`方法相映射。

通过按下*F5*键来运行应用程序，您将能够执行所有操作，如添加，删除和列举`todo`项目：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_05_032.png)

我的 Todo 应用操作

## 总结

* * *

哇！你实际上在本章中学到了这本书非常重要且核心的目标。是的！我在谈论将 Angular 与.NET 应用程序集成。

我们通过创建一个新的 ASP.NET Core 空应用程序开始了这一章,并更新了`Startup`类以服务静态页面和默认页面。然后,您学习了如何在 Visual Studio 中使用 NPM 管理客户端包,我们还设法使用 Visual Studio 中的 Gulp 自动化和运行任务。接下来,您学习了如何添加应用程序所需的组件并将其引导。后来,我们设计了一个模型类和一个服务类来处理应用程序的核心业务逻辑。最后,我们设计了一个模板来列出`Todo`项目,并添加了一些控件并将它们挂钩到`TodoService`和`AppComponent`中的某些方法。

这个应用程序只处理内存中的待办事项。然而，在实时应用程序中,我们会使用一个服务来添加、删除或获取`todo`项目。在下一章中,我们将讨论如何创建一个 ASP.NET Core Web API 服务来处理检索、保存和删除`todo`项目,并从我们刚刚构建的 Angular 应用程序中使用它。


## 第六章：创建 ASP.NET Core Web API 服务用于 Angular

本章将指引您创建 ASP.NET Web API 服务用于上一章中创建的 Angular 应用程序。

在本章中，我们将涵盖以下主题：

+   RESTful Web Services

+   ASP.NET Web API 概述

+   创建 ASP.NET Web API 服务

+   将 ASP.NET Web API 与 Angular 应用程序集成

## RESTful Web Services

*** 

**表征状态转移** (**REST**) 是一种可以应用于实现 RESTful 服务的架构风格或设计原则。REST 确保了客户端和服务之间的通信通过拥有有限数量的操作而改善。REST 帮助您以一种简单的方式组织这些独立系统之间的通信。

在 REST 中，每个资源都由自己的 **通用资源标识符** (**URI**) 标识。它在 HTTP 的基础上使用，并利用 HTTP 动词，如 `GET`、`POST`、`PUT` 和 `DELETE`，来控制或访问资源。

**表征状态转移** (**REST**)是一种无状态的 Web 服务，易于扩展，工作在 HTTP 协议下，可以从任何支持 HTTP 的设备上访问。客户端不需要担心除数据格式之外的任何内容：

![图片](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_001.png)

一个 RESTful 服务

## ASP.NET Web API 概述

*** 

ASP.NET Web API 是一个可以在 .NET 框架上构建 RESTful 服务的框架。ASP.NET Web API 基于 HTTP 协议，以 URI 形式公开 HTTP 动词/操作，允许客户端应用程序使用 HTTP 动词与数据交互。任何支持 HTTP 通信的客户端应用程序或设备都可以轻松访问 Web API 服务。

正如前一节所讨论的，RESTful 服务通过 URI 标识资源。例如，我们有 [`www.programmerguide.net/api/todos/101`](http://www.programmerguide.net/api/todos/101)，并且 Angular 应用程序应用一个 GET 请求。响应这个 GET 请求的 C# 方法将在 Web API 控制器类中。路由技术将根据配置或在相应的类和方法中注释的路由来映射请求 URI 与相应的控制器和方法。

在这里，按照默认配置，请求将由 `TodosController` 中的 `Get` 方法处理。`Get` 方法将根据 ID 值 101 从数据库中检索 `Todo` 项，并将其作为 `Todo` 对象返回。返回的 `Todo` 对象将被序列化为 JSON 或 XML。

对于 `Post` 方法，新发布的 `Todo` 对象将以 JSON 形式从请求体中接收，并且将被反序列化成 `Todo` 对象以在 `TodosController` 的 `Post` 方法中使用。

我们可以通过强大的 ASP.NET **Model-View-Controller** (**MVC**) 编程模型在 ASP.NET Web API 中创建基于 HTTP 的服务。路由、模型绑定和验证等功能提供了在使用 ASP.NET Web API 开发 RESTful Web 服务时更大的灵活性。

### 为什么 ASP.NET Web API 很适合 Angular

ASP.NET Web API 是一个用于构建 HTTP 服务的框架。它采用非常轻量级的架构，可以通过 RESTful 方式在 Angular 中以异步方式访问 HTTP 服务。使用 ASP.NET Web API，我们可以轻松地在 Angular 应用程序中同步数据。

## 创建 ASP.NET Web API 服务

* * *

让我们为上一章创建的我的待办应用添加 ASP.NET Web API 服务。我们的我的待办应用是在 Visual Studio 2015 中使用空的 ASP.NET 5 模板创建的。创建空项目时，会生成一个精简的 Web 应用程序。它不包括与 MVC 或 Web API 相关的程序集。因此，我们需要明确添加所需的程序集或模块来实现应用程序中的 Web API。

### 向 ASP.NET 项目添加和配置 MVC 服务

由于 ASP.NET Core 将 Web API 与 MVC 合并，我们需要添加一个 MVC 服务来实现应用程序中的 Web API：

1.  安装 `NuGet` 包 `Microsoft.AspNetCore.MVC`。

1.  在 Visual Studio 中从项目的根文件夹中打开 `Startup.cs` 文件。

1.  在 `ConfigureServices` 方法下添加以下语句以向项目添加 MVC 服务

```ts
    public void   ConfigureServices(IServiceCollection   
    services)   
        {   
            services.AddMvc();   
        }   
```

1.  我们刚刚在项目中启用了 MVC。接下来，我们将通过在 `Configure` 方法中添加以下语句来将 MVC 与我们的请求管道连接起来：

```ts
    app.UseMvc();
```

### 向 ASP.NET 应用程序添加 Web API 控制器

我们刚刚启用并连接了 MVC 服务到我们的应用程序。现在，让我们按照以下步骤添加一个 Web API 控制器：

1.  在 `我的待办` 项目上右键单击，导航到 `Add` | `New Folder`，并命名文件夹为 `Controllers`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_002.png)

在我的待办项目下创建一个用于控制器的新文件夹

1.  现在，右键单击我们刚刚创建的 `Controllers` 文件夹，转到 `Add` | `New Item`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_003.png)

将 Web API 控制器添加到控制器文件夹中

1.  选择 **`Minimal Dependencies`** 并单击 **`Add`** 如果您收到一个添加 MVC 依赖项的弹出窗口：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_004.png)

添加最小的 MVC 依赖项

Visual Studio 2017 添加了一个 `ScaffoldingReadMe.txt` 自述文件，其中包含以下启用脚手架的说明;遵循并相应地更新您的项目代码。

ASP.NET MVC 核心依赖项已添加到项目中。但是，您可能仍然需要对项目进行以下更改：

1.  向项目添加 `Scaffolding``CLI` 工具：

```ts
    <ItemGroup>   
     <DotNetCliToolReference    
     Include="Microsoft.VisualStudio.Web.CodeGeneration.  
     Tools"  Version="1.0.0" />   
    </ItemGroup>   
```

1.  下面是对 `Startup` 类的建议更改：

```ts
    2.1 Add a constructor:   
        public IConfigurationRoot   Configuration { get; }   
        public Startup(IHostingEnvironment   env)   
        {   
            var builder = new   ConfigurationBuilder()   
                .SetBasePath(env.ContentRootPath)   
                .AddJsonFile("appsettings.json",     
                 optional: true, 
                    reloadOnChange: true)   
                .AddJsonFile($"appsettings.
                 {env.EnvironmentName}.json",   optional: 
                  true)   
                .AddEnvironmentVariables();   
            Configuration =   builder.Build();   
        }   
    2.2 Add MVC services:   
        public void   ConfigureServices(IServiceCollection  
        services)   
        {   
            // Add framework   services.   
            services.AddMvc();   
       }   
    2.3 Configure web app to use   use Configuration and 
        use MVC routing:  
        public void   Configure(IApplicationBuilder app, 
        IHostingEnvironment env, ILoggerFactory   
        loggerFactory)   
        {      
        loggerFactory.AddConsole(Configuration.GetSection       
        ("Logging"));   
              loggerFactory.AddDebug();  
            if (env.IsDevelopment())   
            {   
                  app.UseDeveloperExceptionPage();   
            }   
            else   
            {   
                  app.UseExceptionHandler("/Home/Error");   
            }   
            app.UseStaticFiles();   

            app.UseMvc(routes   =>   
            {   
                routes.MapRoute(   
                    name: "default",   
                    template: " 
            {controller=Home}/{action=Index}
                     /{id?}");   
            });   
        }
```

1.  再次右键单击 `Controllers` 文件夹，转到 **`Add`** | **`Controllers`**，选择 **`API Controller with read/write actions`**，并将其命名为 `TodosController`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_005.png)

将控制器命名为 TodosController

### 注意

如果你在下面的截图中看到了错误，你需要通过编辑你的`csproj`文件添加给定的 XML 标签，然后再次添加控制器。

这是错误：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_006.png)

以下是 XML 标签的代码：

```ts
<ItemGroup>   
          <DotNetCliToolReference Include="Microsoft.VisualStudio.Web.CodeGeneration.Tools"   Version="1.0.1" />   
</ItemGroup>   
```

这将为我们创建`TodosController` Web API 控制器，并提供以下模板代码，供我们根据需求进行修改：

```ts
[Produces("application/json")]   
    [Route("api/Todos")]   
    public class TodosController   : Controller   
    {   
        // GET: api/Todos   
        [HttpGet]   
        public   IEnumerable<string> Get()   
        {   
            return new string[] {   "value1", "value2" };   
        }  
        // GET: api/Todos/5   
        [HttpGet("{id}", Name = "Get")]   
        public string Get(int id)   
        {   
            return "value";   
        }    
        // POST: api/Todos   
        [HttpPost]   
        public void   Post([FromBody]string value)   
        {   
        }   
        // PUT: api/Todos/5   
        [HttpPut("{id}")]   
        public void Put(int id,   [FromBody]string value)   
        {   
        }   
        // DELETE:   api/ApiWithActions/5   
        [HttpDelete("{id}")]   
        public void Delete(int   id)   
        {   
        }   
    }   
```

1.  按下*F5*运行应用程序，并从浏览器导航到`http://localhost:2524/api/todos`。

### 注意

你的系统可能有不同的端口。

你将会在`TodosController`中看到以下输出，默认代码中的`Get`方法。如您在下面的截图中所见，它只返回了一个字符串数组：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_007.png)

在 TodoController 中默认的 Get 操作的输出

### 添加模型到 ASP.NET 应用程序

我们配置了我们的应用程序以使用 MVC 服务，并添加了 Web API 控制器。现在，让我们为我们的 My Todo 应用程序添加所需的模型。按照这些步骤添加一个名为`Todo`的模型：

1.  在`My``Todo`项目上右键点击，转到**`Add`** | **`New Folder`**，并将文件夹命名为`Models`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_008.png)

在 My Todo 项目下为 Models 添加一个新文件夹

1.  现在，右键点击刚刚创建的`Models`文件夹，然后转到**`Add`** | **`Class`**....：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_009.png)

在 Models 文件夹下为 Todo 对象添加一个类

1.  将类命名为`Todo`，并将以下代码片段添加到其中：

```ts
   namespace My_Todo.Models
   {
   public class Todo
   {
   public int Id { get; set;
    }
   public string Title { get; set;
    }
   public bool Completed { get; set;
    }
   }  
  }
```

`Todo`是一个 C# POCO 类，代表一个`Todo`项目。它具有属性，例如`Id`保存着`Todo`项目的主键值，`Title`属性保存着`Todo`项目的标题，`Completed`属性保存着布尔标志，指示该项目是否已完成。

### 将 DBContext 添加到 ASP.NET 应用程序

我们刚刚添加了`Todo`模型。现在，让我们添加`DBContext`来管理和持久化数据库中的`Todo`。`DBContext`充当您的类和数据库之间的桥梁。要添加它，请按照以下步骤操作：

1.  右键点击`Models`文件夹，转到**`Add`** | **`Class`**：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_010.png)

在 Models 文件夹下添加一个 DBContext 类

1.  将类命名为`TodoContext`，并将以下代码片段添加到其中：

```ts
   public class TodoContext : DbContext
   {
     public TodoContext(DbContextOptions<TodoContext>       
     options)
     : base(options)
    {
    }
    public DbSet<Todo> Todos { get; set; }
  }
```

`TodoContext`帮助你与数据库交互，并将更改提交为一个单独的工作单元。`TodoContext`被配置为使用 SQL Server，并且连接字符串是从我们将在下一步添加的`config.json`文件中读取的。

1.  在`Startup.cs`中添加使用语句以导入`Microsoft.EntityFrameworkCore`。

1.  通过将以下代码片段添加到`ConfigureServices`方法中来配置 SQL 服务：

```ts
    services.AddEntityFrameworkSqlServer()   
    .AddDbContext<TodoContext>(options =>   
    options.UseSqlServer(Configuration.GetConnectionString
    ("DefaultConnection")));   
    services.AddMvc();   
```

1.  添加一个`appsettings.json`文件来保存连接字符串的值，并更新它的内容如下：

```ts
 {   
   "ConnectionStrings": 
    {   
     "DefaultConnection": "Server=(localdb)\\mssqllocaldb;
         Database=aspnet-CloudInsights-f2d509d5-468f-4bc9-  
         9c47-
         0593d0907063;Trusted_Connection=True;
         MultipleActiveResultSets=true"   
    },   
   "Logging": 
    {
     "IncludeScopes": false,   
     "LogLevel": {   
      "Default": "Warning"   
     }   
   }   
 }   
```

在这个`JSON`文件中，我们在`data`项下添加了连接字符串。

```ts
Startup.cs file is as follows:
```

```ts
public class Startup   
    {   
        public Startup(IHostingEnvironment   env)   
        {   
            var builder = new   ConfigurationBuilder()   
                  .SetBasePath(env.ContentRootPath)   
                .AddJsonFile("appsettings.json",   optional: true, reloadOnChange: true)   
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json",   optional: true)   
                  .AddEnvironmentVariables();   
            Configuration =   builder.Build();   
        }   
        public IConfigurationRoot   Configuration { get; }   

        // This method gets   called by the runtime. Use this method to add services to the container.   
        // For more information   on how to configure your application, visit   https://go.microsoft.com/fwlink/?LinkID=398940   
        public void ConfigureServices(IServiceCollection   services)   
        {   
              services.AddEntityFrameworkSqlServer()   
              .AddDbContext<TodoContext>(options =>   
                  options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));   
            // Add framework   services.   
            services.AddMvc();   
        }   
        // This method gets   called by the runtime. Use this method to configure the HTTP request   pipeline.   
        public void   Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory   loggerFactory)   
        {   
              loggerFactory.AddConsole();   

            if   (env.IsDevelopment())   
            {   
                  app.UseDeveloperExceptionPage();   
            }   
              app.UseDefaultFiles();   
            app.UseStaticFiles();   
              app.UseStaticFiles(new StaticFileOptions   
            {   
                FileProvider =   new PhysicalFileProvider(   
                      Path.Combine(env.ContentRootPath, "node_modules")   
                ),   
                RequestPath = "/"   + "node_modules"   
            });   
            app.UseMvc();   
        }   
    }   
```

在`Startup.cs`构造函数中，我们创建了用于从`config.json`文件中读取的配置。在`ConfigureServices`方法中，我们添加了 Entity Framework 并将 SQL Server 和`TodoContext`连接到了它。

## 使用数据库迁移

* * *

Entity Framework 中的数据库迁移帮助您在应用程序开发阶段创建数据库或更新数据库模式。现在我们已经准备好了所需的模型和数据库上下文。现在需要创建数据库。让我们使用 Entity Framework 中的数据库迁移功能在 SQL Server Compact 中创建数据库。按照以下步骤操作：

1.  首先通过编辑将以下 XML 标签添加到`csproj`文件中：

```ts
  <ItemGroup>   
    <DotNetCliToolReference    
    Include="Microsoft.EntityFrameworkCore.Tools.DotNet"  
    Version="1.0.0" />   
  </ItemGroup>   
```

1.  打开命令提示符并导航到项目文件夹。

1.  执行以下命令以初始化迁移的数据库：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_011.png)

执行命令以添加迁移

此命令在**`My`****`Todo`**项目下创建`Migration`文件夹，并添加两个类以创建表和更新模式。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_012.png)

与数据库迁移相关的文件

1.  执行以下命令以更新数据库：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_013.png)

执行命令以更新数据库

此命令根据上下文和模型为我们的应用程序创建`database`。

### 在 Web API 控制器中使用数据库上下文

现在我们已经准备就绪，迁移也已设置好，让我们更新`TodosController` Web API 控制器以使用之前创建的`TodoContext`。按照以下步骤进行：

1.  打开`TodosController.cs`。

1.  声明`_db`私有变量类型为`TodoContext`：

```ts
private TodoContext _db; 
```

1.  定义接受`TodoContext`类型的`context`参数并将`context`值赋给`_db`的`constructor`：

```ts
        public TodosController(TodoContext context) 
        { 
            _db = context; 
        } 
```

1.  引入一个`GET`动作方法，该方法使用`_db`数据库上下文从数据库中返回所有`Todo`项的集合：

```ts
        // GET: api/todos 
        [HttpGet] 
        public IEnumerable<Todo> Get() 
        { 
            return _db.Todos.ToList(); 
        } 
```

1.  引入另一个`GET`动作方法，该方法从数据库中移除已完成的`Todo`项，并使用`_db`数据库上下文返回所有待处理的`Todo`项：

```ts
        // GET: api/todos/pending-only 
        [HttpGet] 
        [Route("pending-only")] 
        public IEnumerable<Todo> GetPendingOnly() 
        { 
            _db.Todos.RemoveRange(_db.Todos.Where(x =>   
            x.Completed == true)); 
            _db.SaveChanges(); 
            return _db.Todos.ToList(); 
        }
```

1.  引入一个`POST`动作方法，该方法在`TodoContext``_db`数据库中插入新的`Todo`项：

```ts
        // POST api/todos 
        [HttpPost] 
        public Todo Post([FromBody]Todo value) 
        { 
            _db.Todos.Add(value); 
            _db.SaveChanges(); 
            return value; 
        } 
```

1.  引入`PUT`动作方法，使用`TodoContext``_db`更新具有匹配 ID 的现有`Todo`项：

```ts
        // PUT api/todos/id 
        [HttpPut("{id}")] 
        public Todo Put(int id, [FromBody]Todo value) 
        { 
            var todo = _db.Todos.FirstOrDefault(x => x.Id  
            == id); 
            todo.Title = value.Title; 
            todo.Completed = value.Completed; 
            _db.Entry(todo).State = 
            Microsoft.Data.Entity.EntityState.Modified; 
            _db.SaveChanges(); 
            return value; 
        } 
```

1.  引入一个`DELETE`动作方法，使用`TodoContext``_db`删除具有匹配 ID 的现有`Todo`项：

```ts
        // DELETE api/todos/id 
        [HttpDelete("{id}")] 
        public void Delete(int id) 
        { 
            var todo = _db.Todos.FirstOrDefault(x => x.Id 
            == id); 
            _db.Entry(todo).State = 
            Microsoft.Data.Entity.EntityState.Deleted; 
            _db.SaveChanges(); 
        }     
TodosController is this:
```

```ts
[Produces("application/json")]   
    [Route("api/Todos")]   
    public class TodosController   : Controller   
    {   
        private TodoContext _db;   
        public   TodosController(TodoContext context)   
        {   
            _db = context;   
        }   
        // GET: api/todos   
        [HttpGet]   
        public   IEnumerable<Todo> Get()   
        {   
            return   
            _db.Todos.ToList();   
        }   
        // GET: api/todos/pending-only   
        [HttpGet]   
        [Route("pending-only")]   
        public   IEnumerable<Todo> GetPendingOnly()   
        {   
            _db.Todos.RemoveRange(_db.Todos.Where(x => 
            x.Completed == true));   
            _db.SaveChanges();   
            return   _db.Todos.ToList();   
        }   
        // POST api/todos   
        [HttpPost]   
        public Todo   Post([FromBody]Todo value)   
        {   
            _db.Todos.Add(value);   
            _db.SaveChanges();   
            return value;   
        }   
        // PUT api/todos/id   
        [HttpPut("{id}")]   
        public Todo Put(int id,   [FromBody]Todo value)   
        {   
            var todo =   _db.Todos.FirstOrDefault(x => 
            x.Id == id);   
            todo.Title =   value.Title;   
            todo.Completed =   value.Completed;   
            _db.Entry(todo).State   = 
            EntityState.Modified;   
            _db.SaveChanges();   
            return value;   
        }   
        // DELETE api/todos/id   
        [HttpDelete("{id}")]   
        public void Delete(int   id)   
        {   
            var todo =   _db.Todos.FirstOrDefault(x => 
            x.Id == id);   
            _db.Entry(todo).State   = EntityState.Deleted;   
            _db.SaveChanges();   
        }   
    }   
```

## 将 ASP.NET Core Web API 集成到 Angular 应用程序中

* * *

在上一节中，我们添加和修改了 Web API 控制器，并介绍了处理`Todo`项的 HTTP 动词方法。现在，让我们修改我们的 Angular 代码，以调用所有 Web API 方法来管理`Todo`项。

### 在 Angular 应用程序中更新模型

首先，我们需要在 Angular 应用程序中的`Todo.ts`中添加`id`属性来保存从 API 接收的`Todo`项的 ID。因此，更新后的`Todo.ts`如下所示：

```ts
export class Todo { 
    id: number; 
    title: string; 
    completed: boolean; 
    constructor(id: number, title: string, completed: 
    boolean) { 
        this.id = id; 
        this.title = title; 
        this.completed = completed; 
    } 
    set isCompleted(value: boolean) { 
        this.completed = value; 
    }  
}  
```

`constructor`接受三个参数：`id`、`title`和`completed`，并将它们分配给`id`、`title`和`completed`属性，分别使用`this`关键字访问它们。`Todo`类还为`completed`属性设置了访问器。

### 准备 Angular 应用程序

准备 Angular 应用程序的步骤如下：

1.  在`package.json`中将`@angular/http`模块添加到依赖项中。需要使用 HTTP 模块来消费 Web API 服务。更新后的`package.json`如下所示：

```ts
 {   
   "version": "1.0.0",   
   "name": "my-todo",   
   "private": true,   
   "dependencies": {   
     "@angular/common": "~4.0.0",   
     "@angular/compiler": "~4.0.0",   
     "@angular/core": "~4.0.0",   
     "@angular/forms": "~4.0.0",   
     "@angular/http": "~4.0.0",   
     "@angular/platform-browser": "~4.0.0",   
     "@angular/platform-browser-dynamic":   "~4.0.0",   
     "systemjs": "0.19.40",   
     "core-js": "².4.1",   
     "rxjs": "5.0.1",   
     "zone.js": "⁰.8.4"   
   },   
   "devDependencies": {   
     "@types/node": "⁶.0.46",   
     "gulp": "³.9.1",   
     "typescript": "~2.1.0"   
   }   
 }
```

1.  使用`@angular/http`在`systemjs.config.js`中进行映射更新。更新后的`systemjs.config.js`如下所示：

```ts
  (function (global) {   
      System.config({           
          paths: {               
             'npm:': 'node_modules/'   
        },   
        map: {   
            'app': 'app',   
            '@angular/common':   
   'npm:@angular/common/bundles/common.umd.js',   
            '@angular/compiler': 
   'npm:@angular/compiler/bundles/compiler.umd.js',   
            '@angular/core': 
   'npm:@angular/core/bundles/core.umd.js',   
            '@angular/forms': 
   'npm:@angular/forms/bundles/forms.umd.js',   
            '@angular/http': 
   'npm:@angular/http/bundles/http.umd.js',   
            '@angular/platform-browser':   
   'npm:@angular/platform-browser/bundles/platform-
    browser.umd.js',   
            '@angular/platform-browser-dynamic':   
   'npm:@angular/platform-browser-
    dynamic/bundles/platform-browser-dynamic.umd.js',   
            'rxjs': 'npm:rxjs'   
          },   
           packages: {   
              app: {   
                  main: './main.js',   
                  defaultExtension:   'js'   
              },   
              rxjs: {   
                  defaultExtension:   'js'   
              }   
          }   
      });   
   })(this);   
```

1.  在`AppModule`中导入`HttpModule`，如下所示：

```ts
   import { NgModule } from '@angular/core';   
   import { BrowserModule } from '@angular/platform-   
   browser';   
   import { FormsModule } from '@angular/forms';   
   import { HttpModule } from '@angular/http';   
   import { AppComponent } from './app.component';   
   import { TodoService } from './todo.service'   
   @NgModule({   
   imports: [   
        BrowserModule,   
        FormsModule,   
        HttpModule   
    ],   
       declarations: [AppComponent],   
       providers: [TodoService],   
       bootstrap: [AppComponent]   
   })   
   export class AppModule { }   
```

1.  如下所示更新模型`Todo`：

```ts
export class Todo {   
    id: number;   
    title: string;   
    completed: boolean;   
    constructor(id: number,   title: string, completed: boolean) {   
        this.id = id;   
        this.title = title;   
        this.completed =   completed;   
    }  
    set isCompleted(value:   boolean) {   
        this.completed = value;   
    }   
}   
```

### 在 TodoService 中消耗 Web API GET 操作

首先，让我们更新`TodoService`，以使用`Http`服务与 Web API 服务通信，从而获取`Todo`项目列表：

1.  打开 app 文件夹中的`todoService.ts`文件。

1.  添加以下`import`语句以导入模块，例如`Injectable`、`Http`、`headers`、`Response`、`Observable`、`map`和`Todo`：

```ts
   import { Injectable } from '@angular/core'; 
   import { Http, Headers } from '@angular/http'; 
   import 'rxjs/add/operator/toPromise';
   import { Todo } from './todo'
```

1.  修改`constructor`以注入`Http`服务，添加`Http`服务的参数：

```ts
  constructor (private http: Http) { ... } 
```

1.  添加`getTodos`方法以使用`Http`标签消费 Web API 服务以获取`Todo`项目列表：

```ts
     getTodos(): Promise<Array<Todo>> { 
        return this.http.get('/api/todos') 
            .toPromise() 
            .then(response => response.json() as   
             Array<Todo>) 
            .catch(this.handleError); 
     }
```

在这里，`toPromise`方法将`http`的`Get`方法返回的`Observable`序列转换为 Promise。然后，我们在返回的 promise 上调用`then`方法或`catch`方法。我们将响应中收到的`JSON`转换为`Todo`数组。

1.  我们刚刚添加了`getTodos`方法。接下来，让我们添加`getPendingTodos`方法来调用配置了 Web API 中`pending-only`路由的`GET`方法，从数据库中删除已完成的`Todo`项目，并只返回待办的`Todo`项目。`GetPendingTodos`的代码片段如下所示：

```ts
    getPendingTodos() { 
    this.http.get('http://localhost:2524/api/todos/    
    pending-only') 
         .subscribe( 
         err => console.log(err), 
         () => console.log('getTodos Complete') 
         ); 
    } 
app.component.ts:
```

```ts
       getPending() { 
       return this.todos.filter((todo: Todo) =>   
       todo.completed === false); 
   } 
```

更新后的`todo.service.ts`用于调用 Web API 的`GET`方法的代码如下：

```ts
import { Injectable } from '@angular/core'; 
import { Http, Headers } from '@angular/http'; 
import 'rxjs/add/operator/toPromise';
import { Todo } from './todo' 
@Injectable() 
export class TodoService { 
    constructor(private http: Http) {    } 
    getTodos(): Promise<Array<Todo>> { 
        return this.http.get('/api/todos') 
            .toPromise() 
            .then(response => response.json() as Array<Todo>) 
            .catch(this.handleError); 
    } 
    getPendingTodos() { 
        this.http.get('/api/todos/pending-only') 
            .subscribe( 
            err => console.log(err), 
            () => console.log('getTodos Complete') 
            ); 
    }    
    removeCompleted() { 
        this.getPendingTodos();         
    } 
    private handleError(error: any): Promise<any> { 
        console.error('An error occurred', error);  
        return Promise.reject(error.message || error); 
    } 
} 
```

### 从 TodoService 向 Web API 发布

我们刚刚更新了`todo.Services.ts`以调用 Web API 的`GET`操作并获取`Todo`项目。现在，让我们添加代码来将新的`Todo`项目发布到 Web API。按照给定的步骤进行操作：

1.  打开`todo.service.ts`。

1.  添加`postTodo`函数以将新的`Todo`项目发布到 Web API 控制器：

```ts
     postTodo(todo: Todo): Promise<Todo> { 
             var headers = new Headers(); 
             headers.append('Content-Type',  
     'application/json'); 
        return this.http.post('/api/todos',  
     JSON.stringify(todo), { headers: headers }) 
            .toPromise() 
            .then(response => response.json() as Todo) 
            .catch(this.handleError); 
     } 
```

此函数接受`Todo`项目作为参数。它定义了带有`JSON`内容类型的`header`部分，并使用`http`服务将`Todo`项目异步发布到 Web API。响应被转换为`Promise`，`then`方法返回`Promise<Todo>`。

### 调用 Web API 的 PUT 操作以更新 Todo 项目

我们刚刚添加了消费 Web API GET 操作的代码，并添加了代码将新的`Todo`项目发布到 Web API 的 POST。现在，让我们使用 Web API 的 PUT 操作来更新现有的 Todo 项目。按照以下步骤进行操作：

1.  打开`todo.service.ts`。

1.  使用以下代码段添加 `putTodo` 函数来调用 Web API 中的 `PUT` 操作来更新现有的 `Todo` 项目：

```ts
     putTodo(todo: Todo) {
       var headers = new Headers(); 
       headers.append('Content-Type', 'application/json'); 
       this.http.put('/api/todos/' + todo.id,  
     JSON.stringify(todo), { headers: headers }) 
            .toPromise() 
            .then(() => todo) 
            .catch(this.handleError); 
     } 
```

此代码定义了具有 `JSON` 内容类型的标头，并调用了 `PUT` 操作方法以及 `JSON` 字符串化的 `Todo` 项目和该 `Todo` 项目的 `id`。 Web API 中的 `PUT` 操作方法将更新数据库中的匹配 `Todo` 项目。

### 调用 Web API 的 DELETE 操作来删除一个 Todo 项目

我们添加了一些代码，通过调用各种 Web API 操作，如`GET`，`POST` 和 `PUT`，来获取、添加和编辑 `Todo` 项目。现在，让我们使用 Web API 中的 `DELETE` 操作来删除匹配的 `Todo` 项目。请按照以下步骤进行：

1.  打开 `todo.service.ts`。

1.  使用以下代码段添加 `deleteTodo` 函数，通过调用 `Web API` 中的 `DELETE` 操作来删除匹配的 `Todo` 项目：

```ts
      deleteTodo(todo: Todo) { 
        this.http.delete('/api/todos/' + todo.id) 
            .subscribe(err => console.log(err), 
            () => console.log('getTodos Complete') 
            ); 
         } 
```

此代码调用 `DELETE` 操作，以及被删除的 `Todo` 项目的 `id`。 Web API 中的 `DELETE` 操作方法将从数据库中检索匹配的 `Todo` 项目并删除它。

### 更新 TodoService 中的包装函数

我们有一些函数，如 `getTodos`，`getPendingTodos`，`postTodos`，`putTodo` 和 `deleteTodo`，这些函数与 `GET`，`POST`，`PUT` 和 `DELETE` Web API 操作交互。 现在，让我们更新或替换作为从 `app.component.ts` 中使用的包装器的 `remove`，`add`，`toggleCompletion` 和 `removeCompleted` 函数的代码。 更新或替换函数的代码，如下所示：

```ts
    remove(todo: Todo) { 
        this.deleteTodo(todo);         
    } 
    add(title: string): Promise<Todo> { 
        var todo = new Todo(0, title, false); 
        return this.postTodo(todo); 
    } 
    toggleCompletion(todo: Todo) { 
        todo.completed = !todo.completed; 
        this.putTodo(todo); 
    } 
    removeCompleted() { 
        this.getPendingTodos();         
    } 
todo.service.ts after all the updates is this:
```

```ts
import { Injectable } from '@angular/core'; 
import { Http, Headers } from '@angular/http'; 
import 'rxjs/add/operator/toPromise'; 
import { Todo } from './todo' 
@Injectable() 
export class TodoService { 
    constructor(private http: Http) {    } 
    getTodos(): Promise<Array<Todo>> { 
        return this.http.get('/api/todos') 
            .toPromise() 
            .then(response => response.json() as Array<Todo>) 
            .catch(this.handleError); 
    } 
    getPendingTodos() { 
        this.http.get('/api/todos/pending-only') 
            .subscribe( 
            err => console.log(err), 
            () => console.log('getTodos Complete') 
            ); 
    }    
    postTodo(todo: Todo): Promise<Todo> { 
        var headers = new Headers(); 
        headers.append('Content-Type', 'application/json'); 
        return this.http.post('/api/todos', JSON.stringify(todo), { headers: headers }) 
            .toPromise() 
            .then(response => response.json() as Todo) 
            .catch(this.handleError); 
    } 
    putTodo(todo: Todo) { 
        var headers = new Headers(); 
        headers.append('Content-Type', 'application/json'); 
        this.http.put('/api/todos/' + todo.id, JSON.stringify(todo), { headers: headers }) 
            .toPromise() 
            .then(() => todo) 
            .catch(this.handleError); 
    } 
    deleteTodo(todo: Todo) { 
        this.http.delete('/api/todos/' + todo.id) 
            .subscribe(err => console.log(err), 
            () => console.log('getTodos Complete') 
            ); 
    }     
    remove(todo: Todo) { 
        this.deleteTodo(todo);         
    } 
    add(title: string): Promise<Todo> { 
        var todo = new Todo(0, title, false); 
        return this.postTodo(todo); 
    } 
    toggleCompletion(todo: Todo) { 
        todo.completed = !todo.completed; 
        this.putTodo(todo); 
    } 
    removeCompleted() { 
        this.getPendingTodos();         
    } 
    private handleError(error: any): Promise<any> { 
        console.error('An error occurred', error);  
        return Promise.reject(error.message || error); 
    } 
} 
```

### 更新 AppComponent

```ts
app.component.ts is as shown:
```

```ts
import { Component, OnInit } from '@angular/core'; 
import { Todo } from './todo' 
import { TodoService } from './todo.service' 
@Component({ 
    selector: 'my-app', 
    templateUrl: './app/app.component.html', 
    providers: [TodoService] 
}) 
export class AppComponent implements OnInit { 
    todos: Array<Todo>; 
    newTodoText = ''; 
    constructor(private todoService: TodoService) { 
        this.todos = new Array(); 
    } 
    getTodos(): void { 
        this.todoService 
            .getTodos() 
            .then(todos => this.todos = todos); 
    } 
    ngOnInit(): void { 
        this.getTodos(); 
    } 
    removeCompleted() { 
        this.todoService.removeCompleted(); 
        this.todos = this.getPending(); 
    } 
    toggleCompletion(todo: Todo) { 
        this.todoService.toggleCompletion(todo); 
    } 
    remove(todo: Todo) { 
        this.todoService.remove(todo); 
        this.todos.splice(this.todos.indexOf(todo), 1); 
    } 
    addTodo() { 
        if (this.newTodoText.trim().length) { 
        this.todoService.add(this.newTodoText).then(res =>    
   { 
            this.getTodos(); 
            }); 
            this.newTodoText = ''; 
            this.getTodos(); 
        } 
    } 
    getPending() { 
        return this.todos.filter((todo: Todo) => todo.completed === false); 
    } 
    getCompleted() { 
        return this.todos.filter((todo: Todo) => todo.completed === true); 
    } 
} 
```

### 更新 AppComponent 模板

`app.component.html` 的更新内容如下所示：

```ts
<section> 
    <header> 
        <h1>todos</h1> 
        <input placeholder="Add new todo" autofocus="" [(ngModel)]="newTodoText"> 
        <button type="button" (click)="addTodo()">Add</button> 
    </header> 
    <section> 
        <ul> 
            <li *ngFor="let todo of todos"> 
                <input type="checkbox" (click)="toggleCompletion(todo)" [checked]="todo.completed"> 
                <label>{{todo.title}}</label> 
                <button (click)="remove(todo)">X</button> 
            </li> 
        </ul> 
    </section> 
    <footer *ngIf="todos.length > 0"> 
        <span><strong>{{getPending().length}}</strong> {{getPending().length == 1 ? 'item' : 'items'}} left</span> 
        <button *ngIf="getCompleted().length > 0" (click)="removeCompleted()">Clear completed</button> 
    </footer> 
</section> 
```

`TexBox` 输入应用了双向绑定，使用 `ngModel` 来绑定新的 `Todo` 项目 `title`。 `Add` 按钮的点击事件与 `AppComponent` 中的 `addTodo` 方法绑定。可用的 `Todo` 项目将在 `<li>` 标签中列出，使用 `ngFor` 迭代 `TodoService` 中的每个 `Todo` 项目。 渲染每个 `Todo` 项目的复选框分别具有 `click` 事件和 `checked` 属性，与 `toggleCompletion` 方法和 `Todo` 项目的 `completed` 属性映射。 接下来，移除按钮的 `click` 事件与 `AppComponent` 中的 `remove` 方法映射。

`footer` 标签中有一个 span，显示待办 `Todo` 项目的计数以及一个按钮，用于从列表中移除已完成的 `Todo` 项目。这个按钮有一个点击事件，映射到 `AppComponent` 中的 `removeCompleted` 方法。

### 更新索引页面

```ts
index.html:
```

```ts
<!DOCTYPE html> 
<html> 
<head> 
    <title>My Todo</title> 
    <script>document.write('<base href="' +   
    document.location + '" />');</script> 
    <meta charset="UTF-8"> 
    <!-- Polyfills --> 
    <script src="img/shim.min.js"></script> 
    <script src="img/zone.min.js"></script> 
    <script src="img/system.src.js"></script> 
    <script src="img/systemjs.config.js"></script> 
    <script> 
      System.import('main.js').catch(function(err){ console.error(err); }); 
    </script> 
</head> 
<body> 
    <my-app>Loading My Todo App...</my-app> 
</body> 
</html> 
```

注意 `body` 标签中有一个特殊的 `<my-app/>` 标签, 这是 `AppComponent` 中的元数据。这是 `AppComponent` 将被实例化并使用模板渲染的地方。

## 运行应用程序

* * *

通过按下 *F5* 运行应用程序，之后，您将能够执行添加、编辑、删除和列出 `Todo` 项目等操作：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/lrn-ng-dnet-dev/img/image_06_014.png)

我的 Todo 应用程序具有所有操作

## 总结

* * *

我们从介绍 RESTful 服务开始本章，并为您概述了 ASP.NET Web API。我们还讨论了为什么 ASP.NET Web API 是 Angular 应用程序的最佳选择。然后，您了解了如何在 ASP.NET 5 项目中添加和配置 Entity Framework 以及使用数据库迁移来创建数据库所需的步骤。接下来，我们讲解了创建 Web API 服务和使用 Entity Framework 管理数据的过程。最后，您学会了如何从 Angular 应用程序中调用 Web API。

在本章中，我们讨论了如何从 Angular 应用程序中使用 Web API 服务来添加、更新、删除和检索数据库中的 Todo 项目，使用 Entity Framework。

在下一章中，我们将讨论如何将 Angular 应用程序与 ASP.NET MVC 和 Web API 集成。
