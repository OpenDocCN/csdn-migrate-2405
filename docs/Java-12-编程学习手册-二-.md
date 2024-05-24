# Java 12 编程学习手册（二）

> 原文：[Learn Java 12 Programming ](https://libgen.rs/book/index.php?md5=2D05FE7A99FD37AE2178F1DD99C27887)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 三、Java 基础

本章向读者展示了 Java 作为一种语言的更详细的视图。从包中的代码组织、类（接口）的可访问性级别及其方法和属性（字段）的描述入手，详细介绍了 Java 面向对象的主要类型&引用类型，并给出了保留关键字和限制关键字的列表，讨论了它们的用法。本章最后介绍了原始类型之间的转换方法，以及从原始类型到相应引用类型的转换方法。

这些是 Java 语言的基本术语和特性。他们理解的重要性怎么强调都不为过。没有它们，就不能编写任何 Java 程序。所以，尽量不要匆匆读完这一章，确保你理解了所有的内容。

本章将讨论以下主题：

*   包、导入和访问
*   Java 引用类型
*   保留和限制关键字
*   `this`和`super`关键字的用法
*   在原始类型之间转换
*   在原始类型和引用类型之间转换

# 包、导入和访问

如您所知，包名反映了目录结构，从包含`.java`文件的项目目录开始。每个`.java`文件的名称必须与其中声明的顶级类的名称相同（该类可以包含其他类）。`.java`文件的第一行是`package`语句，该语句以`package`关键字开头，后跟实际的包名—指向此文件的目录路径，其中斜杠替换为点

包名和类名一起构成一个**完全限定类名**。它唯一地标识类，但往往太长，使用起来不方便。也就是说，当**导入**成功时，只允许指定一次完全限定名，然后只通过类名引用类。

只有调用方能够访问某个类及其方法时，才能从另一个类的方法调用该类的方法。访问修饰符`public`、`protected`和`private`定义了可访问性级别，并允许（或不允许）某些方法、属性，甚至类本身对其他类可见。

本节将详细讨论所有这些方面。

# 包

让我们看看我们称之为`Packages`的类：

```java
package com.packt.learnjava.ch03_fundamentals;
import com.packt.learnjava.ch02_oop.hiding.C;
import com.packt.learnjava.ch02_oop.hiding.D;
public class Packages {
    public void method(){
        C c = new C();
        D d = new D();
    }
}
```

`Packages`类中的第一行是一个包声明，它标识源树上的类位置，或者换句话说，文件系统中的`.java`文件位置。在编译类并生成包含字节码的`.class`文件时，包名还反映了文件系统中的`.class`文件位置

# 导入

在包声明之后，`import`语句如下。从前面的示例中可以看出，它们允许避免在当前类的任何其他位置使用完全限定的类（或接口）名称。当导入来自同一个包的多个类（和接口）时，可以使用符号`*`将来自同一个包的所有类和接口作为一个组导入。在我们的示例中，它如下所示：

```java
import com.packt.learnjava.ch02_oop.hiding.*;

```

但这不是推荐的做法，因为当几个包作为一个组导入时，它会隐藏导入的类（和接口）位置。例如，请看以下代码段：

```java
package com.packt.learnjava.ch03_fundamentals;
import com.packt.learnjava.ch02_oop.*;
import com.packt.learnjava.ch02_oop.hiding.*;
public class Packages {
    public void method(){
        C c = new C();
        D d = new D();
    }
}
```

在前面的代码中，您能猜出类`C`或类`D`属于哪个包吗？另外，不同包中的两个类可能具有相同的名称。如果是这样，组导入可能会造成混乱，甚至是难以解决的问题。

也可以导入单个静态类（或接口）成员。例如，如果`SomeInterface`有一个`NAME`属性（提醒您，接口属性默认为`public`和`static`），您通常可以如下引用它：

```java
package com.packt.learnjava.ch03_fundamentals;
import com.packt.learnjava.ch02_oop.SomeInterface;
public class Packages {
    public void method(){
        System.out.println(SomeInterface.NAME);
    }
}
```

为了避免使用接口名称，可以使用静态导入：

```java
package com.packt.learnjava.ch03_fundamentals;
import static com.packt.learnjava.ch02_oop.SomeInterface.NAME;
public class Packages {
    public void method(){
        System.out.println(NAME);
    }
}
```

类似地，如果`SomeClass`具有公共静态属性`someProperty`和公共静态方法`someMethod()`，则也可以静态地导入它们：

```java
package com.packt.learnjava.ch03_fundamentals;
import com.packt.learnjava.ch02_oop.StaticMembers.SomeClass;
import com.packt.learnjava.ch02_oop.hiding.C;
import com.packt.learnjava.ch02_oop.hiding.D;
import static com.packt.learnjava.ch02_oop.StaticMembers
                                          .SomeClass.someMethod;
import static com.packt.learnjava.ch02_oop.StaticMembers
                                          .SomeClass.SOME_PROPERTY;
public class Packages {
    public static void main(String... args){
        C c = new C();
        D d = new D();

        SomeClass obj = new SomeClass();
        someMethod(42);
        System.out.println(SOME_PROPERTY);    //prints: abc
    }
}
```

但是应该明智地使用这种技术，因为它可能会造成静态导入的方法或属性属于当前类的印象。

# 访问修饰符

我们已经在我们的示例中使用了三个访问修饰符-`public`、`protected`和`private`-它们控制对类、接口和，还有第四个隐式的（也称为**默认修饰符**包级`private`），当没有指定三个显式访问修饰符时应用。

它们的使用效果非常简单：

*   `public`：可访问当前包和其他包的其他类和接口
*   `protected`：只允许同一个包的其他成员和该类的子级访问
*   无访问修饰符表示*仅可由同一包*的其他成员访问
*   `private`：只允许同一类成员访问

从类或接口内部，所有的类或接口成员总是可以访问的。此外，正如我们已经多次声明的那样，除非声明为`private`，否则所有接口成员在默认情况下都是公共的。

另外，请注意，类可访问性取代了类成员的可访问性，因为如果类本身不能从某个地方访问，那么对其方法或属性的可访问性的任何更改都不能使它们可访问。

当人们谈论类和接口的访问修饰符时，他们指的是在其他类或接口中声明的类和接口。包含的类或接口称为**顶级类或接口**，其中的类或接口称为**内部类或接口**。静态内部类也称为**静态嵌套类**。

声明顶级类或接口`private`是没有意义的，因为它不能从任何地方访问。Java 作者决定不允许顶级类或接口也被声明`protected`。但是，有一个没有显式访问修饰符的类是可能的，这样就使得它只能被同一个包的成员访问。

举个例子：

```java
public class AccessModifiers {
    String prop1;
    private String prop2;
    protected String prop3;
    public String prop4;

    void method1(){ }
    private void method2(){ }
    protected void method3(){ }
    public void method4(){ }

    class A1{ }
    private class A2{ }
    protected class A3{ }
    public class A4{ }

    interface I1 {}
    private interface I2 {}
    protected interface I3 {}
    public interface I4 {}
}
```

请注意，静态嵌套类*无权访问顶级类的其他成员*。

 *内部类的另一个特殊特性是它可以访问顶级类的所有成员，甚至私有成员，反之亦然。为了演示此功能，让我们在顶级类和私有内部类中创建以下私有属性和方法：

```java
public class AccessModifiers {
    private String topLevelPrivateProperty = "Top-level private value";
    private void topLevelPrivateMethod(){
        var inner = new InnerClass();
        System.out.println(inner.innerPrivateProperty);
        inner.innerPrivateMethod();
    }

    private class InnerClass {
        //private static String PROP = "Inner static"; //error
        private String innerPrivateProperty = "Inner private value";
        private void innerPrivateMethod(){
            System.out.println(topLevelPrivateProperty);
        }
    }

    private static class InnerStaticClass {
        private static String PROP = "Inner private static";
        private String innerPrivateProperty = "Inner private value";
        private void innerPrivateMethod(){
            var top = new AccessModifiers();
            System.out.println(top.topLevelPrivateProperty);
        }
    }
}
```

如您所见，前面类中的所有方法和属性都是私有的，这意味着通常不能从类外部访问它们。对于`AccessModifiers`类也是如此：它的私有方法和属性对于在它之外声明的其他类是不可访问的。但是`InnerClass`类可以访问顶级类的私有成员，而顶级类可以访问其内部类的私有成员。唯一的限制是非静态内部类不能有静态成员。相比之下，静态嵌套类可以同时具有静态和非静态成员，这使得静态嵌套类更加可用。

为了演示所描述的所有可能性，我们在类`AccessModifiers`中添加了以下`main()`方法：

```java
public static void main(String... args){
    var top = new AccessModifiers();
    top.topLevelPrivateMethod();
    //var inner = new InnerClass();  //error
    System.out.println(InnerStaticClass.PROP);
    var inner = new InnerStaticClass();
    System.out.println(inner.innerPrivateProperty);
    inner.innerPrivateMethod();
}
```

自然地，不能从顶级类的静态上下文访问非静态内部类，因此前面代码中的注释是无效的。如果我们运行它，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ea8ab7e7-4920-4650-897e-15c2b184413c.png)

输出的前两行来自`topLevelPrivateMethod()`，其余来自`main()`方法。如您所见，内部类和顶级类可以访问彼此的私有状态，从外部无法访问。

# Java 引用类型

`new`操作符创建一个类的对象，并返回对该对象所在内存的引用。从实际的角度来看，保存此引用的变量在代码中被视为对象本身。此类变量的类型可以是类、接口、数组或指示未向该变量分配内存引用的`null`文本。如果引用的类型是一个接口，则可以将其分配给`null`或对实现该接口的类的对象的引用，因为接口本身无法实例化。

JVM 监视所有创建的对象，并检查当前执行的代码中是否有对每个对象的引用。如果有一个对象没有任何引用，JVM 会在名为**垃圾收集**的进程中将其从内存中移除。我们将在第 9 章、“JVM 结构和垃圾收集”中描述这个过程。例如，在方法执行期间创建了一个对象，并由局部变量引用。此引用将在方法完成执行后立即消失。

您已经看到了定制类和接口的示例，我们已经讨论了`String`类（参见第 1 章、“Java12 入门”）。在本节中，我们还将描述另外两种 Java 引用类型数组和枚举，并演示如何使用它们

# 类和接口

类类型的变量使用相应的类名声明：

```java
<Class name> identifier;
```

可分配给此类变量的值可以是以下值之一：

*   引用类型字面值`null`（表示可以使用变量，但不引用任何对象）
*   对同一类的对象或其任何子对象的引用（因为子对象继承其所有祖先的类型）

最后一种类型的赋值被称为**加宽赋值**，因为它迫使一个特化的引用变得不那么专业化。例如，由于每个 Java 类都是`java.lang.Object`的子类，因此可以对任何类进行以下赋值：

```java
Object obj = new AnyClassName();
```

这种赋值也被称为**向上转型**，因为它将变量的类型在继承线上上移（与任何家谱树一样，通常在最上面显示最早的祖先）。

在这样的向上转型之后，可以使用转型操作符`(type)`进行缩小分配：

```java
AnyClassName anyClassName = (AnyClassName)obj;
```

这样的赋值也称为**向下转型**，允许您恢复子体类型。要应用此操作，必须确保标识符实际上引用了子体类型。如果有疑问，可以使用`instanceof`操作符（参见第 2 章、"Java 面向对象编程"）检查引用类型。

类似地，如果类实现某个接口，则可以将其对象引用指定给该接口或该接口的任何祖先：

```java
interface C {}
interface B extends C {}
class A implements B { }
B b = new A();
C c = new A();
A a1 = (A)b;
A a2 = (A)c;
```

如您所见，在类引用向上转换和向下转换的情况下，在将对象的引用分配给某个实现接口类型的变量之后，可以恢复该对象的原始类型

本节的内容也可以看作 Java 多态的另一个实际演示。

# 数组

**数组**是一种引用类型，因此也扩展了`java.lang.Object`类。数组元素的类型与声明的数组类型相同。元素的数目可以是零，在这种情况下，数组被称为空数组。每个元素都可以被一个索引访问，索引是正整数或零。第一个元素的索引为零。元素的数量称为数组长度。数组一旦创建，其长度就不会改变。

以下是数组声明的示例：

```java
int[] intArray;
float[][] floatArray;
String[] stringArray;
SomeClass[][][] arr;
```

每个括号对表示另一个维度。括号对的数目是数组的嵌套深度：

```java
int[] intArray = new int[10];
float[][] floatArray = new float[3][4];
String[] stringArray = new String[2];
SomeClass[][][] arr = new SomeClass[3][5][2];
```

`new`操作符为以后可以赋值（填充）的每个元素分配内存。但是数组的元素在创建时被初始化为默认值，如下例所示：

```java
System.out.println(intArray[3]);      //prints: 0
System.out.println(floatArray[2][2]); //prints: 0.0
System.out.println(stringArray[1]);   //prints: null

```

创建数组的另一种方法是使用数组初始化器，即用逗号分隔的值列表，每个维度都用大括号括起来。例如：

```java
int[] intArray = {1,2,3,4,5,6,7,8,9,10};
float[][] floatArray ={{1.1f,2.2f,3,2},{10,20.f,30.f,5},{1,2,3,4}};
String[] stringArray = {"abc", "a23"};

System.out.println(intArray[3]);      //prints: 4
System.out.println(floatArray[2][2]); //prints: 3.0
System.out.println(stringArray[1]);   //prints: a23

```

可以创建多维数组，而无需声明每个维度的长度。只有第一个维度必须指定长度：

```java
float[][] floatArray = new float[3][];

System.out.println(floatArray.length);  //prints: 3
System.out.println(floatArray[0]);      //prints: null
System.out.println(floatArray[1]);      //prints: null
System.out.println(floatArray[2]);      //prints: null
//System.out.println(floatArray[3]);    //error
//System.out.println(floatArray[2][2]); //error

```

其他尺寸的缺失长度可以稍后指定：

```java
float[][] floatArray = new float[3][];
floatArray[0] = new float[4];
floatArray[1] = new float[3];
floatArray[2] = new float[7];
System.out.println(floatArray[2][5]);   //prints: 0.0

```

这样，就可以为不同的尺寸指定不同的长度。使用数组初始化器，还可以创建不同长度的维度：

```java
float[][] floatArray ={{1.1f},{10,5},{1,2,3,4}};

```

唯一的要求是在使用维度之前必须对其进行初始化。

# 枚举

**枚举**引用类型类扩展了`java.lang.Enum`类，后者又扩展了`java.lang.Object`。它允许指定一组有限的常量，每个常量都是同一类型的实例。此类集合的声明以关键字`enum`开始。举个例子：

```java
enum Season { SPRING, SUMMER, AUTUMN, WINTER }
```

所列的每一项–`SPRING`、`SUMMER`、`AUTUMN`和`WINTER`–都是`Season `类型的实例。它们是`Season`类仅有的四个实例。它们是预先创建的，可以作为`Season`类型的值在任何地方使用。无法创建`Season`类的其他实例。这就是创建`enum`类型的原因：当一个类的实例列表必须限制为固定的集合时，可以使用它。

`enum`声明也可以用驼色字母写：

```java
enum Season { Spring, Summer, Autumn, Winter }
```

但是，使用全部大写样式的频率更高，因为正如我们前面提到的，有一个约定，在大写情况下表示静态最终常量的标识符。它有助于区分常量和变量。`enum`常量是静态的，隐式地是最终的。

因为`enum`值是常量，所以它们在 JVM 中是唯一存在的，可以通过引用进行比较：

```java
Season season = Season.WINTER;
boolean b = season == Season.WINTER;
System.out.println(b);   //prints: true
```

以下是`java.lang.Enum`类中最常用的方法：

*   `name()`：按声明时的拼写返回`enum`常量的标识符（例如`WINTER`）。
*   `toString()`：默认返回与`name()`方法相同的值，但可以覆盖以返回任何其他`String`值。
*   `ordinal()`：返回声明时`enum`常量的位置（列表中第一个有`0`序数值）。
*   `valueOf(Class enumType, String name)`：返回`enum`常量对象，其名称表示为`String`文本。
*   `values()`：在`java.lang.Enum`类的文档中没有描述的静态方法。在[《Java 语言规范 8.9.3》](https://docs.oracle.com/javase/specs/jls/se12/html/jls-8.html#jls-8.9.3)中，描述为隐式声明。[《Java™ 教程》](https://docs.oracle.com/javase/tutorial/java/javaOO/enum.html)表示编译器在创建`enum`时会自动添加一些特殊方法，其中静态`values()`方法按声明顺序返回包含`enum`所有值的数组。

为了演示上述方法，我们将使用已经熟悉的`enum`、`Season`：

```java
enum Season { SPRING, SUMMER, AUTUMN, WINTER }
```

下面是演示代码：

```java
System.out.println(Season.SPRING.name());            //prints: SPRING
System.out.println(Season.WINTER.toString());        //prints: WINTER
System.out.println(Season.SUMMER.ordinal());         //prints: 1
Season season = Enum.valueOf(Season.class, "AUTUMN");
System.out.println(season == Season.AUTUMN);         //prints: true

for(Season s: Season.values()){
    System.out.print(s.name() + " "); 
                               //prints: SPRING SUMMER AUTUMN WINTER
}
```

为了覆盖`toString()`方法，我们创建`enum Season1`：

```java
enum Season1 {
    SPRING, SUMMER, AUTUMN, WINTER;
    public String toString() {
        return this.name().charAt(0) + 
               this.name().substring(1).toLowerCase();
    }
}
```

其工作原理如下：

```java
for(Season1 s: Season1.values()){
    System.out.print(s.toString() + " "); 
                                 //prints: Spring Summer Autumn Winter
}
```

可以向每个`enum`常量添加任何其他属性。例如，让我们为每个`enum`实例添加一个平均温度值：

```java
enum Season2 {
    SPRING(42), SUMMER(67), AUTUMN(32), WINTER(20);
    private int temperature;
    Season2(int temperature){
        this.temperature = temperature;
    }
    public int getTemperature(){
        return this.temperature;
    }
    public String toString() {
        return this.name().charAt(0) +
                this.name().substring(1).toLowerCase() +
                "(" + this.temperature + ")";
    }
}
```

如果我们迭代`enum Season2`的值，结果如下：

```java
for(Season2 s: Season2.values()){
    System.out.print(s.toString() + " "); 
              //prints: Spring(42) Summer(67) Autumn(32) Winter(20)
}
```

在标准 Java 库中，有几个`enum`类。例如，`java.time.Month`、`java.time.DayOfWeek`、`java.util.concurrent.TimeUnit`

# 默认值和字面值

我们已经看到，引用类型的默认值是`null`。一些源代码将其称为**特殊类型**`null`，但 Java 语言规范将其限定为文本。当引用类型的实例属性或数组自动初始化时（未显式赋值时），赋值为`null`

除了`null`字面值之外，唯一的引用类型是`String`类，我们在第 1 章、“Java12 入门”中讨论了字符串。

# 作为方法参数的引用类型

当一个原始类型值被传递到一个方法中时，我们使用它。如果我们不喜欢传递到方法中的值，我们会根据需要进行更改，并且不会三思而后行：

```java
void modifyParameter(int x){
    x = 2;
}
```

我们不担心方法之外的变量值会发生变化：

```java
int x = 1;
modifyParameter(x);
System.out.println(x);  //prints: 1

```

无法在方法之外更改原始类型的参数值，因为原始类型参数是通过值传递到方法的。这意味着值的副本被传递到方法中，因此即使方法中的代码为其指定了不同的值，原始值也不会受到影响。

引用类型的另一个问题是，即使引用本身是通过值传递的，它仍然指向内存中相同的原始对象，因此方法中的代码可以访问该对象并修改它。为了演示它，让我们创建一个`DemoClass`和使用它的方法：

```java
class DemoClass{
    private String prop;
    public DemoClass(String prop) { this.prop = prop; }
    public String getProp() { return prop; }
    public void setProp(String prop) { this.prop = prop; }
}
void modifyParameter(DemoClass obj){
    obj.setProp("Changed inside the method");
}
```

如果我们使用上述方法，结果如下：

```java
DemoClass obj = new DemoClass("Is not changed");
modifyParameter(obj);
System.out.println(obj.getProp()); //prints: Changed inside the method

```

这是一个很大的区别，不是吗？因此，您必须小心不要修改传入的对象以避免产生不希望的效果。但是，此效果偶尔用于返回结果。但它不属于最佳实践列表，因为它会降低代码的可读性。更改传入对象就像使用一个难以注意的秘密隧道。所以，只有在必要的时候才使用它。

即使传入的对象是一个包装原始类型值的类，这种效果仍然有效（我们将在“原始和引用类型”之间的转换部分讨论原始类型值包装类型），下面是一个`DemoClass1`和一个重载版本的`modifyParameter()`方法：

```java
class DemoClass1{
    private Integer prop;
    public DemoClass1(Integer prop) { this.prop = prop; }
    public Integer getProp() { return prop; }
    public void setProp(Integer prop) { this.prop = prop; }
}
void modifyParameter(DemoClass1 obj){
    obj.setProp(Integer.valueOf(2));
}
```

如果我们使用上述方法，结果如下：

```java
DemoClass1 obj = new DemoClass1(Integer.valueOf(1));
modifyParameter(obj);
System.out.println(obj.getProp());  //prints: 2

```

引用类型的这种行为的唯一例外是`String`类的对象。下面是另一个重载版本的`modifyParameter()`方法：

```java
void modifyParameter(String obj){
    obj = "Changed inside the method";
}  
```

如果我们使用上述方法，结果如下：

```java
String obj = "Is not changed";
modifyParameter(obj);
System.out.println(obj); //prints: Is not changed

obj = new String("Is not changed");
modifyParameter(obj);
System.out.println(obj); //prints: Is not changed

```

如您所见，无论我们使用一个字面值还是一个新的`String`对象，结果都是一样的：在给它赋值的方法之后，原始的`String`值没有改变。这正是我们在第 1 章“Java12 入门”中讨论的`String`值不变性特性的目的

# `equals()`方法

等式运算符（`==`应用于引用类型的变量时，比较的是引用本身，而不是对象的内容（状态）。但是两个对象总是有不同的内存引用，即使它们有相同的内容。即使用于`String`对象，如果至少有一个对象是使用`new`操作符创建的，操作符（`==`也会返回`false`（参见第 1 章“Java12 入门”中关于`String`值不变性的讨论）。

要比较内容，可以使用`equals()`方法。它在`String`类和数值类型包装类（`Integer`、`Float`等）中的实现正好可以比较对象的内容

然而，`java.lang.Object`类中的`equals()`方法实现只比较引用，这是可以理解的，因为子类可能拥有的内容种类繁多，而泛型内容比较的实现是不可行的。这意味着每一个需要有`equals()`方法来比较对象内容而不仅仅是引用的 Java 对象都必须重新实现`equals()`方法，从而在`java.lang.Object`类中覆盖其实现，如下所示：

```java
  public boolean equals(Object obj) {
       return (this == obj);
}
```

相比之下，看看同样的方法是如何在`Integer`类中实现的：

```java
private final int value;
public boolean equals(Object obj) {
    if (obj instanceof Integer) {
        return value == ((Integer)obj).intValue();
    }
    return false;
}

```

如您所见，它从输入对象中提取原始`int`值，并将其与当前对象的原始值进行比较。它根本不比较对象引用

另一方面，`String`类首先比较引用，如果引用的值不相同，则比较对象的内容：

```java
private final byte[] value;
public boolean equals(Object anObject) {
      if (this == anObject) {
            return true;
      }
      if (anObject instanceof String) {
         String aString = (String)anObject;
         if (coder() == aString.coder()) {
           return isLatin1() ? StringLatin1.equals(value, aString.value)
                             : StringUTF16.equals(value, aString.value);
         }
      }
      return false;
}
```

`StringLatin1.equals()`和`StringUTF16.equals()`方法逐个字符比较值，而不仅仅是引用值。

类似地，如果应用代码需要按内容比较两个对象，则必须覆盖相应类中的`equals()`方法。例如，让我们看看熟悉的`DemoClass`类：

```java
class DemoClass{
    private String prop;
    public DemoClass(String prop) { this.prop = prop; }
    public String getProp() { return prop; }
    public void setProp(String prop) { this.prop = prop; }
}
```

我们可以手动添加`equals()`方法，但是 IDE 可以帮助我们完成以下操作：

1.  在类中右键单击右大括号（`}`）
2.  选择“生成”，然后按照提示进行操作

最终，将生成两个方法并将其添加到类中：

```java
@Override
public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DemoClass)) return false;
    DemoClass demoClass = (DemoClass) o;
    return Objects.equals(getProp(), demoClass.getProp());
}

@Override
public int hashCode() {
    return Objects.hash(getProp());
}
```

通过查看生成的代码，我们希望您注意以下几点：

*   `@Override`注解的用法：它确保该方法覆盖某个祖先中的方法（具有相同的签名）。有了这个注解，如果您修改了方法并更改了签名（错误地或有意地），编译器（和您的 IDE）将立即引发一个错误，告诉您在任何祖先类中都没有具有这种签名的方法。因此，它有助于及早发现错误。
*   `java.util.Objects`类的用法：它有很多非常有用的方法，包括`equals()`静态方法，它不仅比较引用，还使用`equals()`方法：

```java
     public static boolean equals(Object a, Object b) {
         return (a == b) || (a != null && a.equals(b));
     }
```

因为，正如我们前面所演示的，在`String`类中实现的`equals()`方法根据字符串的内容进行比较，符合我们的目的，因为`DemoClass`的方法`getProp()`返回一个字符串

*   `hashCode()`方法：这个方法返回的整数唯一地标识这个特定的对象（但是请不要期望它在应用的不同运行之间是相同的）。如果唯一需要的方法是`equals()`，则不需要实现此方法。尽管如此，我们还是建议在`Set`或基于哈希码的另一个集合中收集此类的对象时使用它（我们将在第 6 章、“数据结构、泛型和流行工具”中讨论 Java 集合）

这两种方法都在`Object`中实现，因为许多算法使用`equals()`和`hashCode()`方法，如果没有实现这些方法，应用可能无法工作。同时，对象在应用中可能不需要它们。但是，一旦您决定实现`equals()`方法，也可以实现`hasCode()`方法。此外，正如您所看到的，IDE 可以做到这一点而不需要任何开销。

# 保留和受限关键字

**关键字**是对编译器有特殊意义的词，不能用作标识符。保留关键字 51 个，限制关键字 10 个。保留关键字不能在 Java 代码中的任何地方用作标识符，而受限关键字只能在模块声明的上下文中用作标识符。

# 保留关键字

以下是所有 Java 保留关键字的列表：

| | | | | |
| --- | --- | --- | --- | --- |
| `abstract` | `assert` | `boolean` | `break` | `byte` |
| `case` | `catch` | `char` | `class` | `const` |
| `continue` | `default` | `do` | `double` | `else` |
| `enum` | `extends` | `final ` | `finally` | `float` |
| `for` | `if` | `goto` | `implements` | `import` |
| `instanceof` | `int` | `interface` | `long` | `native` |
| `new` | `package` | `private` | `protected` | `public` |
| `return` | `short` | `static` | `strictfp` | `super` |
| `switch` | `synchronized` | `this` | `throw` | `throws` |
| `transient` | `try` | `void` | `volatile` | `while` |

下划线（`_`也是一个保留字。

到现在为止，您应该对前面的大多数关键字都很熟悉了。通过一个练习，你可以浏览一下清单，看看你记得其中有多少。我们不仅仅讨论了以下八个关键词：

*   `const`和`goto`已保留，但尚未使用
*   `assert`关键字用于`assert`语句中（我们将在第 4 章、“处理”中讨论）
*   `synchronized`关键字用于并发编程（我们将在第 8 章、“多线程和并发处理”中讨论）
*   `volatile`关键字使变量的值不被缓存
*   `transient`关键字使变量的值不可序列化
*   `strictfp`关键字限制浮点计算，使得在对浮点变量执行操作时，每个平台上的结果相同
*   关键字 AutoT0:Audio 声明了一种在依赖于平台的代码中实现的方法，如 C 或 C++。

# 受限关键字

Java 中的 10 个受限关键字如下：

*   `open`
*   `module`
*   `requires`
*   `transitive`
*   `exports`
*   `opens`
*   `to`
*   `uses`
*   `provides`
*   `with`

它们被称为*受限*，因为它们不能作为模块声明上下文中的标识符，这在本书中我们将不讨论。在所有其他地方，都可以将它们用作标识符。例如：

```java
String to = "To";
String with = "abc";
```

尽管可以，但最好不要将它们用作标识符，即使是在模块声明之外

# `this`和`super`关键字的用法

`this`关键字提供对当前对象的引用。`super`关键字引用父类对象。这些关键字允许我们引用在当前上下文和父对象中具有相同名称的变量或方法。

# `this`关键字的用法

下面是最流行的例子：

```java
class A {
    private int count;
    public void setCount(int count) {
        count = count;         // 1
    }
    public int getCount(){
        return count;          // 2
    }
}
```

第一行看起来模棱两可，但事实上并非如此：局部变量`int count`隐藏实例私有属性`int count`。我们可以通过运行以下代码来演示：

```java
A a = new A();
a.setCount(2);
System.out.println(a.getCount());     //prints: 0

```

使用`this`关键字修复问题：

```java
class A {
    private int count;
    public void setCount(int count) {
        this.count = count;         // 1
    }
    public int getCount(){
        return this.count;          // 2
    }
}
```

将`this`添加到第 1 行允许将值赋给实例属性。在第 2 行中添加`this`并没有什么区别，但是每次都使用`this`关键字和`instance`属性是一个很好的做法。它使代码更具可读性，并有助于避免难以跟踪的错误，例如我们刚刚演示的错误。

我们也看到了`equals()`方法中的`this`关键字用法：

```java
@Override
public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DemoClass)) return false;
    DemoClass demoClass = (DemoClass) o;
    return Objects.equals(getProp(), demoClass.getProp());
}
```

并且，为了提醒您，下面是我们在第 2 章、“Java 面向对象编程（OOP）”中介绍的构造器示例：

```java
class TheChildClass extends TheParentClass{
    private int x;
    private String prop;
    private String anotherProp = "abc";
    public TheChildClass(String prop){
        super(42);
        this.prop = prop;
    }
    public TheChildClass(int arg1, String arg2){
        super(arg1);
        this.prop = arg2;
    }
    // methods follow
}
```

在前面的代码中，您不仅可以看到`this`关键字，还可以看到`super`关键字的用法，我们将在下面讨论。

# super 关键字的用法

`super`关键字引用父对象。我们已经在“构造器中的`this`关键字的用法”部分中看到了它的用法，因为必须先创建父类对象，然后才能创建当前对象。如果构造器的第一行不是`super()`，则表示父类有一个没有参数的构造器。

当方法被覆盖并且必须调用父类的方法时，`super`关键字特别有用：

```java
class B  {
    public void someMethod() {
        System.out.println("Method of B class");
    }
}
class C extends B {
    public void someMethod() {
        System.out.println("Method of C class");
    }
    public void anotherMethod() {
        this.someMethod();    //prints: Method of C class
        super.someMethod();   //prints: Method of B class
    }
}
```

随着本书的深入，我们将看到更多使用`this`和`super`关键字的例子。

# 在原始类型之间转换

一个数值类型可以容纳的最大数值取决于分配给它的位数。以下是每种数字表示形式的位数：

*   `byte`：8 位
*   `char`：16 位
*   `short`：16 位
*   `int`：32 位
*   `long`：64 位
*   `float`：32 位
*   `double`：64 位

当一个数值类型的值被分配给另一个数值类型的变量，并且新类型可以容纳更大的数值时，这种转换被称为**加宽转换**。否则，它是一个**缩小转换**，通常需要使用`cast`操作符进行类型转换

# 加宽转换

根据 Java 语言规范，有 19 种基本类型转换：

*   `byte`至`short`、`int`、`long`、`float`或`double`
*   `short`至`int`、`long`、`float`或`double`
*   `char`至`int`、`long`、`float`或`double`
*   `int`至`long`、`float`或`double`
*   `long`至`float`或`double`
*   `float`至`double`

在整数类型之间以及从某些整数类型到浮点类型的加宽转换过程中，生成的值与原始值完全匹配。然而，从`int`到`float`，或从`long`到`float`，或从`long`到`double`的转换可能会导致精度损失。根据 Java 语言规范，产生的浮点值可以使用`IEEE 754 round-to-nearest mode`正确舍入。以下几个例子说明了精度的损失：

```java
int i = 123456789;
double d = (double)i;
System.out.println(i - (int)d);    //prints: 0

long l1 = 12345678L;
float f1 = (float)l1;
System.out.println(l1 - (long)f1);    //prints: 0

long l2 = 123456789L;
float f2 = (float)l2;
System.out.println(l2 - (long)f2);    //prints: -3

long l3 = 1234567891111111L;
double d3 = (double)l3;
System.out.println(l3 - (long)d3);    //prints: 0

long l4 = 12345678999999999L;
double d4 = (double)l4;
System.out.println(l4 - (long)d4);    //prints: -1 
```

如您所见，从`int`到`double`的转换保留了值，但是`long`到`float`或`long`到`double`可能会失去精度。这取决于这个值有多大。所以，如果它对你的计算很重要的话，请注意并考虑到精度的损失。

# 缩小转换

Java 语言规范确定了 22 种缩小原始类型转换：

*   `short`至`byte`或`char`
*   `char`至`byte`或`short`
*   `int`至`byte`、`short`或`char`
*   `long`至`byte`、`short`、`char`或`int`
*   `float`至`byte`、`short`、`char`、`int`或`long`
*   `double`至`byte`、`short`、`char`、`int`、`long`或`float`

与加宽转换类似，变窄转换可能导致精度损失，甚至值幅度损失。缩小的转换比扩大的转换更复杂，在本书中我们将不讨论它。请务必记住，在执行缩小之前，必须确保原始值小于目标类型的最大值。否则，您可以得到完全不同的值（丢失幅值）。请看以下示例：

```java
System.out.println(Integer.MAX_VALUE); //prints: 2147483647
double d1 = 1234567890.0;
System.out.println((int)d1);           //prints: 1234567890

double d2 = 12345678909999999999999.0;
System.out.println((int)d2);           //prints: 2147483647

```

从示例中可以看出，不必首先检查目标类型是否可以容纳该值，就可以得到正好等于目标类型的最大值的结果。剩下的就要丢了，不管差别有多大。

在执行缩小转换之前，请检查目标类型的最大值是否可以保持原始值。

请注意，`char`类型和`byte`或`short`类型之间的转换是一个更复杂的过程，因为`char`类型是无符号数字类型，而`byte`和`short`类型是有符号数字类型，所以即使值看起来像它符合目标类型。

# 转换方法

除了转换之外，每个原始类型都有一个对应的引用类型（称为**包装类**），该类具有将该类型的值转换为除`boolean`和`char`之外的任何其他原始类型的方法。所有包装类都属于`java.lang`包：

*   `java.lang.Boolean`
*   `java.lang.Byte`
*   `java.lang.Character`
*   `java.lang.Short`
*   `java.lang.Integer`
*   `java.lang.Long`
*   `java.lang.Float`
*   `java.lang.Double`

除了类`Boolean`和`Character`之外，它们都扩展了抽象类`java.lang.Number`，抽象类有以下抽象方法：

*   `byteValue()`
*   `shortValue()`
*   `intValue()`
*   `longValue()`
*   `floatValue()`
*   `doubleValue()`

这样的设计迫使`Number`类的后代实现所有这些。它们产生的结果与前面示例中的`cast`运算符相同：

```java
int i = 123456789;
double d = Integer.valueOf(i).doubleValue();
System.out.println(i - (int)d);          //prints: 0

long l1 = 12345678L;
float f1 = Long.valueOf(l1).floatValue();
System.out.println(l1 - (long)f1);       //prints: 0

long l2 = 123456789L;
float f2 = Long.valueOf(l2).floatValue();
System.out.println(l2 - (long)f2);       //prints: -3

long l3 = 1234567891111111L;
double d3 = Long.valueOf(l3).doubleValue();
System.out.println(l3 - (long)d3);       //prints: 0

long l4 = 12345678999999999L;
double d4 = Long.valueOf(l4).doubleValue();
System.out.println(l4 - (long)d4);       //prints: -1

double d1 = 1234567890.0;
System.out.println(Double.valueOf(d1)
                         .intValue());   //prints: 1234567890

double d2 = 12345678909999999999999.0;
System.out.println(Double.valueOf(d2)
                         .intValue());   //prints: 2147483647

```

此外，每个包装器类都有允许将数值的`String`表示转换为相应的原始数值类型或引用类型的方法。例如：

```java
byte b1 = Byte.parseByte("42");
System.out.println(b1);             //prints: 42
Byte b2 = Byte.decode("42");
System.out.println(b2);             //prints: 42

boolean b3 = Boolean.getBoolean("property");
System.out.println(b3);            //prints: false
Boolean b4 = Boolean.valueOf("false");
System.out.println(b4);            //prints: false

int i1 = Integer.parseInt("42");
System.out.println(i1);            //prints: 42
Integer i2 = Integer.getInteger("property");
System.out.println(i2);            //prints: null

double d1 = Double.parseDouble("3.14");
System.out.println(d1);            //prints: 3.14
Double d2 = Double.valueOf("3.14");
System.out.println(d2);            //prints: 3.14

```

在示例中，请注意接受参数**属性**的两种方法。这两种方法以及其他包装类的类似方法将系统属性（如果存在）转换为相应的原始类型。

并且每个包装器类都有一个`toString(primitive value)`静态方法来将原始类型值转换为它的`String`表示。例如：

```java
String s1 = Integer.toString(42);
System.out.println(s1);            //prints: 42
String s2 = Double.toString(3.14);
System.out.println(s2);            //prints: 3.14
```

包装器类还有许多其他有用的方法，可以将一种原始类型转换为另一种原始类型和不同的格式。因此，如果您需要这样做，请首先查看相应的包装器类。

# 在原始类型和引用类型之间转换

将原始类型值转换为相应包装类的对象称为**装箱**。此外，从包装类的对象到相应的原始类型值的转换被称为**拆箱**。

# 装箱

原始类型的装箱可以自动补全（称为**自动装箱**），也可以显式使用每个包装器类型中可用的`valueOf()`方法完成：

```java
int i1 = 42;
Integer i2 = i1;              //autoboxing
//Long l2 = i1;               //error
System.out.println(i2);       //prints: 42

i2 = Integer.valueOf(i1);
System.out.println(i2);       //prints: 42

Byte b = Byte.valueOf((byte)i1);
System.out.println(b);       //prints: 42

Short s = Short.valueOf((short)i1);
System.out.println(s);       //prints: 42

Long l = Long.valueOf(i1);
System.out.println(l);       //prints: 42

Float f = Float.valueOf(i1);
System.out.println(f);       //prints: 42.0

Double d = Double.valueOf(i1);
System.out.println(d);       //prints: 42.0 
```

请注意，只有在将原始类型转换为相应的包装器类型时，才能进行自动装箱。否则，编译器将生成一个错误。

`Byte`和`Short`包装器的方法`valueOf()`的输入值需要强制转换，因为这是我们在上一节讨论过的原始类型的缩小。

# 拆箱

拆箱可以使用在每个包装类中实现的`Number`类的方法来完成：

```java
Integer i1 = Integer.valueOf(42);
int i2 = i1.intValue();
System.out.println(i2);      //prints: 42

byte b = i1.byteValue();
System.out.println(b);       //prints: 42

short s = i1.shortValue();
System.out.println(s);       //prints: 42

long l = i1.longValue();
System.out.println(l);       //prints: 42

float f = i1.floatValue();
System.out.println(f);       //prints: 42.0

double d = i1.doubleValue();
System.out.println(d);       //prints: 42.0

Long l1 = Long.valueOf(42L);
long l2 = l1;                //implicit unboxing
System.out.println(l2);      //prints: 42

double d2 = l1;              //implicit unboxing
System.out.println(d2);      //prints: 42

long l3 = i1;                //implicit unboxing
System.out.println(l3);      //prints: 42

double d3 = i1;              //implicit unboxing
System.out.println(d3);      //prints: 42
```

从示例中的注释可以看出，从包装器类型到相应的原始类型的转换不是称为**自动拆箱**，而是称为**隐式拆箱**。与自动装箱不同的是，即使在包装和不匹配的原始类型之间也可以使用隐式拆箱。

# 总结

在本章中，您了解了什么是 Java 包，以及它们在组织代码和类可访问性（包括`import`语句和访问修饰符）方面所起的作用。您还熟悉了引用类型：类、接口、数组和枚举。任何引用类型的默认值为`null`，包括`String`类型。

现在您了解了引用类型是通过引用传递到方法中的，以及如何使用和覆盖`equals()`方法。您还学习了保留关键字和限制关键字的完整列表，了解了`this`和`super`关键字的含义和用法。

本章最后描述了原始类型、包装类型和`String`字面值之间转换的过程和方法。

在下一章中，我们将讨论 Java 异常框架、受检和非受检（运行时）异常、`try-catch-finally`块、`throws`和`throw`语句，以及异常处理的最佳实践。

# 测验

1.  选择所有正确的语句：
    1.  `Package`语句描述类或接口位置
    2.  `Package`语句描述类或接口名称
    3.  `Package`是一个完全限定的名称
    4.  `Package`名称和类名构成了类的完全限定名

2.  选择所有正确的语句：
    1.  `Import`语句允许使用完全限定名
    2.  `Import`语句必须是`.java`文件中的第一个语句
    3.  `Group import`语句只引入一个包的类（和接口）
    4.  `Import statement`允许避免使用完全限定名

3.  选择所有正确的语句：
    1.  如果没有访问修饰符，该类只能由同一包的其他类和接口访问
    2.  私有类的私有方法可以被同一`.java`文件中声明的其他类访问
    3.  私有类的`public`方法可以被不在同一`.java`文件中声明但来自同一包的其他类访问
    4.  受保护的方法只能由类的后代访问

4.  选择所有正确的语句：
    1.  私有方法可以重载，但不能覆盖
    2.  受保护的方法可以覆盖，但不能重载
    3.  没有访问修饰符的方法可以被覆盖和重载
    4.  私有方法可以访问同一类的私有属性

5.  选择所有正确的语句：
    1.  缩小和向上转型是同义词
    2.  加宽和向下转型是同义词
    3.  加宽和向上转型是同义词
    4.  加宽和缩小与向上转型和向下转型没有任何共同之处

6.  选择所有正确的语句：
    1.  `Array`是一个对象
    2.  `Array`的长度是它能容纳的元素的数量
    3.  数组的第一个元素具有索引 1
    4.  数组的第二个元素具有索引 1

7.  选择所有正确的语句：
    1.  `Enum`包含常量。
    2.  `Enum`总是有一个构造器，默认或显式
    3.  `enum`常量可以有属性
    4.  `Enum`可以有任何引用类型的常量

8.  选择所有正确的语句：
    1.  可以修改作为参数传入的任何引用类型
    2.  作为参数传入的`new String()`对象可以修改
    3.  不能修改作为参数传入的对象引用值
    4.  作为参数传入的数组可以将元素指定给不同的值

9.  选择所有正确的语句：
    1.  不能使用保留关键字
    2.  受限关键字不能用作标识符
    3.  保留关键字`identifier`不能用作标识符
    4.  保留关键字不能用作标识符

10.  选择所有正确的语句：
    1.  `this`关键字是指`current`类
    2.  `super`关键字是指`super`类
    3.  关键词`this`和`super`指的是对象
    4.  `this`和`super`是指方法

11.  选择所有正确的语句：
    1.  原始类型的加宽使值变大
    2.  原始类型的缩小总是会更改值的类型
    3.  原始类型的加宽只能在缩小转换后进行
    4.  缩小会使值变小

12.  选择所有正确的语句：
    1.  装箱限制了值
    2.  拆箱将创建一个新值
    3.  装箱创建引用类型对象
    4.  拆箱将删除引用类型对象

# 四、异常处理

我们在第 1 章“Java12 入门”中简要介绍了异常。在本章中，我们将更系统地讨论这个问题。Java 中有两种异常：受检异常和非受检异常。两者都将被演示，并解释两者之间的区别。读者还将了解与异常处理相关的 Java 构造的语法以及处理异常的最佳实践。本章将以可用于调试生产代码的断言语句的相关主题结束。

本章将讨论以下主题：

*   Java 异常框架
*   受检和非受检（运行时）异常
*   `try`、`catch`和`finally`块
*   `throws`声明
*   `throw`声明
*   `assert`声明
*   异常处理的最佳实践

# Java 异常框架

正如我们在[第一章](01.html)“Java12 入门”中所描述的，一个意外的情况可能会导致 **Java 虚拟机**（**JVM**）创建并抛出一个异常对象，或者应用代码可以这样做。一旦发生异常，如果异常是在一个`try`块中抛出的，那么控制流就被转移到`catch`子句。让我们看一个例子。考虑以下方法：

```java
void method(String s){
    if(s.equals("abc")){
        System.out.println("Equals abc");
    } else {
        System.out.println("Not equal");
    }
}
```

如果输入参数值为`null`，则可以预期输出为`Not equal`。不幸的是，情况并非如此。`s.equals("abc")`表达式对`s`变量引用的对象调用`equals()`方法，但是，如果`s`变量是`null`，则它不引用任何对象。让我们看看会发生什么。

让我们运行以下代码：

```java
try {
    method(null);
} catch (Exception ex){
    System.out.println(ex.getClass().getCanonicalName());  
                              //prints: java.lang.NullPointerException
    ex.printStackTrace();     //prints: see the screenshot
    if(ex instanceof NullPointerException){
        //do something
    } else {
        //do something else
    }
}
```

此代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/823979db-4f8b-4c79-b453-77b17989e501.png)

在屏幕截图上看到的红色部分称为**栈跟踪**。名称来自方法调用在 JVM 内存中的存储方式（作为栈）：一个方法调用另一个方法，而另一个方法又反过来调用另一个方法，依此类推。在最内部的方法返回后，遍历栈，并从栈中移除返回的方法（**栈帧**）（我们将在第 9 章、“JVM 结构和垃圾收集”中详细讨论 JVM 内存结构）。当发生异常时，所有栈内容（栈帧）都作为栈跟踪返回。它允许我们追踪导致问题的代码行。

在前面的代码示例中，根据异常的类型执行不同的代码块。在我们的案例中，是`java.lang.NullPointerException`。如果应用代码没有捕获它，这个异常将通过被调用方法的栈一直传播到 JVM 中，JVM 随后停止执行应用。为了避免这种情况的发生，可以捕获异常并执行一些代码来从异常情况中恢复。

Java 中异常处理框架的目的是保护应用代码不受意外情况的影响，并在可能的情况下从中恢复。在下面的部分中，我们将更详细地剖析它，并使用框架功能重新编写给定的示例。

# 受检和非受检的异常

如果你查阅`java.lang`包 API 的文档，你会发现这个包包含了近三十个异常类和几十个错误类。两个组都扩展了`java.lang.Throwable`类，从中继承所有方法，并且不添加其他方法。`java.lang.Throwable`类最常用的方法如下：

*   `void printStackTrace()`：输出方法调用的栈跟踪（栈帧）
*   `StackTraceElement[] getStackTrace()`：返回与`printStackTrace()`相同的信息，但允许对栈跟踪的任何帧进行编程访问
*   `String getMessage()`：检索通常包含异常或错误原因的用户友好解释的消息
*   `Throwable getCause()`：检索`java.lang.Throwable`的可选对象，该对象是异常的原始原因（但代码的作者决定将其包装在另一个异常或错误中）

所有错误都扩展了`java.lang.Error`类，而`java.lang.Error`类又扩展了`java.lang.Throwable`类。一个错误通常是由 JVM 抛出的，根据官方文档，*表示一个合理的应用不应该试图捕捉*的严重问题。以下是几个例子：

*   `OutOfMemoryError`：当 JVM 耗尽内存并且无法使用垃圾收集清理内存时抛出
*   `StackOverflowError`：当分配给方法调用栈的内存不足以存储另一个栈帧时抛出
*   `NoClassDefFoundError`：当 JVM 找不到当前加载的类所请求的类的定义时抛出

框架的作者假设应用不能自动从这些错误中恢复，这在很大程度上被证明是正确的假设。这就是为什么程序员通常不会捕捉到错误，我们将不再讨论它们。

另一方面，异常通常与特定于应用的问题相关，通常不需要我们关闭应用并允许恢复。这就是为什么程序员通常会捕捉到它们并实现应用逻辑的替代（主流程）路径，或者至少在不关闭应用的情况下报告问题。以下是几个例子：

*   `ArrayIndexOutOfBoundsException`：当代码试图通过等于或大于数组长度的索引访问元素时抛出（记住数组的第一个元素有索引`0`，所以索引等于数组之外的数组长度点）
*   `ClassCastException`：当代码对与变量引用的对象无关的类或接口进行引用时抛出
*   `NumberFormatException`：当代码试图将字符串转换为数字类型，但字符串不包含必需的数字格式时抛出

所有异常都扩展了`java.lang.Exception`类，而`java.lang.Exception`类又扩展了`java.lang.Throwable`类。这就是为什么通过捕捉`java.lang.Exception`类的对象，代码捕捉任何异常类型的对象。我们已经在“Java 异常框架”一节中通过这种方式捕获了`java.lang.NullPointerException`进行了演示。

异常之一是`java.lang.RuntimeException`。扩展它的异常称为**运行时异常**或**非受检异常**。我们已经提到了其中的一些：`NullPointerException`、`ArrayIndexOutOfBoundsException`、`ClassCastException`和`NumberFormatException`。为什么它们被称为运行时异常是很清楚的，而为什么它们被称为非受检的异常将在下一段中变得很清楚。

祖先中没有`java.lang.RuntimeException`的称为**检查异常**。这样命名的原因是编译器确保（检查）这些异常被捕获或列在方法的`throws`子句中（参见“`throws`语句”部分）。这种设计迫使程序员做出有意识的决定，要么捕获受检的异常，要么通知方法的客户端该异常可能由方法引发，并且必须由客户端处理（处理）。以下是一些受检异常的示例：

*   `ClassNotFoundException`：当尝试用`Class`类的`forName()`方法加载使用其字符串名称的类失败时抛出
*   `CloneNotSupportedException`：当代码试图克隆未实现`Cloneable`接口的对象时抛出
*   `NoSuchMethodException`：代码没有调用方法时抛出

并非所有的异常都存在于`java.lang`包中。许多其他包包含与包支持的功能相关的异常。例如，`java.util.MissingResourceException`运行时异常和`java.io.IOException`检查异常。

尽管不是被迫的，程序员也经常捕捉运行时（非受检的）异常，以便更好地控制程序流，使应用的行为更稳定和可预测。顺便说一下，所有的错误都是运行时（非受检的）异常，但是，正如我们已经说过的，通常不可能以编程方式处理它们，因此捕捉`java.lang.Error`类的后代是没有意义的。

# `try`，`catch`，`finally`块

当在`try`块中抛出异常时，它将控制流重定向到第一个`catch`子句。如果没有可以捕获异常的`catch`块（但是`finally`块必须就位），异常会一直向上传播并从方法中传播出去。如果有多个`catch`子句，编译器会强制您排列它们，以便子异常列在父异常之前。让我们看看下面的例子：

```java
void someMethod(String s){
    try {
       method(s);
    } catch (NullPointerException ex){
       //do something
    } catch (Exception ex){
       //do something else
    }
}
```

在上例中，由于`NullPointerException`扩展`RuntimeException`，而`RuntimeException`又扩展`Exception`，所以将具有`NullPointerException`的`catch`块放置在具有`Exception`的块之前。我们甚至可以实现以下示例：

```java
void someMethod(String s){
    try {
        method(s);
    } catch (NullPointerException ex){
        //do something
    } catch (RuntimeException ex){
        //do something else
    } catch (Exception ex){
        //do something different
    }
}
```

第一个`catch`子句只包含`NullPointerException`。其他扩展了`RuntimeException`的异常将被第二个`catch`子句捕获。其余的异常类型（所有选中的异常）将被最后一个`catch`块捕获。请注意，这些`catch`子句中的任何一个都不会捕捉到错误。为了捕获它们，应该为`Error`（在任何位置）或`Throwable`（在上一个示例中的最后一个`catch`子句之后）添加`catch`子句，但是程序员通常不会这样做，并且允许错误一直传播到 JVM 中。

每个异常类型都有一个`catch`块，这允许我们提供一个特定于异常类型的处理。但是，如果在异常处理中没有差异，则可以只使用一个具有`Exception`基类的`catch`块来捕获所有类型的异常：

```java
void someMethod(String s){
    try {
        method(s);
    } catch (Exception ex){
        //do something
    }
}
```

如果没有一个子句捕捉到异常，则会进一步抛出异常，直到它被某个方法调用者中的`try...catch`语句处理，或者传播到应用代码之外。在这种情况下，JVM 终止应用并退出。

添加一个`finally`块不会改变所描述的行为。如果存在，不管是否生成了异常，它总是被执行。`finally`块通常用于释放资源：关闭数据库连接、文件等。但是，如果资源实现了`Closeable`接口，那么最好使用资源尝试语句，该语句允许自动释放资源。下面是如何使用 Java7 实现的：

```java
try (Connection conn = DriverManager.getConnection("dburl", 
                                         "username", "password");
     ResultSet rs = conn.createStatement()
                        .executeQuery("select * from some_table")) {
    while (rs.next()) {
        //process the retrieved data
    }
} catch (SQLException ex) {
    //Do something
    //The exception was probably caused by incorrect SQL statement
}
```

本例创建数据库连接，检索数据并对其进行处理，然后关闭（调用`close()`方法）`conn`和`rs`对象。

Java9 增强了资源尝试语句功能，允许创建表示`try`块外资源的对象，然后在资源尝试语句中使用这些对象，如下所示：

```java
void method(Connection conn, ResultSet rs) {
    try (conn; rs) {
        while (rs.next()) {
            //process the retrieved data
        }
    } catch (SQLException ex) {
        //Do something
        //The exception was probably caused by incorrect SQL statement
    }
}
```

前面的代码看起来更简洁，尽管在实践中，程序员更喜欢在同一上下文中创建和释放（关闭）资源。如果这也是您的偏好，请考虑将`throws`语句与资源尝试语句结合使用。

# `throws`语句

前面使用资源尝试语句的示例可以使用在相同上下文中创建的资源对象重新编写，如下所示：

```java
Connection conn;
ResultSet rs;
try {
    conn = DriverManager.getConnection("dburl", "username", "password");
    rs = conn.createStatement().executeQuery("select * from some_table");
} catch (SQLException e) {
    e.printStackTrace();
    return;
}

try (conn; rs) {
    while (rs.next()) {
        //process the retrieved data
    }
} catch (SQLException ex) {
    //Do something
    //The exception was probably caused by incorrect SQL statement
}
```

我们必须处理`SQLException`，因为它是一个受检异常，`getConnection()`、`createStatement()`、`executeQuery()`和`next()`方法在它们的`throws`子句中声明它，下面是一个例子：

```java
Statement createStatement() throws SQLException;
```

这意味着该方法的作者警告该方法的用户它可能抛出这样一个异常，并强制他们要么捕获异常，要么在方法的`throws`子句中声明异常。在前面的例子中，我们选择捕捉它，并且必须使用两个`try...catch`语句。或者，我们也可以在`throws`子句中列出异常，从而有效地将异常处理的负担推给我们方法的用户，从而消除混乱：

```java
void throwsDemo() throws SQLException {
    Connection conn = DriverManager.getConnection("url","user","pass");
    ResultSet rs = conn.createStatement().executeQuery("select * ...");
    try (conn; rs) {
        while (rs.next()) {
            //process the retrieved data
        }
    } finally { }
}
```

我们去掉了`catch`子句，但是 Java 语法要求`catch`或`finally`块必须跟在`try`块后面，所以我们添加了一个空的`finally`块

`throws`条款允许但不要求我们列出非受检异常的情况。添加非受检的异常不会强制方法的用户处理它们。

最后，如果方法抛出几个不同的异常，可以列出基本的`Exception`异常类，而不是列出所有异常。这将使编译器感到高兴，但这并不是一个好的实践，因为它隐藏了方法用户可能期望的特定异常的细节。

请注意，编译器不会检查方法体中的代码可以引发何种异常。因此，可以在`throws`子句中列出任何异常，这可能会导致不必要的开销。如果程序员错误地在`throws`子句中包含一个受检异常，而该异常从未被方法实际抛出，那么该方法的用户可能会为它编写一个从未执行过的`catch`块

# `throw`语句

`throw`语句允许抛出程序员认为必要的任何异常。人们甚至可以创建自己的异常。要创建选中的异常，请扩展`java.lang.Exception`类：

```java
class MyCheckedException extends Exception{
    public MyCheckedException(String message){
        super(message);
    }
    //add code you need to have here
}
```

另外，要创建非受检的异常，请扩展`java.lang.RunitmeException`类，如下所示：

```java
class MyUncheckedException extends RuntimeException{
    public MyUncheckedException(String message){
        super(message);
    }
    //add code you need to have here
}
```

注意注释*这里需要添加代码*。您可以像向任何其他常规类一样向自定义异常添加方法和属性，但程序员很少这样做。最佳实践甚至明确建议避免使用异常来驱动业务逻辑。异常应该是顾名思义，只包括异常的，非常罕见的情况。

但是，如果您需要宣布异常情况，请使用`throw`关键字和`new`运算符来创建并触发异常对象的传播。以下是几个例子：

```java
throw new Exception("Something happend"); 
throw new RunitmeException("Something happened");
throw new MyCheckedException("Something happened");
throw new MyUncheckedException("Something happened");
```

甚至可以按如下方式抛出`null`：

```java
throw null;
```

上述语句的结果与此语句的结果相同：

```java
throw new NullPointerException;
```

在这两种情况下，非受检的`NullPointerException`的对象开始在系统中传播，直到它被应用或 JVM 捕获。

# `assert`语句

有时，程序员需要知道代码中是否发生了特定的情况，即使应用已经部署到生产环境中。同时，没有必要一直运行检查。这就是分支`assert`语句派上用场的地方。举个例子：

```java
public someMethod(String s){
    //any code goes here
    assert(assertSomething(x, y, z));
    //any code goes here
}

boolean assertSomething(int x, String y, double z){
 //do something and return boolean
}
```

在前面的代码中，`assert()`方法从`assertSomething()`方法获取输入，如果`assertSomething()`方法返回`false`，程序停止执行。

只有当 JVM 使用`-ea`选项运行时，`assert()`方法才会执行。`-ea`标志不应该在生产中使用，除非可能暂时用于测试目的，因为它会产生影响应用性能的开销。

# 异常处理的最佳实践

当应用可以自动执行某些操作来修改或解决问题时，选中的异常被设计为用于可恢复条件。实际上，这种情况并不经常发生。通常，当捕捉到异常时，应用会记录栈跟踪并中止当前操作。根据记录的信息，应用支持团队修改代码以解决未知情况或防止将来发生这种情况

每个应用都是不同的，因此最佳实践取决于特定的应用需求、设计和上下文。一般来说，在开发社区中似乎有一个协议，即避免使用检查过的异常，并尽量减少它们在应用代码中的传播。以下是其他一些被证明是有用的建议：

*   始终捕获靠近源的所有受检异常
*   如果有疑问，也可以在源代码附近捕获非受检的异常
*   尽可能靠近源处理异常，因为它是上下文最具体的地方，也是根本原因所在的地方
*   除非必须，否则不要抛出选中的异常，因为您强制为可能永远不会发生的情况生成额外代码
*   如果有必要，将第三方的受检异常转换为非受检的异常，方法是将它们作为`RuntimeException`重新抛出，并显示相应的消息
*   除非必须，否则不要创建自定义异常
*   除非必须，否则不要使用异常处理机制来驱动业务逻辑
*   通过使用消息系统和可选的枚举类型（而不是使用异常类型）来定制泛型`RuntimeException`，以传达错误的原因

# 总结

本章向读者介绍了 Java 异常处理框架，了解了两种异常：受检和非受检（运行时），以及如何使用`try-catch-finally`和`throws`语句处理它们。读者还学习了如何生成（抛出）异常以及如何创建自己的（自定义）异常。本章最后介绍了异常处理的最佳实践。

在下一章中，我们将详细讨论字符串及其处理，以及输入/输出流和文件读写技术。

# 测验

1.  什么是栈跟踪？选择所有适用项：

    1.  当前加载的类的列表
    2.  当前正在执行的方法的列表
    3.  当前正在执行的代码行的列表
    4.  当前使用的变量列表

2.  有哪些异常？选择所有适用的选项：
    1.  编译异常
    2.  运行时异常
    3.  读取异常
    4.  写入异常

3.  以下代码的输出是什么？

```java
try {
    throw null;
} catch (RuntimeException ex) {
    System.out.print("RuntimeException ");
} catch (Exception ex) {
    System.out.print("Exception ");
} catch (Error ex) {
    System.out.print("Error ");
} catch (Throwable ex) {
    System.out.print("Throwable ");
} finally {
    System.out.println("Finally ");
}
```

4.  下列哪种方法编译时不会出错？

```java
void method1() throws Exception { throw null; }
void method2() throws RuntimeException { throw null; }
void method3() throws Throwable { throw null; }
void method4() throws Error { throw null; }
```

5.  下列哪个语句编译时不会出错？

```java
throw new NullPointerException("Hi there!"); //1
throws new Exception("Hi there!");          //2
throw RuntimeException("Hi there!");       //3
throws RuntimeException("Hi there!");     //4
```

6.  假设`int x = 4`，下列哪条语句编译时不会出错？

```java
assert (x > 3); //1
assert (x = 3); //2
assert (x < 4); //3
assert (x = 4); //4
```

7.  以下列表中的最佳实践是什么？
    1.  始终捕获所有异常和错误
    2.  总是捕获所有异常
    3.  从不抛出非受检的异常
    4.  除非必须，否则不要抛出受检的异常

# 五、字符串、输入/输出和文件

在本章中，读者将更详细地了解`String`类方法。我们还将讨论标准库和 ApacheCommons 项目中流行的字符串工具。下面将概述 Java 输入/输出流和`java.io`包的相关类，以及`org.apache.commons.io`包的一些类。文件管理类及其方法在专用部分中进行了描述。

本章将讨论以下主题：

*   字符串处理
*   I/O 流
*   文件管理
*   Apache Commons 工具`FileUtils`和`IOUtils`

# 字符串处理

在主流编程中，`String`可能是最流行的类。在[第一章](01.html)“Java12 入门”中，我们了解了这个类，它的文本和它的特殊特性**字符串不变性**。在本节中，我们将解释如何使用标准库中的`String`类方法和工具类处理字符串，特别是使用`org.apache.commons.lang3`包中的`StringUtils`类。

# 字符串类的方法

`String`类有 70 多个方法，可以分析、修改、比较字符串，并将数字文本转换为相应的字符串文本。要查看`String`类的所有方法，请参考[在线 Java API](https://docs.oracle.com/en/java/javase)。

# 字符串分析

`length()`方法返回字符串中的字符数，如下代码所示：

```java
String s7 = "42";
System.out.println(s7.length());    //prints: 2
System.out.println("0 0".length()); //prints: 3

```

当字符串长度（字符数）为`0`时，下面的`isEmpty()`方法返回`true`：

```java
System.out.println("".isEmpty());   //prints: true
System.out.println(" ".isEmpty());  //prints: false

```

`indexOf()`和`lastIndexOf()`方法返回指定子字符串在该代码段所示字符串中的位置：

```java
String s6 = "abc42t%";
System.out.println(s6.indexOf(s7));            //prints: 3
System.out.println(s6.indexOf("a"));           //prints: 0
System.out.println(s6.indexOf("xyz"));         //prints: -1
System.out.println("ababa".lastIndexOf("ba")); //prints: 3
```

如您所见，字符串中的第一个字符有一个位置（索引）`0`，缺少指定的子字符串将导致索引`-1`。

`matches()`方法将正则表达式（作为参数传递）应用于字符串，如下所示：

```java
System.out.println("abc".matches("[a-z]+"));   //prints: true
System.out.println("ab1".matches("[a-z]+"));   //prints: false

```

正则表达式超出了本书的范围。你可以在[这个页面](https://www.regular-expressions.info)了解它们。在上例中，表达式`[a-z]+`只匹配一个或多个字母。

# 字符串比较

在第 3 章、“Java 基础”中，我们已经讨论过只有当两个`String`对象或文字拼写完全相同时才返回`true`的`equals()`方法。以下代码段演示了它的工作原理：

```java
String s1 = "abc";
String s2 = "abc";
String s3 = "acb";
System.out.println(s1.equals(s2));     //prints: true
System.out.println(s1.equals(s3));     //prints: false
System.out.println("abc".equals(s2));  //prints: true
System.out.println("abc".equals(s3));  //prints: false

```

另一个`String`类`equalsIgnoreCase()`方法做了类似的工作，但忽略了字符大小写的区别，如下所示：

```java
String s4 = "aBc";
String s5 = "Abc";
System.out.println(s4.equals(s5));           //prints: false
System.out.println(s4.equalsIgnoreCase(s5)); //prints: true

```

`contentEquals()`方法的作用类似于此处所示的`equals()`方法：

```java
String s1 = "abc";
String s2 = "abc";
System.out.println(s1.contentEquals(s2));    //prints: true
System.out.println("abc".contentEquals(s2)); //prints: true 
```

区别在于`equals()`方法检查两个值是否都用`String`类
表示，而`contentEquals()`只比较字符序列的字符（内容），字符序列可以用`String`、`StringBuilder`、`StringBuffer`、`CharBuffer`表示，或者实现`CharSequence`接口的任何其他类。然而，如果两个序列包含相同的字符，`contentEquals()`方法将返回`true`，而如果其中一个序列不是由`String`类创建的，`equals()`方法将返回`false`。

如果`string`包含某个子串，`contains()`方法返回`true`，如下所示：

```java
String s6 = "abc42t%";
String s7 = "42";
String s8 = "xyz";
System.out.println(s6.contains(s7));    //prints: true
System.out.println(s6.contains(s8));    //prints: false

```

`startsWith()`和`endsWith()`方法执行类似的检查，但仅在字符串的开头或字符串值的结尾执行，如以下代码所示：

```java
String s6 = "abc42t%";
String s7 = "42";

System.out.println(s6.startsWith(s7));      //prints: false
System.out.println(s6.startsWith("ab"));    //prints: true
System.out.println(s6.startsWith("42", 3)); //prints: true

System.out.println(s6.endsWith(s7));        //prints: false
System.out.println(s6.endsWith("t%"));      //prints: true
```

`compareTo()`和`compareToIgnoreCase()`方法根据字符串中每个字符的 Unicode 值按字典顺序比较字符串。如果字符串相等，则返回值`0`；如果第一个字符串按字典顺序小于第二个字符串（Unicode 值较小），则返回负整数值；如果第一个字符串按字典顺序大于第二个字符串（Unicode 值较大），则返回正整数值。例如：

```java
String s4 = "aBc";
String s5 = "Abc";
System.out.println(s4.compareTo(s5));             //prints: 32
System.out.println(s4.compareToIgnoreCase(s5));   //prints: 0
System.out.println(s4.codePointAt(0));            //prints: 97
System.out.println(s5.codePointAt(0));            //prints: 65

```

从这个代码片段中，您可以看到，`compareTo()`和`compareToIgnoreCase()`方法基于组成字符串的字符的代码点。字符串`s4`比字符串`s5`大`32`的原因是因为字符`a`（`97`的码点比字符`A`（`65`的码点大`32`

示例还显示，`codePointAt()`方法返回字符串中指定位置的字符的码位。代码点在第 1 章“Java12 入门”的“整数类型”部分进行了描述。

# 字符串变换

`substring()`方法返回从指定位置（索引）开始的子字符串，如下所示：

```java
System.out.println("42".substring(0));   //prints: 42
System.out.println("42".substring(1));   //prints: 2
System.out.println("42".substring(2));   //prints:
System.out.println("42".substring(3));   //error: index out of range: -1
String s6 = "abc42t%";
System.out.println(s6.substring(3));     //prints: 42t%
System.out.println(s6.substring(3, 5));  //prints: 42
```

`format()`方法使用传入的第一个参数作为模板，并在模板的相应位置依次插入其他参数！请给我两个苹果！“三次：

```java
String t = "Hey, %s! Give me %d apples, please!";
System.out.println(String.format(t, "Nick", 2));

String t1 = String.format(t, "Nick", 2);
System.out.println(t1);

System.out.println(String
          .format("Hey, %s! Give me %d apples, please!", "Nick", 2));

```

`%s`和`%d`符号称为**格式说明符**。有许多说明符和各种标志，允许程序员精确控制结果。您可以在`java.util.Formatter`类的 API 中了解它们。

`concat()`方法的工作方式与算术运算符（`+`相同，如图所示：

```java
String s7 = "42";
String s8 = "xyz";
String newStr1 = s7.concat(s8);
System.out.println(newStr1);    //prints: 42xyz

String newStr2 = s7 + s8;
System.out.println(newStr2);    //prints: 42xyz
```

以下`join()`方法的作用类似，但允许添加分隔符：

```java
String newStr1 = String.join(",", "abc", "xyz");
System.out.println(newStr1);        //prints: abc,xyz

List<String> list = List.of("abc","xyz");
String newStr2 = String.join(",", list);
System.out.println(newStr2);        //prints: abc,xyz

```

以下一组`replace()`、`replaceFirst()`和`replaceAll()`方法用提供的字符替换字符串中的某些字符：

```java
System.out.println("abcbc".replace("bc", "42"));         //prints: a4242
System.out.println("abcbc".replaceFirst("bc", "42"));    //prints: a42bc
System.out.println("ab11bcd".replaceAll("[a-z]+", "42"));//prints: 421142

```

前面代码的第一行用`"42"`替换`"bc"`的所有实例。第二个实例仅将`"bc"`的第一个实例替换为`"42"`。最后一个将匹配所提供正则表达式的所有子字符串替换为`"42"`。

`toLowerCase()`和`toUpperCase()`方法改变整个字符串的大小写，如下所示：

```java
System.out.println("aBc".toLowerCase());   //prints: abc
System.out.println("aBc".toUpperCase());   //prints: ABC

```

`split()`方法将字符串分成子字符串，使用提供的字符作为分隔符，如下所示：

```java
String[] arr = "abcbc".split("b");
System.out.println(arr[0]);   //prints: a
System.out.println(arr[1]);   //prints: c
System.out.println(arr[2]);   //prints: c
```

有几种`valueOf()`方法可以将原始类型的值转换为`String`类型。例如：

```java
float f = 23.42f;
String sf = String.valueOf(f);
System.out.println(sf);         //prints: 23.42

```

也有`()`和`getChars()`方法将字符串转换为相应类型的数组，而`chars()`方法创建一个`IntStream`字符（它们的代码点）。我们将在第 14 章、“Java 标准流”中讨论流。

# 使用 Java11 添加的方法

Java11 在`String`类中引入了几个新方法。

`repeat()`方法允许您基于同一字符串的多个连接创建新的字符串值，如下代码所示：

```java
System.out.println("ab".repeat(3)); //prints: ababab
System.out.println("ab".repeat(1)); //prints: ab
System.out.println("ab".repeat(0)); //prints:

```

如果字符串长度为`0`或只包含空格，`isBlank()`方法返回`true`。例如：

```java
System.out.println("".isBlank());     //prints: true
System.out.println("   ".isBlank());  //prints: true
System.out.println(" a ".isBlank());  //prints: false

```

`stripLeading()`方法从字符串中删除前导空格，`stripTrailing()`方法删除尾部空格，`strip()`方法同时删除这两个空格，如下所示：

```java
String sp = "   abc   ";
System.out.println("'" + sp + "'");                 //prints: '   abc   '
System.out.println("'" + sp.stripLeading() + "'");  //prints: 'abc   '
System.out.println("'" + sp.stripTrailing() + "'"); //prints: '  abc'
System.out.println("'" + sp.strip() + "'");         //prints: 'abc'

```

最后，`lines()`方法通过行终止符来中断字符串并返回结果行的`Stream<String>`，行终止符是转义序列换行符`\n`（`\u000a`），或回车符`\r`（`\u000d`），或回车符紧跟换行符`\r\n`（`\u000d\u000a`）。例如：

```java
String line = "Line 1\nLine 2\rLine 3\r\nLine 4";
line.lines().forEach(System.out::println); 
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/0c968570-7ace-4243-87b1-bdaaecf16775.png)

我们将在第 14 章、“Java 标准流”中讨论流。

# 字符串工具

除了`String`类之外，还有许多其他类具有处理`String`值的方法。其中最有用的是来自一个名为 **Apache Commons** 的项目的`org.apache.commons.lang3`包的`StringUtils`类，该项目由名为 **Apache Software Foundation** 的开源程序员社区维护。我们将在第 7 章、“Java 标准和外部库”中详细介绍这个项目及其库。要在项目中使用它，请在`pom.xml`文件中添加以下依赖项：

```java
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-lang3</artifactId>
    <version>3.8.1</version>
</dependency>
```

`StringUtils`类是许多程序员的最爱。它通过提供以下空安全操作来补充`String`类的方法：

*   `isBlank(CharSequence cs)`：如果输入值为空格、空（`""`或`null`，则返回`true`
*   `isNotBlank(CharSequence cs)`：前面方法返回`true`时返回`false`
*   `isEmpty(CharSequence cs)`：如果输入值为空（`""`或`null`，则返回`true`
*   `isNotEmpty(CharSequence cs)`：前面方法返回`true`时返回`false`
*   `trim(String str)`：从输入值中删除前导和尾随空格，并按如下方式处理`null`、空（`""`）和空格：

```java
System.out.println("'" + StringUtils.trim(" x ") + "'"); //prints: 'x'
System.out.println(StringUtils.trim(null));              //prints: null
System.out.println("'" + StringUtils.trim("") + "'");    //prints: ''
System.out.println("'" + StringUtils.trim("   ") + "'"); //prints: ''

```

*   `trimToNull(String str)`：从输入值中删除前导和尾随空格，并按如下方式处理`null`、空（`""`）和空格：

```java
System.out.println("'" + StringUtils.trimToNull(" x ") + "'");  // 'x'
System.out.println(StringUtils.trimToNull(null));        //prints: null
System.out.println(StringUtils.trimToNull(""));          //prints: null
System.out.println(StringUtils.trimToNull("   "));       //prints: null
```

*   `trimToEmpty(String str)`：从输入值中删除前导和尾随空格，并按如下方式处理`null`、空（`""`）和空格：

```java
System.out.println("'" + StringUtils.trimToEmpty(" x ") + "'");   // 'x'
System.out.println("'" + StringUtils.trimToEmpty(null) + "'");    // ''
System.out.println("'" + StringUtils.trimToEmpty("") + "'");      // ''
System.out.println("'" + StringUtils.trimToEmpty("   ") + "'");   // ''
```

*   `strip(String str)`、`stripToNull(String str)`、`stripToEmpty(String str)`：产生与前面`trim*(String str)`方法相同的结果，但使用更广泛的空格定义（基于`Character.isWhitespace(int codepoint)`），从而删除与`trim*(String str)`相同的字符，等等

*   `strip(String str, String stripChars)`、`stripAccents(String input)`、`stripAll(String... strs)`、`stripAll(String[] strs, String stripChars)`、`stripEnd(String str, String stripChars)`、`stripStart(String str, String stripChars)`：从`String`或`String[]`数组元素的特定部分删除特定字符
*   `startsWith(CharSequence str, CharSequence prefix)`、`startsWithAny(CharSequence string, CharSequence... searchStrings)`、`startsWithIgnoreCase(CharSequence str, CharSequence prefix)`以及类似的`endsWith*()`方法：检查`String`值是否以某个前缀（或后缀）开始（或结束）
*   `indexOf`、`lastIndexOf`、`contains`：以空安全的方式检查索引
*   `indexOfAny`、`lastIndexOfAny`、`indexOfAnyBut`、`lastIndexOfAnyBut`：收益指标
*   `containsOnly`、`containsNone`、`containsAny`：检查值是否包含特定字符
*   `substring`、`left`、`right`、`mid`：空安全返回子串
*   `substringBefore`、`substringAfter`、`substringBetween`：从相对位置返回子串
*   `split`、`join`：拆分或合并一个值（对应）
*   `remove`、`delete`：消除子串
*   `replace`、`overlay`：替换一个值
*   `chomp`、`chop`：移除末尾的换行符
*   `appendIfMissing`：如果不存在，则添加一个值
*   `prependIfMissing`：如果不存在，则在`String`值的开头加前缀
*   `leftPad`、`rightPad`、`center`、`repeat`：添加填充
*   `upperCase`、`lowerCase`、`swapCase`、`capitalize`、`uncapitalize`：变更案例

*   `countMatches`：返回子串出现的次数
*   `isWhitespace`、`isAsciiPrintable`、`isNumeric`、`isNumericSpace`、`isAlpha`、`isAlphaNumeric`、`isAlphaSpace`、`isAlphaNumericSpace`：检查是否存在某种类型的字符
*   `isAllLowerCase`、`isAllUpperCase`：检查案例
*   `defaultString`、`defaultIfBlank`、`defaultIfEmpty`：若`null`返回默认值
*   `rotate`：使用循环移位旋转字符
*   `reverse`、`reverseDelimited`：倒排字符或分隔字符组
*   `abbreviate`、`abbreviateMiddle`：使用省略号或其他值的缩写值
*   `difference`：返回值的差异
*   `getLevenshteinDistance`：返回将一个值转换为另一个值所需的更改数

如您所见，`StringUtils`类有一组非常丰富的方法（我们没有列出所有的方法）用于字符串分析、比较和转换，这些方法是对`String`类方法的补充。

# I/O 流

任何软件系统都必须接收和生成某种数据，这些数据可以组织为一组独立的输入/输出或数据流。流可以是有限的，也可以是无穷无尽的。一个程序可以从一个流中读取（然后称为一个**输入流**），或者写入一个流（然后称为一个**输出流**）。java I/O 流要么基于字节，要么基于字符，这意味着它的数据要么被解释为原始字节，要么被解释为字符。

`java.io`包包含支持许多（但不是所有）可能数据源的类。它主要围绕文件、网络流和内部内存缓冲区的输入来构建。它不包含许多网络通信所必需的类。它们属于 Java 网络 API 的`java.net`、`javax.net`等包。只有在建立了网络源或目的地（例如网络套接字）之后，程序才能使用`java.io`包的`InputStream`和`OutputStream`类读写数据

`java.nio`包的类与`java.io`包的类具有几乎相同的功能。但是，除此之外，它们还可以在非阻塞的模式下工作，这可以在某些情况下显著提高性能。我们将在第 15 章“反应式编程”中讨论非阻塞处理。

# 流数据

一个程序所能理解的数据必须是二进制的，基本上用 0 和 1 表示。数据可以一次读或写一个字节，也可以一次读或写几个字节的数组。这些字节可以保持二进制，也可以解释为字符。

在第一种情况下，它们可以被`InputStream`和`OutputStream`类的后代读取为字节或字节数组。例如（如果类属于`java.io`包，则省略包名）：`ByteArrayInputStream`、`ByteArrayOutputStream`、`FileInputStream`、`FileOutputStream`、`ObjectInputStream`、`ObjectOutputStream`、`javax.sound.sampled.AudioInputStream`、`org.omg.CORBA.portable.OutputStream`；使用哪一个取决于数据的来源或目的地。`InputStream`和`OutputStream`类本身是抽象的，不能实例化。

在第二种情况下，可以解释为字符的数据称为**文本数据**，在`Reader`和`Writer`的基础上还有面向字符的读写类，它们也是抽象类。它们的子类的例子有：`CharArrayReader`、`CharArrayWriter`、`InputStreamReader`、`OutputStreamWriter`、`PipedReader`、`PipedWriter`、`StringReader`和`StringWriter`。

你可能已经注意到了，我们把这些类成对地列了出来。但并非每个输入类都有匹配的输出特化。例如，有`PrintStream`和`PrintWriter`类支持输出到打印设备，但没有相应的输入伙伴，至少没有名称。然而，有一个`java.util.Scanner`类以已知格式解析输入文本

还有一组配备了缓冲区的类，它们通过一次读取或写入更大的数据块来帮助提高性能，特别是在访问源或目标需要很长时间的情况下。

在本节的其余部分，我们将回顾`java.io`包的类以及其他包中一些流行的相关类。

# `InputStream`类及其子类

在 Java 类库中，`InputStream`抽象类有以下直接实现：`ByteArrayInputStream`、`FileInputStream`、`ObjectInputStream`、`PipedInputStream`、`SequenceInputStream`、`FilterInputStream`、`javax.sound.sampled.AudioInputStream`

它们要么按原样使用，要么覆盖`InputStream`类的以下方法：

*   `int available()`：返回可读取的字节数
*   `void close()`：关闭流并释放资源
*   `void mark(int readlimit)`：标记流中的一个位置，定义可以读取的字节数
*   `boolean markSupported()`：支持打标返回`true`
*   `static InputStream nullInputStream()`：创建空流
*   `abstract int read()`：读取流中的下一个字节
*   `int read(byte[] b)`：将流中的数据读入`b`缓冲区
*   `int read(byte[] b, int off, int len)`：从流中读取`len`或更少字节到`b`缓冲区
*   `byte[] readAllBytes()`：读取流中所有剩余的字节
*   `int readNBytes(byte[] b, int off, int len)`：在`off`偏移量处将`len`或更少字节读入`b`缓冲区
*   `byte[] readNBytes(int len)`：将`len`或更少的字节读入`b`缓冲区
*   `void reset()`：将读取位置重置为上次调用`mark()`方法的位置
*   `long skip(long n)`：跳过流的`n`或更少字节；返回实际跳过的字节数
*   `long transferTo(OutputStream out)`：从输入流读取数据，逐字节写入提供的输出流；返回实际传输的字节数

`abstract int read()`是唯一必须实现的方法，但是这个类的大多数后代也覆盖了许多其他方法。

# 字节数组输入流

`ByteArrayInputStream`类允许读取字节数组作为输入流。它有以下两个构造器，用于创建类的对象并定义用于读取字节输入流的缓冲区：

*   `ByteArrayInputStream(byte[] buffer)`
*   `ByteArrayInputStream(byte[] buffer, int offset, int length)`

第二个构造器除了允许设置缓冲区外，还允许设置缓冲区的偏移量和长度。让我们看看这个例子，看看如何使用这个类。我们假设有一个`byte[]`数组的数据源：

```java
byte[] bytesSource(){
    return new byte[]{42, 43, 44};
}
```

然后我们可以写下：

```java
byte[] buffer = bytesSource();
try(ByteArrayInputStream bais = new ByteArrayInputStream(buffer)){
    int data = bais.read();
    while(data != -1) {
        System.out.print(data + " ");   //prints: 42 43 44
        data = bais.read();
    }
} catch (Exception ex){
    ex.printStackTrace();
}
```

`bytesSource()`方法生成填充缓冲区的字节数组，缓冲区作为参数传递给`ByteArrayInputStream`类的构造器。然后使用`read()`方法逐字节读取得到的流，直到到达流的末尾为止（并且`read()`方法返回`-1`。每个新字节都会被打印出来（不带换行符，后面有空格，所以所有读取的字节都显示在一行中，用空格隔开）

前面的代码通常以更简洁的形式表示，如下所示：

```java
byte[] buffer = bytesSource();
try(ByteArrayInputStream bais = new ByteArrayInputStream(buffer)){
    int data;
    while ((data = bais.read()) != -1) {
        System.out.print(data + " ");   //prints: 42 43 44
    }
} catch (Exception ex){
    ex.printStackTrace();
}
```

不只是打印字节，它们可以以任何其他必要的方式进行处理，包括将它们解释为字符。例如：

```java
byte[] buffer = bytesSource();
try(ByteArrayInputStream bais = new ByteArrayInputStream(buffer)){
    int data;
    while ((data = bais.read()) != -1) {
        System.out.print(((char)data) + " ");   //prints: * + ,
    }
} catch (Exception ex){
    ex.printStackTrace();
}
```

但在这种情况下，最好使用专门用于字符处理的`Reader`类之一。我们将在“读取器类和写入器及其子类”部分讨论它们。

# 文件输入流

`FileInputStream`类从文件系统中的文件获取数据，例如图像的原始字节。它有以下三个构造器：

*   `FileInputStream(File file)`
*   `FileInputStream(String name)`
*   `FileInputStream(FileDescriptor fdObj)`

每个构造器打开指定为参数的文件。第一个构造器接受`File`对象，第二个是文件系统中文件的路径，第三个是表示文件系统中实际文件的现有连接的文件描述符对象。让我们看看下面的例子：

```java
String filePath = "src/main/resources/hello.txt";
try(FileInputStream fis=new FileInputStream(filePath)){
    int data;
    while ((data = fis.read()) != -1) {
        System.out.print(((char)data) + " ");   //prints: H e l l o !
    }
} catch (Exception ex){
    ex.printStackTrace();
}
```

在`src/main/resources`文件夹中，我们创建了只有一行的`hello.txt`文件—`Hello!`。上述示例的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1b619c0b-eec8-4bf9-acaf-422301cf45d1.png)

因为我们在 IDE 中运行这个示例，所以它在项目根目录中执行。为了找到代码的执行位置，您可以这样打印：

```java
File f = new File(".");                //points to the current directory
System.out.println(f.getAbsolutePath()); //prints the directory path
```

在从`hello.txt`文件读取字节之后，出于演示目的，我们决定将每个`byte`转换为`char`，因此您可以看到我们的代码确实从指定的文件读取，但是对于文本文件处理，`FileReader`类是一个更好的选择（我们将很快讨论）。如果没有演员阵容，结果将是：

```java
System.out.print((data) + " ");   //prints: 72 101 108 108 111 33
```

顺便说一下，因为`src/main/resources`文件夹是由 IDE（使用 Maven）放置在类路径上的，所以放置在其中的文件也可以通过类加载器访问，该类加载器使用自己的`InputStream`实现创建流：

```java
try(InputStream is = InputOutputStream.class.getResourceAsStream("/hello.txt")){
    int data;
    while ((data = is.read()) != -1) {
        System.out.print((data) + " ");   //prints: 72 101 108 108 111 33
    }
} catch (Exception ex){
    ex.printStackTrace();
}
```

上例中的`InputOutputStream`类不是某个库中的类。它只是我们用来运行示例的主类。`InputOutputStream.class.getResourceAsStream()`构造允许使用加载了`InputOutputStream`类的类加载器来查找类路径上的文件并创建包含其内容的流。在“文件管理”部分，我们也将介绍其他读取文件的方法。

# 对象输入流

`ObjectInputStream`类的方法集比任何其他`InputStream`实现的方法集大得多。原因是它是围绕读取对象字段的值构建的，对象字段可以是各种类型的。为了使`ObjectInputStream`能够从输入的数据流构造一个对象，该对象必须是*可反序列化的*，这意味着它首先必须是*可序列化的*，可以转换成字节流。通常，这样做是为了通过网络传输对象。在目标位置，序列化对象被反序列化，原始对象的值被还原。

基本类型和大多数 Java 类，包括`String`类和基本类型包装器，都是可序列化的。如果类具有自定义类型的字段，则必须通过实现`java.io.Serizalizable`使其可序列化。怎么做不在这本书的范围之内。现在，我们只使用可序列化类型。我们来看看这个类：

```java
class SomeClass implements Serializable {
    private int field1 = 42;
    private String field2 = "abc";
}
```

我们必须告诉编译器它是可序列化的。否则，编译将失败。这样做是为了确保在声明类是可序列化的之前，程序员检查了所有字段并确保它们是可序列化的，或者已经实现了序列化所需的方法

在创建输入流并使用`ObjectInputStream`进行反序列化之前，我们需要先序列化对象。这就是为什么我们首先使用`ObjectOutputStream`和`FileOutputStream`来序列化一个对象并将其写入`someClass.bin`文件的原因，我们将在“类`OutputStream`及其子类”一节中详细讨论它们。然后我们使用`FileInputStream`读取文件，并使用`ObjectInputStream`反序列化文件内容：

```java
String fileName = "someClass.bin";
try (ObjectOutputStream objectOutputStream =
             new ObjectOutputStream(new FileOutputStream(fileName));
     ObjectInputStream objectInputStream =
              new ObjectInputStream(new FileInputStream(fileName))){
    SomeClass obj = new SomeClass();
    objectOutputStream.writeObject(obj);
    SomeClass objRead = (SomeClass) objectInputStream.readObject();
    System.out.println(objRead.field1);  //prints: 42
    System.out.println(objRead.field2);  //prints: abc
} catch (Exception ex){
    ex.printStackTrace();
}
```

请注意，在运行前面的代码之前，必须先创建文件。我们将在“创建文件和目录”一节中展示如何进行。并且，为了提醒您，我们使用了资源尝试语句，因为`InputStream`和`OutputStream`都实现了`Closeable`接口

# 管道输入流

管道输入流具有非常特殊的特化；它被用作线程之间通信的机制之一。一个线程从`PipedInputStream`对象读取数据，并将数据传递给另一个线程，该线程将数据写入`PipedOutputStream`对象。举个例子：

```java
PipedInputStream pis = new PipedInputStream();
PipedOutputStream pos = new PipedOutputStream(pis);

```

或者，当一个线程从`PipedOutputStream`对象读取数据，而另一个线程向`PipedInputStream`对象写入数据时，数据可以反向移动，如下所示：

```java
PipedOutputStream pos = new PipedOutputStream();
PipedInputStream pis = new PipedInputStream(pos);

```

在这方面工作的人都熟悉消息，“*断管**，表示提供的数据管道流已经停止工作。*

 *管道流也可以在没有任何连接的情况下创建，稍后再连接，如下所示：

```java
PipedInputStream pis = new PipedInputStream();
PipedOutputStream pos = new PipedOutputStream();
pos.connect(pis); 
```

例如，这里有两个类将由不同的线程执行。首先，`PipedOutputWorker`类如下：

```java
class PipedOutputWorker implements Runnable{
    private PipedOutputStream pos;
    public PipedOutputWorker(PipedOutputStream pos) {
        this.pos = pos;
    }
    @Override
    public void run() {
        try {
            for(int i = 1; i < 4; i++){
                pos.write(i);
            }
            pos.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```

`PipedOutputWorker`类有`run()`方法（因为它实现了`Runnable`接口），将三个数字`1`、`2`和`3`写入流中，然后关闭。现在让我们看一下`PipedInputWorker`类，如下所示：

```java
class PipedInputWorker implements Runnable{
    private PipedInputStream pis;
    public PipedInputWorker(PipedInputStream pis) {
        this.pis = pis;
    }
    @Override
    public void run() {
        try {
            int i;
            while((i = pis.read()) > -1){
                System.out.print(i + " ");  
            }
            pis.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
```

它还有`run()`方法（因为它实现了`Runnable`接口），从流中读取并打印出每个字节，直到流结束（由`-1`表示）。现在我们连接这些管道，执行这些类的`run()`方法：

```java
PipedOutputStream pos = new PipedOutputStream();
PipedInputStream pis = new PipedInputStream();
try {
    pos.connect(pis);
    new Thread(new PipedOutputWorker(pos)).start();
    new Thread(new PipedInputWorker(pis)).start(); //prints: 1 2 3
} catch (Exception ex) {
    ex.printStackTrace();
}
```

如您所见，工作器的对象被传递到了`Thread`类的构造器中。`Thread`对象的`start()`方法执行传入的`Runnable`的`run()`方法。我们看到了我们预期的结果，`PipedInputWorker`打印了`PipedOutputWorker`写入管道流的所有字节。我们将在第 8 章“多线程和并发处理”中详细介绍线程。

# 序列输入流

`SequenceInputStream`类将传入以下构造器之一的输入流作为参数连接起来：

*   `SequenceInputStream(InputStream s1, InputStream s2)`
*   `SequenceInputStream(Enumeration<InputStream> e)`

**枚举**是尖括号中所示类型的对象集合，称为`T`类型的**泛型**。`SequenceInputStream`类从第一个输入字符串读取，直到它结束，然后从第二个字符串读取，依此类推，直到最后一个流结束。例如，我们在`hello.txt`文件旁边的`resources`文件夹中创建一个`howAreYou.txt`文件（文本为`How are you?`）。`SequenceInputStream`类的用法如下：

```java
try(FileInputStream fis1 = 
                    new FileInputStream("src/main/resources/hello.txt");
    FileInputStream fis2 = 
                new FileInputStream("src/main/resources/howAreYou.txt");
    SequenceInputStream sis=new SequenceInputStream(fis1, fis2)){
    int i;
    while((i = sis.read()) > -1){
        System.out.print((char)i);       //prints: Hello!How are you?
    }
} catch (Exception ex) {
    ex.printStackTrace();
}
```

类似地，当输入流的枚举被传入时，每个流都被读取（在本例中被打印）直到结束。

# 过滤流

`FilterInputStream`类是在构造器中作为参数传递的`InputStream`对象周围的包装器。以下是`FilterInputStream`类的构造器和两个`read()`方法：

```java
protected volatile InputStream in;
protected FilterInputStream(InputStream in) { this.in = in; }
public int read() throws IOException { return in.read(); }
public int read(byte b[]) throws IOException { 
    return read(b, 0, b.length);
}

```

`InputStream`类的所有其他方法都被类似地覆盖；函数被委托给分配给`in`属性的对象。

如您所见，构造器是受保护的，这意味着只有子级可以访问它。这样的设计对客户端隐藏了流的实际来源，并迫使程序员使用`FilterInputStream`类扩展之一：`BufferedInputStream`、`CheckedInputStream`、`DataInputStream`、`PushbackInputStream`、`javax.crypto.CipherInputStream`、`java.util.zip.DeflaterInputStream`、`java.util.zip.InflaterInputStream`、`java.security.DigestInputStream`或`javax.swing.ProgressMonitorInputStream`。或者，可以创建自定义扩展。但是，在创建自己的扩展之前，请查看列出的类，看看其中是否有一个适合您的需要。下面是一个使用`BufferedInputStream`类的示例：

```java
try(FileInputStream  fis = 
        new FileInputStream("src/main/resources/hello.txt");
    FilterInputStream filter = new BufferedInputStream(fis)){
    int i;
    while((i = filter.read()) > -1){
        System.out.print((char)i);     //prints: Hello!
    }
} catch (Exception ex) {
    ex.printStackTrace();
}
```

`BufferedInputStream`类使用缓冲区来提高性能。当跳过或读取流中的字节时，内部缓冲区会自动重新填充所包含的输入流中所需的字节数。

`CheckedInputStream`类添加了所读取数据的校验和，允许使用`getChecksum()`方法验证输入数据的完整性。

`DataInputStream`类以独立于机器的方式将输入数据读取并解释为原始 Java 数据类型。

`PushbackInputStream`类增加了使用`unread()`方法倒推读取数据的功能，在代码具有分析刚刚读取的数据并决定未读取的逻辑的情况下非常有用，因此可以在下一步重新读取。

`javax.crypto.CipherInputStream`类将`Cipher`添加到`read()`方法中。如果`Cipher`初始化为解密，`javax.crypto.CipherInputStream`将在返回之前尝试解密数据。

`java.util.zip.DeflaterInputStream`类以 Deflate 压缩格式压缩数据。

类以 Deflate 压缩格式解压缩数据。

`java.security.DigestInputStream`类使用流经流的位来更新相关的消息摘要。`on (boolean on)`方法打开或关闭摘要功能。计算的摘要可使用`getMessageDigest()`方法检索。

`javax.swing.ProgressMonitorInputStream`类提供了对`InputStream`读取进度的监控。可以使用`getProgressMonitor()`方法访问监控对象。

# `javax.sound.sampled.AudioInputStream`

`AudioInputStream`类表示具有指定音频格式和长度的输入流。它有以下两个构造器：

*   `AudioInputStream (InputStream stream, AudioFormat format, long length)`：接受音频数据流、请求的格式和样本帧的长度
*   `AudioInputStream (TargetDataLine line)`：接受指示的目标数据行

`javax.sound.sampled.AudioFormat`类描述音频格式属性，如频道、编码、帧速率等。`javax.sound.sampled.TargetDataLine`类有`open()`方法打开指定格式的行，还有`read()`方法从数据行的输入缓冲区读取音频数据。

还有一个`javax.sound.sampled.AudioSystem`类，它的方法处理`AudioInputStream`对象。它们可用于读取音频文件、流或 URL，以及写入音频文件，还可用于将音频流转换为其他音频格式。

# `OutputStream`类及其子类

`OutputStream`类是`InputStream`类的一个对等类，它是一个抽象类，在 **Java 类库**（**JCL**）中有以下直接实现：`ByteArrayOutputStream`、`FilterOutputStream`、`ObjectOutputStream`、`PipedOutputStream`、`FileOutputStream`

`FileOutputStream`类有以下直接扩展：`BufferedOutputStream`、`CheckedOutputStream`、`DataOutputStream`、`PrintStream`、`javax.crypto.CipherOutputStream`、`java.util.zip.DeflaterOutputStream`、`java.security.DigestOutputStream`和`java.util.zip.InflaterOutputStream`。

它们要么按原样使用，要么覆盖`OutputStream`类的以下方法：

*   `void close()`：关闭流并释放资源
*   `void flush()`：强制写出剩余字节
*   `static OutputStream nullOutputStream()`：创建一个新的`OutputStream`，不写入任何内容
*   `void write(byte[] b)`：将提供的字节数组写入输出流
*   `void write(byte[] b, int off, int len)`：从`off`偏移量开始，将所提供字节数组的`len`字节写入输出流
*   `abstract void write(int b)`：将提供的字节写入输出流

唯一需要实现的方法是`abstract void write(int b)`，但是`OutputStream`类的大多数后代也覆盖了许多其他方法

在学习了“类`InputStream`及其子类”部分中的输入流之后，除了`PrintStream`类之外的所有`OutputStream`实现都应该对您非常熟悉。所以，我们在这里只讨论`PrintStream`类。

# 打印流

`PrintStream`类向另一个输出流添加了将数据打印为字符的能力。实际上我们已经用过很多次了。`System`类将`PrintStream`类的对象设置为`System.out`公共静态属性。这意味着每次我们使用`System.out`打印东西时，我们都使用`PrintStream`类：

```java
System.out.println("Printing a line");
```

让我们看另一个`PrintStream`类用法的例子：

```java
String fileName = "output.txt";
try(FileOutputStream  fos = new FileOutputStream(fileName);
    PrintStream ps = new PrintStream(fos)){
    ps.println("Hi there!");
} catch (Exception ex) {
    ex.printStackTrace();
}
```

如您所见，`PrintStream`类接受`FileOutputStream`对象并打印它生成的字符，在这种情况下，它打印出`FileOutputStream`写入文件的所有字节，顺便说一下，不需要显式地创建目标文件。如果不存在，则会在`FileOutputStream`构造器中自动创建，如果在前面的代码运行后打开文件，则会看到其中一行：`"Hi there!"`

或者，也可以使用另一个`PrintStream`构造器来获得相同的结果，该构造器接受`File`对象，如下所示：

```java
String fileName = "output.txt";
File file = new File(fileName);
try(PrintStream ps = new PrintStream(file)){
    ps.println("Hi there!");
} catch (Exception ex) {
    ex.printStackTrace();
}
```

使用以文件名为参数的`PrintStream`构造器的第三个变体可以创建一个更简单的解决方案：

```java
String fileName = "output.txt";
try(PrintStream ps = new PrintStream(fileName)){
    ps.println("Hi there!");
} catch (Exception ex) {
    ex.printStackTrace();
}
```

前两个例子是可能的，因为`PrintStream`构造器在幕后使用`FileOutputStream`类，就像我们在`PrintStream`类用法的第一个例子中所做的一样。所以`PrintStream`类有几个构造器只是为了方便，但它们基本上都有相同的功能：

*   `PrintStream(File file)`
*   `PrintStream(File file, String csn)`
*   `PrintStream(File file, Charset charset)`
*   `PrintStream(String fileName)`
*   `PrintStream(String fileName, String csn)`
*   `PrintStream(String fileName, Charset charset)`
*   `PrintStream(OutputStream out)`
*   `PrintStream(OutputStream out, boolean autoFlush)`
*   `PrintStream(OutputStream out, boolean autoFlush, String encoding)`
*   `PrintStream(OutputStream out, boolean autoFlush, Charset charset)`

一些构造器还采用一个`Charset`实例或其名称（`String csn`），这允许在 16 位 Unicode 代码单元序列和字节序列之间应用不同的映射。只需将所有可用的字符集打印出来即可查看它们，如下所示：

```java
for (String chs : Charset.availableCharsets().keySet()) {
    System.out.println(chs);
}
```

其他构造器以`boolean autoFlush`为参数。此参数表示（当`true`时）当写入数组或遇到符号行尾时，输出缓冲区应自动刷新。

一旦创建了一个`PrintStream`的对象，它就提供了如下所示的各种方法：

*   `void print(T value)`：打印传入的任何`T`原始类型的值，而不移动到另一行
*   `void print(Object obj)`：对传入对象调用`toString()`方法，打印结果，不移行；传入对象为`null`时不生成`NullPointerException`，而是打印`null`

*   `void println(T value)`：打印传入的任何`T`原始类型的值并移动到另一行
*   `void println(Object obj)`：对传入对象调用`toString()`方法，打印结果，移到另一行；传入对象为`null`时不生成`NullPointerException`，而是打印`null`
*   `void println()`：移动到另一行
*   `PrintStream printf(String format, Object... values)`：用提供的`values`替换提供的`format`字符串中的占位符，并将结果写入流中
*   `PrintStream printf(Locale l, String format, Object... args)`：与前面的方法相同，但是使用提供的`Local`对象进行定位；如果提供的`Local`对象是`null`，则不进行定位，该方法的行为与前面的方法完全相同
*   `PrintStream format(String format, Object... args)`、`PrintStream format(Locale l, String format, Object... args)`：与`PrintStream printf(String format, Object... values)`、`PrintStream printf(Locale l, String format, Object... args)`（已在列表中描述）行为相同，例如：

```java
System.out.printf("Hi, %s!%n", "dear reader"); //prints: Hi, dear reader!
System.out.format("Hi, %s!%n", "dear reader"); //prints: Hi, dear reader!

```

在上例中，（`%`表示格式化规则。以下符号（`s`）表示`String`值，此位置的其他可能符号可以是（`d`（十进制）、（`f`（浮点）等。符号（`n`）表示新行（与（`\n`）转义符相同）。有许多格式规则。所有这些都在`java.util.Formatter`类的文档中进行了描述。

*   `PrintStream append(char c)`、`PrintStream append(CharSequence c)`、`PrintStream append(CharSequence c, int start, int end)`：将提供的字符追加到流中。例如：

```java
System.out.printf("Hi %s", "there").append("!\n");  //prints: Hi there!
System.out.printf("Hi ")
               .append("one there!\n two", 4, 11);  //prints: Hi there!

```

至此，我们结束了对`OutputStream`子类的讨论，现在将注意力转向另一个类层次结构`Reader`和`Writer`类及其子类。

# `Reader`和`Writer`类及其子类

正如我们已经多次提到的，`Reader`和`Writer`类在功能上与`InputStream`和`OutputStream`类非常相似，但专门处理文本。它们将流字节解释为字符，并有自己独立的`InputStream`和`OutputStream`类层次结构。在没有`Reader`和`Writer`或它们的任何子类的情况下，可以将流字节作为字符进行处理。我们在前面描述`InputStream`和`OutputStream`类的章节中看到了这样的示例。但是，使用`Reader`和`Writer`类可以简化文本处理，代码更易于阅读。

# `Reader`及其子类

类`Reader`是一个抽象类，它将流作为字符读取。它是对`InputStream`的模拟，有以下方法：

*   `abstract void close()`：关闭流和其他使用的资源
*   `void mark(int readAheadLimit)`：标记流中的当前位置
*   `boolean markSupported()`：如果流支持`mark()`操作，则返回`true`
*   `static Reader nullReader()`：创建不读取字符的空读取器
*   `int read()`：读一个字符
*   `int read(char[] buf)`：将字符读入提供的`buf`数组，并返回读取字符的计数
*   `abstract int read(char[] buf, int off, int len)`：从`off`索引开始将`len`字符读入数组
*   `int read(CharBuffer target)`：尝试将字符读入提供的`target`缓冲区
*   `boolean ready()`：当流准备好读取时返回`true`
*   `void reset()`：重新设置标记，但是不是所有的流都支持这个操作，有些流支持，但是不支持设置标记

*   `long skip(long n)`：尝试跳过`n`个字符；返回跳过字符的计数
*   `long transferTo(Writer out)`：从该读取器读取所有字符，并将字符写入提供的`Writer`对象

如您所见，唯一需要实现的方法是两个抽象的`read()`和`close()`方法。然而，这个类的许多子类也覆盖了其他方法，有时是为了更好的性能或不同的功能。JCL 中的`Reader`子类是：`CharArrayReader`、`InputStreamReader`、`PipedReader`、`StringReader`、`BufferedReader`和`FilterReader`。`BufferedReader`类有`LineNumberReader`子类，`FilterReader`类有`PushbackReader`子类。

# `Writer`及其子类

抽象的`Writer`类写入字符流。它是`OutputStream`的一个模拟，具有以下方法：

*   `Writer append(char c)`：将提供的字符追加到流中
*   `Writer append(CharSequence c)`：将提供的字符序列追加到流中
*   `Writer append(CharSequence c, int start, int end)`：将所提供的字符序列的子序列追加到流中
*   `abstract void close()`：刷新并关闭流和相关系统资源
*   `abstract void flush()`：冲流
*   `static Writer nullWriter()`：创建一个新的`Writer`对象，丢弃所有字符
*   `void write(char[] c)`：写入`c`字符数组
*   `abstract void write(char[] c, int off, int len)`：从`off`索引开始写入`c`字符数组的`len`元素
*   `void write(int c)`：写一个字
*   `void write(String str)`：写入提供的字符串
*   `void write(String str, int off, int len)`：从`off`索引开始，从提供的`str`字符串写入一个`len`长度的子字符串

如您所见，三个抽象方法：`write(char[], int, int)`、`flush()`和`close()`必须由这个类的子类实现，它们通常也覆盖其他方法。

JCL 中的`Writer`子类是：`CharArrayWriter`、`OutputStreamWriter`、`PipedWriter`、`StringWriter`、`BufferedWriter`、`FilterWriter`和`PrintWriter`。`OutputStreamWriter`类有一个`FileWriter`子类。

# `java.io`包的其他类

`java.io`包的其他类别包括：

*   `Console`：允许与当前 JVM 实例关联的基于字符的控制台设备进行交互
*   `StreamTokenizer`：获取一个输入流并将其解析为`tokens`
*   `ObjectStreamClass`：类的序列化描述符
*   `ObjectStreamField`：可序列化类中可序列化字段的描述
*   `RandomAccessFile`：允许对文件进行随机读写，但其讨论超出了本书的范围
*   `File`：允许创建和管理文件和目录；在“文件管理”部分中描述

# 控制台

创建和运行执行应用的 **Java 虚拟机**（**JVM**）实例有几种方法，如果 JVM 是从命令行启动的，控制台窗口会自动打开，它允许从键盘在显示器上键入内容，但是 JVM 也可以通过后台进程启动。在这种情况下，不会创建控制台。

为了通过编程检查控制台是否存在，可以调用`System.console()`静态方法。如果没有可用的控制台设备，则调用该方法将返回`null`。否则，它将返回一个允许与控制台设备和应用用户交互的`Console`类的对象。

让我们创建以下`ConsoleDemo`类：

```java
package com.packt.learnjava.ch05_stringsIoStreams;
import java.io.Console;
public class ConsoleDemo {
    public static void main(String... args)  {
        Console console = System.console();
        System.out.println(console);
    }
}
```

如果我们像通常那样从 IDE 运行它，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ebc1dbfe-424f-47b1-bef6-6321d235dd9f.png)

这是因为 JVM 不是从命令行启动的。为了做到这一点，让我们编译应用并通过在项目的根目录中执行`mvn clean package`Maven 命令来创建一个`.jar`文件。删除`target`文件夹，然后重新创建，将所有`.java`文件编译成`target`文件夹中相应的`.class`文件，然后归档到`.jar`文件`learnjava-1.0-SNAPSHOT.jar`中。

现在我们可以使用以下命令从同一个项目根目录启动`ConsoleDemo`应用：

```java
java -cp ./target/learnjava-1.0-SNAPSHOT.jar 
 com.packt.learnjava.ch05_stringsIoStreams.ConsoleDemo
```

前面的命令显示为两行，因为页面宽度不能容纳它。但是如果你想运行它，一定要把它作为一行。结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/8585c838-8837-4601-9064-8d13f2c249f8.png)

它告诉我们现在有了`Console`类对象。让我们看看能用它做些什么。该类具有以下方法：

*   `String readLine()`：等待用户点击`Enter`并从控制台读取文本行
*   `String readLine(String format, Object... args)`：显示提示（提供的格式将占位符替换为提供的参数后产生的消息），等待用户点击`Enter`，从控制台读取文本行；如果没有提供参数`args`，则显示格式作为提示

*   `char[] readPassword()`：执行与`readLine()`相同的功能，但不回显键入的字符
*   `char[] readPassword(String format, Object... args)`：执行与`readLine(String format, Object... args)`相同的功能，但不回显键入的字符

让我们用下面的例子来演示前面的方法：

```java
Console console = System.console();

String line = console.readLine();
System.out.println("Entered 1: " + line);
line = console.readLine("Enter something 2: ");
System.out.println("Entered 2: " + line);
line = console.readLine("Enter some%s", "thing 3: ");
System.out.println("Entered 3: " + line);

char[] password = console.readPassword();
System.out.println("Entered 4: " + new String(password));
password = console.readPassword("Enter password 5: ");
System.out.println("Entered 5: " + new String(password));
password = console.readPassword("Enter pass%s", "word 6: ");
System.out.println("Entered 6: " + new String(password));
```

上例的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c7751f80-9a56-4beb-9603-7c6614aec5ad.png)

另一组`Console`类方法可以与刚才演示的方法结合使用：

*   `Console format(String format, Object... args)`：用提供的`args`值替换提供的`format`字符串中的占位符，并显示结果
*   `Console printf(String format, Object... args)`：与`format()`方法相同

例如，请看下面一行：

```java
String line = console.format("Enter some%s", "thing:").readLine();

```

它产生与此行相同的结果：

```java
String line = console.readLine("Enter some%s", "thing:");

```

最后，`Console`类的最后三个方法如下：

*   `PrintWriter writer()`：创建一个与此控制台关联的`PrintWriter`对象，用于生成字符的输出流
*   `Reader reader()`：创建一个与此控制台相关联的`Reader`对象，用于将输入作为字符流读取
*   `void flush()`：刷新控制台并强制立即写入任何缓冲输出

以下是它们的用法示例：

```java
try (Reader reader = console.reader()){
    char[] chars = new char[10];
    System.out.print("Enter something: ");
    reader.read(chars);
    System.out.print("Entered: " + new String(chars));
} catch (IOException e) {
    e.printStackTrace();
}

PrintWriter out = console.writer();
out.println("Hello!");

console.flush();

```

上述代码的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/93bcad35-3e24-47ad-b9f6-baddd6fe10ff.png)

`Reader`和`PrintWriter`还可以用于创建我们在本节中讨论的其他`Input`和`Output`流。

# 流分词器

`StreamTokenizer`类解析输入流并生成令牌。它的`StreamTokenizer(Reader r)`构造器接受一个`Reader`对象，该对象是令牌的源。每次对`StreamTokenizer`对象调用`int nextToken()`方法时，都会发生以下情况：

1.  下一个标记被解析
2.  `StreamTokenizer`实例字段`ttype`由指示令牌类型的值填充：
    *   `ttype`值可以是以下整数常量之一：`TT_WORD`、`TT_NUMBER`、`TT_EOL`（行尾）或`TT_EOF`（流尾）
    *   如果`ttype`值为`TT_WORD`，则`StreamTokenizer`实例`sval`字段由令牌的`String`值填充
    *   如果`ttype`值为`TT_NUMBER`，则`StreamTokenizer`实例字段`nval`由令牌的`double`值填充
3.  `StreamTokenizer`实例的`lineno()`方法返回当前行号

在讨论`StreamTokenizer`类的其他方法之前，让我们先看一个例子。假设在项目`resources`文件夹中有一个`tokens.txt`文件，其中包含以下四行文本：

```java
There
happened
42
events.
```

以下代码将读取文件并标记其内容：

```java
String filePath = "src/main/resources/tokens.txt";
try(FileReader fr = new FileReader(filePath);
 BufferedReader br = new BufferedReader(fr)){
 StreamTokenizer st = new StreamTokenizer(br);
    st.eolIsSignificant(true);
    st.commentChar('e');
    System.out.println("Line " + st.lineno() + ":");
    int i;
    while ((i = st.nextToken()) != StreamTokenizer.TT_EOF) {
        switch (i) {
            case StreamTokenizer.TT_EOL:
                System.out.println("\nLine " + st.lineno() + ":");
                break;
            case StreamTokenizer.TT_WORD:
                System.out.println("TT_WORD => " + st.sval);
                break;
            case StreamTokenizer.TT_NUMBER:
                System.out.println("TT_NUMBER => " + st.nval);
                break;
            default:
                System.out.println("Unexpected => " + st.ttype);
        }
    }         
} catch (Exception ex){
    ex.printStackTrace();
}
```

如果运行此代码，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/a8321bb4-1929-415d-8d37-dc72e6edd773.png)

我们已经使用了`BufferedReader`类，这是提高效率的一个很好的实践，但是在我们的例子中，我们可以很容易地避免这样的情况：

```java
 FileReader fr = new FileReader(filePath);
 StreamTokenizer st = new StreamTokenizer(fr);

```

结果不会改变。我们还使用了以下三种尚未描述的方法：

*   `void eolIsSignificant(boolean flag)`：表示行尾是否作为令牌处理
*   `void commentChar(int ch)`：表示哪个字符开始一个注释，因此忽略行的其余部分
*   `int lineno()`：返回当前行号

使用`StreamTokenizer`对象可以调用以下方法：

*   `void lowerCaseMode(boolean fl)`：表示单词标记是否应该小写
*   `void ordinaryChar(int ch)`、`void ordinaryChars(int low, int hi)`：表示必须作为*普通*处理的特定字符或字符范围（不能作为注释字符、词成分、字符串分隔符、空格或数字字符）
*   `void parseNumbers()`：表示具有双精度浮点数格式的字标记必须被解释为数字而不是字
*   `void pushBack()`：强制`nextToken()`方法返回`ttype`字段的当前值
*   `void quoteChar(int ch)`：表示提供的字符必须解释为字符串值的开头和结尾，该字符串值必须按原样（作为引号）处理
*   `void resetSyntax()`：重置此标记器的语法表，使所有字符都是*普通*
*   `void slashSlashComments(boolean flag)`：表示必须识别 C++ 风格的注释
*   `void slashStarComments(boolean flag)`：表示必须识别 C 风格的注释
*   `String toString()`：返回令牌的字符串表示和行号
    `void whitespaceChars(int low, int hi)`：表示必须解释为空白的字符范围
*   `void wordChars(int low, int hi)`：表示必须解释为单词的字符范围

如您所见，使用前面丰富的方法可以对文本解释进行微调。

# `ObjectStreamClass`和`ObjectStreamField`

`ObjectStreamClass`和`ObjectStreamField`类提供对 JVM 中加载的类的序列化数据的访问。`ObjectStreamClass`对象可以使用以下查找方法之一找到/创建：

*   `static ObjectStreamClass lookup(Class cl)`：查找可序列化类的描述符
*   `static ObjectStreamClass lookupAny(Class cl)`：查找任何类的描述符，无论是否可序列化

在找到`ObjectStreamClass`并且类是可序列化的（实现`Serializable`接口）之后，可以使用它访问`ObjectStreamField`对象，每个对象包含一个序列化字段的信息。如果该类不可序列化，则没有与任何字段关联的`ObjectStreamField`对象。

让我们看一个例子。以下是显示从`ObjectStreamClass`和`ObjectStreamField`对象获得的信息的方法：

```java
void printInfo(ObjectStreamClass osc) {
    System.out.println(osc.forClass());
    System.out.println("Class name: " + osc.getName());
    System.out.println("SerialVersionUID: " + osc.getSerialVersionUID());
    ObjectStreamField[] fields = osc.getFields();
    System.out.println("Serialized fields:");
    for (ObjectStreamField osf : fields) {
        System.out.println(osf.getName() + ": ");
        System.out.println("\t" + osf.getType());
        System.out.println("\t" + osf.getTypeCode());
        System.out.println("\t" + osf.getTypeString());
    }
}
```

为了演示它是如何工作的，我们创建了一个可序列化的`Person1`类：

```java
package com.packt.learnjava.ch05_stringsIoStreams;
import java.io.Serializable;
public class Person1 implements Serializable {
    private int age;
    private String name;
    public Person1(int age, String name) {
        this.age = age;
        this.name = name;
    }
}
```

我们没有添加方法，因为只有对象状态是可序列化的，而不是方法。现在让我们运行以下代码：

```java
ObjectStreamClass osc1 = ObjectStreamClass.lookup(Person1.class);
printInfo(osc1);

```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/86ca6ffa-a2a4-4e8c-8a62-e93ba17d58e4.png)

如您所见，有关于类名、所有字段名和类型的信息。使用`ObjectStreamField`对象还可以调用另外两个方法：

*   `boolean isPrimitive()`：如果该字段有原始类型，则返回`true`
*   `boolean isUnshared()`：如果此字段未共享（私有或只能从同一包访问），则返回`true`

现在让我们创建一个不可序列化的`Person2`类：

```java
package com.packt.learnjava.ch05_stringsIoStreams;
public class Person2 {
    private int age;
    private String name;
    public Person2(int age, String name) {
        this.age = age;
        this.name = name;
    }
}
```

这次，我们将运行只查找类的代码，如下所示：

```java
ObjectStreamClass osc2 = ObjectStreamClass.lookup(Person2.class);
System.out.println("osc2: " + osc2);    //prints: null

```

正如预期的那样，使用`lookup()`方法找不到不可序列化的对象。为了找到一个不可序列化的对象，我们需要使用`lookupAny()`方法：

```java
ObjectStreamClass osc3 = ObjectStreamClass.lookupAny(Person2.class);
printInfo(osc3);
```

如果我们运行前面的示例，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/7766049f-f24a-44d2-bb2f-9e1aa51c86d1.png)

从一个不可序列化的对象中，我们可以提取关于类的信息，但不能提取关于字段的信息。

# `java.util.Scanner`类

`java.util.Scanner`类通常用于从键盘读取输入，但可以从实现`Readable`接口的任何对象读取文本（该接口只有`int read(CharBuffer buffer)`方法）。它用一个分隔符（空白是默认分隔符）将输入值拆分为使用不同方法处理的标记。

例如，我们可以从`System.in`读取一个输入—一个标准输入流，它通常表示键盘输入：

```java
Scanner sc = new Scanner(System.in);
System.out.print("Enter something: ");
while(sc.hasNext()){
    String line = sc.nextLine();
    if("end".equals(line)){
        System.exit(0);
    }
    System.out.println(line);
}
```

它接受许多行（每行在按下`Enter`键后结束），直到按如下方式输入行`end`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/7f2c2b9e-17e3-40ec-b1ae-228c46092c21.png)

或者，`Scanner`可以从文件中读取行：

```java
String filePath = "src/main/resources/tokens.txt";
try(Scanner sc = new Scanner(new File(filePath))){
    while(sc.hasNextLine()){
        System.out.println(sc.nextLine());
    }
} catch (Exception ex){
    ex.printStackTrace();
}
```

如您所见，我们再次使用了`tokens.txt`文件。结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e16dbebb-7087-46f6-9378-dddbcded13e2.png)

为了演示`Scanner`用分隔符打断输入，让我们运行以下代码：

```java
String input = "One two three";
Scanner sc = new Scanner(input);
while(sc.hasNext()){
    System.out.println(sc.next());
}
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c2bedcd5-3234-409c-b0cd-d62015d6f9ec.png)

要使用另一个分隔符，可以按如下方式设置：

```java
String input = "One,two,three";
Scanner sc = new Scanner(input).useDelimiter(",");
while(sc.hasNext()){
    System.out.println(sc.next());
}
```

结果保持不变：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c87d32bd-c7ee-47dc-ba10-8d57f6963a9d.png)

也可以使用正则表达式来提取标记，但是本主题不在本书的范围之内。

`Scanner`类有许多其他方法使其用法适用于各种源和所需结果。`findInLine()`、`findWithinHorizon()`、`skip()`和`findAll()`方法不使用分隔符，它们只是尝试匹配提供的模式。有关更多信息，[请参阅扫描器文档](https://docs.oracle.com/en/java/javase/12/docs/api/java.base/java/util/Scanner.html)。

# 文件管理

我们已经使用了一些方法来使用 JCL 类查找、创建、读取和写入文件。我们必须这样做，以支持输入/输出流的演示代码。在本节中，我们将更详细地讨论使用 JCL 的文件管理。

来自`java.io`包的`File`类表示底层文件系统。可以使用以下构造器之一创建`File`类的对象：

*   `File(String pathname)`：根据提供的路径名新建`File`实例
*   `File(String parent, String child)`：根据提供的父路径名和子路径名新建`File`实例
*   `File(File parent, String child)`：基于提供的父`File`对象和子路径名创建一个新的`File`实例
*   `File(URI uri)`：根据提供的`URI`对象创建一个新的`File`实例，该对象表示路径名

我们现在将看到构造器在创建和删除文件时的用法示例。

# 创建和删除文件和目录

要在文件系统中创建文件或目录，首先需要使用“文件管理”部分中列出的一个构造器来构造一个新的`File`对象。例如，假设文件名为`FileName.txt`，则可以将`File`对象创建为`new File("FileName.txt")`。如果必须在目录中创建文件，则必须在文件名前面添加路径（当文件被传递到构造器时），或者必须使用其他三个构造器中的一个。例如：

```java
String path = "demo1" + File.separator + "demo2" + File.separator;
String fileName = "FileName.txt";
File f = new File(path + fileName);

```

注意使用`File.separator`代替斜杠符号（`/`）或（`\`）。这是因为`File.separator`返回特定于平台的斜杠符号。下面是另一个`File`构造器用法的示例：

```java
String path = "demo1" + File.separator + "demo2" + File.separator;
String fileName = "FileName.txt";
File f = new File(path, fileName);
```

另一个构造器可以如下使用：

```java
String path = "demo1" + File.separator + "demo2" + File.separator;
String fileName = "FileName.txt";
File f = new File(new File(path), fileName);
```

但是，如果您喜欢或必须使用**通用资源标识符**（**URI**），您可以这样构造一个`File`对象：

```java
String path = "demo1" + File.separator + "demo2" + File.separator;
String fileName = "FileName.txt";
URI uri = new File(path + fileName).toURI();
File f = new File(uri);
```

然后必须在新创建的`File`对象上调用以下方法之一：

*   `boolean createNewFile()`：如果该名称的文件不存在，则新建一个文件，返回`true`，否则返回`false`

*   `static File createTempFile(String prefix, String suffix)`：在临时文件目录中创建一个文件
*   `static File createTempFile(String prefix, String suffix, File directory)`：创建目录，提供的前缀和后缀用于生成目录名

如果要创建的文件必须放在尚不存在的目录中，则必须首先使用以下方法之一，在表示文件的文件系统路径的`File`对象上调用：

*   `boolean mkdir()`：用提供的名称创建目录
*   `boolean mkdirs()`：用提供的名称创建目录，包括任何必要但不存在的父目录

在看代码示例之前，我们需要解释一下`delete()`方法是如何工作的：

*   `boolean delete()`：删除文件或空目录，即可以删除文件，但不能删除所有目录，如下所示：

```java
String path = "demo1" + File.separator + "demo2" + File.separator;
String fileName = "FileName.txt";
File f = new File(path + fileName);
f.delete();
```

让我们在下面的示例中看看如何克服此限制：

```java
String path = "demo1" + File.separator + "demo2" + File.separator;
String fileName = "FileName.txt";
File f = new File(path + fileName);
try {
    new File(path).mkdirs();
    f.createNewFile();
    f.delete();
    path = StringUtils.substringBeforeLast(path, File.separator);
    while (new File(path).delete()) {
        path = StringUtils.substringBeforeLast(path, File.separator);
    }
} catch (Exception e) {
    e.printStackTrace();
}
```

这个例子创建和删除一个文件和所有相关的目录，注意我们在“字符串工具”一节中讨论的`org.apache.commons.lang3.StringUtils`类的用法。它允许我们从路径中删除刚刚删除的目录，并继续这样做，直到所有嵌套的目录都被删除，而顶层目录最后被删除

# 列出文件和目录

下列方法可用于列出其中的目录和文件：

*   `String[] list()`：返回目录中文件和目录的名称
*   `File[] listFiles()`：返回`File`表示目录中文件和目录的对象
*   `static File[] listRoots()`：列出可用的文件系统根目录

为了演示前面的方法，假设我们已经创建了目录和其中的两个文件，如下所示：

```java
String path1 = "demo1" + File.separator;
String path2 = "demo2" + File.separator;
String path = path1 + path2;
File f1 = new File(path + "file1.txt");
File f2 = new File(path + "file2.txt");
File dir1 = new File(path1);
File dir = new File(path);
dir.mkdirs();
f1.createNewFile();
f2.createNewFile();

```

之后，我们应该能够运行以下代码：

```java
System.out.print("\ndir1.list(): ");
for(String d: dir1.list()){
    System.out.print(d + " ");
}
System.out.print("\ndir1.listFiles(): ");
for(File f: dir1.listFiles()){
    System.out.print(f + " ");
}
System.out.print("\ndir.list(): ");
for(String d: dir.list()){
    System.out.print(d + " ");
}
System.out.print("\ndir.listFiles(): ");
for(File f: dir.listFiles()){
    System.out.print(f + " ");
}
System.out.print("\nFile.listRoots(): ");
for(File f: File.listRoots()){
    System.out.print(f + " ");
}
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/06931621-3ea8-4cb0-bdd3-99984f878bd8.png)

演示的方法可以通过向其添加以下过滤器来增强，因此它们将仅列出与过滤器匹配的文件和目录：

*   `String[] list(FilenameFilter filter)`
*   `File[] listFiles(FileFilter filter)`
*   `File[] listFiles(FilenameFilter filter)`

但是，对文件过滤器的讨论超出了本书的范围。

# Apache 公共工具`FileUtils`和`IOUtils`

JCL 最流行的伙伴是 [ApacheCommons 项目](https://commons.apache.org)，它提供了许多库来补充 JCL 功能。`org.apache.commons.io`包的类包含在以下根包和子包中：

*   `org.apache.commons.io`根包包含用于常见任务的带有静态方法的工具类，例如分别在“类`FileUtils`”和“类`IOUtils`”小节中描述的流行的`FileUtils`和`IOUtils`类
*   `org.apache.commons.io.input`包包含支持基于`InputStream`和`Reader`实现的输入的类，如`XmlStreamReader`或`ReversedLinesFileReader`

*   `org.apache.commons.io.output`包包含支持基于`OutputStream`和`Writer`实现的输出的类，如`XmlStreamWriter`或`StringBuilderWriter`
*   `org.apache.commons.io.filefilter`包包含用作文件过滤器的类，如`DirectoryFileFilter`或`RegexFileFilter`
*   `org.apache.commons.io.comparator`包包含`java.util.Comparator`的各种文件实现，如`NameFileComparator`
*   `org.apache.commons.io.serialization`包提供了一个控制类反序列化的框架
*   `org.apache.commons.io.monitor`包允许监视文件系统并检查目录或文件的创建、更新或删除；可以将`FileAlterationMonitor`对象作为线程启动，并创建一个`FileAlterationObserver`对象，以指定的间隔检查文件系统中的更改

请参阅 [Apache Commons 项目文档](https://commons.apache.org)了解更多细节。

# `FileUtils`类

一个流行的`org.apache.commons.io.FileUtils`类允许对您可能需要的文件执行所有可能的操作，如下所示：

*   写入文件
*   从文件读取
*   创建包含父目录的目录
*   复制文件和目录
*   删除文件和目录
*   与 URL 之间的转换
*   按过滤器和扩展名列出文件和目录
*   比较文件内容
*   获取文件上次更改日期
*   计算校验和

如果您计划以编程方式管理文件和目录，那么您必须学习 [ApacheCommons 项目网站](https://commons.apache.org/proper/commons-io/javadocs/api-2.5/org/apache/commons/io/FileUtils.html)上的此类文档。

# `IOUtils`类

`org.apache.commons.io.IOUtils`是另一个非常有用的工具类，提供以下通用 IO 流操作方法：

*   `closeQuietly`：关闭流的方法，忽略空值和异常
*   `toXxx/read`：从流中读取数据的方法
*   `write`：将数据写入流的方法
*   `copy`：将所有数据从一个流复制到另一个流的方法
*   `contentEquals`：比较两种流的含量的方法

该类中所有读取流的方法都在内部缓冲，因此不需要使用`BufferedInputStream`或`BufferedReader`类。`copy`方法都在幕后使用`copyLarge`方法，大大提高了它们的性能和效率。

这个类对于管理 IO 流是必不可少的。在 [ApacheCommons 项目网站](https://commons.apache.org/proper/commons-io/javadocs/api-2.5/org/apache/commons/io/IOUtils.html)上可以看到关于这个类及其方法的更多细节。

# 总结

在本章中，我们讨论了允许分析、比较和转换字符串的`String`类方法。我们还讨论了 JCL 和 ApacheCommons 项目中流行的字符串工具。本章的两个主要部分专门介绍 JCL 和 ApacheCommons 项目中的输入/输出流和支持类。文中还讨论了文件管理类及其方法，并给出了具体的代码实例。

在下一章中，我们将介绍 Java 集合框架及其三个主要接口`List`、`Set`和`Map`，包括泛型的讨论和演示。我们还将讨论用于管理数组、对象和时间/日期值的工具类。

# 测验

1.  下面的代码打印什么？

```java
String str = "&8a!L";
System.out.println(str.indexOf("a!L"));
```

2.  下面的代码打印什么？

```java
String s1 = "x12";
String s2 = new String("x12");
System.out.println(s1.equals(s2)); 
```

3.  下面的代码打印什么？

```java
System.out.println("%wx6".substring(2));

```

4.  下面的代码打印什么？

```java
System.out.println("ab"+"42".repeat(2));
```

5.  下面的代码打印什么？

```java
String s = "  ";
System.out.println(s.isBlank()+" "+s.isEmpty());

```

6.  选择所有正确的语句：

    1.  流可以表示数据源
    2.  输入流可以写入文件
    3.  流可以表示数据目的地
    4.  输出流可以在屏幕上显示数据
7.  选择所有关于`java.io`包类的正确语句：
    1.  读取器扩展`InputStream`
    2.  读取器扩展`OutputStream`
    3.  读取器扩展`java.lang.Object`
    4.  读取器扩展`java.lang.Input`
8.  选择所有关于`java.io`包类的正确语句：
    1.  写入器扩展`FilterOutputStream`
    2.  写入器扩展`OutputStream`
    3.  写入器扩展`java.lang.Output`
    4.  写入器扩展`java.lang.Object`
9.  选择所有关于`java.io`包类的正确语句：
    1.  `PrintStream`扩展`FilterOutputStream`
    2.  `PrintStream`扩展`OutputStream`
    3.  `PrintStream`扩展`java.lang.Object`
    4.  `PrintStream`扩展`java.lang.Output`

10.  下面的代码是做什么的？

```java
String path = "demo1" + File.separator + "demo2" + File.separator;
String fileName = "FileName.txt";
File f = new File(path, fileName);
try {
    new File(path).mkdir();
    f.createNewFile();
} catch (Exception e) {
    e.printStackTrace();
} 
```*