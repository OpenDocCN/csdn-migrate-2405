# Java11 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/2bf50d1e2a61626a8f3de4e5aae60b76`](https://zh.annas-archive.org/md5/2bf50d1e2a61626a8f3de4e5aae60b76)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：进行函数式编程

本章介绍了一种称为函数式编程的编程范式，以及它在 Java 11 中的适用性。我们将涵盖以下内容：

+   使用标准功能接口

+   创建函数式接口

+   理解 lambda 表达式

+   使用 lambda 表达式

+   使用方法引用

+   在程序中利用 lambda 表达式

# 介绍

函数式编程是将某个功能作为对象对待，并将其作为方法的参数或返回值传递的能力。这个特性存在于许多编程语言中，Java 在 Java 8 发布时获得了这个特性。

它避免了创建类、对象和管理对象状态。函数的结果仅取决于输入数据，无论调用多少次。这种风格使结果更可预测，这是函数式编程最吸引人的方面。

它也让我们能够通过将并行性的责任从客户端代码转移到库中，来改进 Java 中的并行编程能力。在此之前，为了处理 Java 集合的元素，客户端代码必须从集合中获取迭代器并组织集合的处理。

Java 集合的一些默认方法接受一个函数（函数式接口的实现）作为参数，然后将其应用于集合的每个元素。因此，库的责任是组织处理。一个例子是在每个 Iterable 接口中都可用的 forEach(Consumer)方法，其中 Consumer 是一个函数式接口。另一个例子是在每个 Collection 接口中都可用的 removeIf(Predicate)方法，其中 Predicate 也是一个函数式接口。此外，List 接口中添加了 sort(Comparator)和 replaceAll(UnaryOperator)方法，Map 中添加了 compute()方法。

Lambda 表达式利用函数式接口，并显著简化了它们的实现，使代码更短、更清晰、更具表现力。

在本章中，我们将讨论函数式编程的优势，定义和解释函数式接口和 lambda 表达式，并在代码示例中演示所有相关功能。

使函数成为语言的一等公民为 Java 增加了更多的功能。但利用这种语言能力需要——对于尚未接触函数式编程的人来说——一种新的思维方式和代码组织方式。

解释这一新特性并分享使用它的最佳实践是本章的目的。

# 使用标准功能接口

在这个示例中，您将学习什么是函数式接口，以及为什么它被添加到 Java 中，以及 JDK 8 中附带的标准 Java 库中的 43 个可用的函数式接口。

没有函数式接口，将功能传递到方法的唯一方法是通过编写一个类，创建其对象，然后将其作为参数传递。但即使是最不涉及的样式——使用匿名类——也需要编写太多的代码。使用函数式接口有助于避免所有这些。

# 准备工作

任何具有一个且仅有一个抽象方法的接口都被称为函数式接口。为了避免运行时错误，可以在接口前面添加@FunctionalInterface 注解。它告诉编译器意图，因此编译器可以检查该接口中是否实际上有一个抽象方法，包括从其他接口继承的方法。

在前几章的演示代码中，我们已经有了一个函数式接口的示例，即使我们没有将其注释为函数式接口。

```java
public interface SpeedModel {
  double getSpeedMph(double timeSec, int weightPounds, int horsePower);
  enum DrivingCondition {
    ROAD_CONDITION,
    TIRE_CONDITION
  }
  enum RoadCondition {
    //...
  }
  enum TireCondition {
    //...
  }
}
```

`enum`类型的存在或任何实现的（默认或静态）方法并不会使其成为非功能接口。只有抽象（未实现）方法才算。因此，这也是一个功能接口的例子：

```java
public interface Vehicle {
  void setSpeedModel(SpeedModel speedModel);
  default double getSpeedMph(double timeSec){ return -1; };
  default int getWeightPounds(){ return -1; }
  default int getWeightKg(){ 
    return convertPoundsToKg(getWeightPounds());
  }
  private int convertPoundsToKg(int pounds){
    return (int) Math.round(0.454 * pounds);
  }
  static int convertKgToPounds(int kilograms){
    return (int) Math.round(2.205 * kilograms);
  }
}
```

回顾您在第二章中已经学到的关于接口的默认方法，`getWeightPounds()`方法在被`getWeightKg()`调用或直接调用时将返回`-1`，使用实现`Vehicle`接口的类的对象。但是，只有在类中未实现`getWeightPounds()`方法时才会如此。否则，将使用类的实现并返回不同的值。

除了默认和静态接口方法，功能接口还可以包括`java.lang.Object`基类的任何和所有抽象方法。在 Java 中，每个对象都提供了`java.lang.Object`方法的默认实现，因此编译器和 Java 运行时会忽略这样的抽象方法。

例如，这也是一个功能接口：

```java
public interface SpeedModel {
  double getSpeedMph(double timeSec, int weightPounds, int horsePower);
  boolean equals(Object obj);
  String toString();
}
```

以下虽然不是功能接口：

```java
public interface Car extends Vehicle {
   int getPassengersCount();
}
```

这是因为`Car`接口有两个抽象方法——它自己的`getPassengersCount()`方法和从`Vehicle`接口继承的`setSpeedModel(SpeedModel speedModel)`方法。

我们可以尝试将`@FunctionalInterface`注解添加到`Car`接口中：

```java
@FunctionalInterface 
public interface Car extends Vehicle {
   int getPassengersCount();
}
```

如果我们这样做，编译器将生成以下错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/df18df69-1aed-4f20-b3cf-b2c5f741d2f6.png)

使用`@FunctionalInterface`注解不仅有助于在编译时捕获错误，而且还确保了程序员之间设计意图的可靠沟通。它可以帮助您或其他程序员记住该接口不能有多个抽象方法，这在已经存在依赖于这种假设的一些代码时尤其重要。

出于同样的原因，`Runnable`和`Callable`接口（它们自 Java 早期版本以来就存在）在 Java 8 中被注释为`@FunctionalInterface`，以明确区分：

```java
@FunctionalInterface
interface Runnable { void run(); }

@FunctionalInterface
interface Callable<V> { V call() throws Exception; }
```

# 如何做…

在创建自己的功能接口之前，首先考虑使用`java.util.function`包中提供的 43 个功能接口中的一个。它们中的大多数是`Function`、`Consumer`、`Supplier`和`Predicate`接口的特殊化。

以下是您可以遵循的步骤，以熟悉功能接口：

1.  看看`Function<T,R>`功能接口：

```java
        @FunctionalInterface
        public interface Function<T,R>
```

从`<T,R>`泛型中可以看出，该接口的唯一方法接受`T`类型的参数并返回`R`类型的值。根据 JavaDoc，该接口具有`R apply(T t)`方法。我们可以使用匿名类创建该接口的实现：

```java
      Function<Integer, Double> ourFunc = 
          new Function<Integer, Double>() {
              public Double apply(Integer i){
                  return i * 10.0;
              }
          };
```

我们的实现中的`R apply(T t)`方法接受`Integer`类型的值（或将自动装箱的`int`原始类型），将其乘以`10`，并返回`Double`类型的值，以便我们可以如下使用我们的新函数：

```java
        System.out.println(ourFunc.apply(1));  //prints: 10
```

在下面的*理解 lambda 表达式*的示例中，我们将介绍 lambda 表达式，并向您展示它的使用方式如何使实现变得更短。但现在，我们将继续使用匿名类。

1.  看看`Consumer<T>`功能接口。名称帮助我们记住该接口的方法接受一个值，但不返回任何东西——它只消耗。它的唯一方法是`void accept(T)`。该接口的实现可以如下所示：

```java
        Consumer<String> ourConsumer = new Consumer<String>() {
          public void accept(String s) {
            System.out.println("The " + s + " is consumed.");
          }
        };
```

我们的实现中的`void accept(T t)`方法接收`String`类型的值并打印它。例如，我们可以这样使用它：

```java
          ourConsumer.accept("Hello!");  
                        //prints: The Hello! is consumed.
```

1.  看看`Supplier<T>`功能接口。名称帮助您记住该接口的方法不接受任何值，但确实返回一些东西——只提供。它的唯一方法是`T get()`。基于此，我们可以创建一个函数：

```java
        Supplier<String> ourSupplier = new Supplier<String>() {
          public String get() {
            String res = "Success";
            //Do something and return result—Success or Error.
            return res;
          }
        };
```

我们的实现中的`T get()`方法执行某些操作，然后返回`String`类型的值，因此我们可以编写以下内容：

```java
        System.out.println(ourSupplier.get());   //prints: Success
```

1.  看一下`Predicate<T>`函数接口。名称有助于记住该接口的方法返回一个布尔值——它预测某些东西。它的唯一方法是`boolean test(T t)`，这意味着我们可以创建以下函数：

```java
        Predicate<Double> ourPredicate = new Predicate<Double>() {
          public boolean test(Double num) {
            System.out.println("Test if " + num + 
                               " is smaller than 20");
            return num < 20;
          }
        };
```

我们的实现的`boolean test(T t)`方法接受`Double`类型的值作为参数，并返回`boolean`类型的值，因此我们可以这样使用它：

```java
        System.out.println(ourPredicate.test(10.0) ? 
                           "10 is smaller" : "10 is bigger");
```

这将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/e7d9f55b-d73b-41f4-9142-39cfb2f4fe29.png)

1.  查看`java.util.function`包中的其他 39 个函数接口。请注意，它们是我们已经讨论过的四个接口的变体。这些变体是为以下原因而创建的：

+   +   为了通过显式使用`int`、`double`或`long`原始类型来避免自动装箱和拆箱而获得更好的性能

+   接受两个输入参数

+   更短的表示法

以下函数接口只是 39 个接口列表中的几个示例。

`IntFunction<R>`函数接口具有`R apply(int i)`抽象方法。它提供了更短的表示法（不带参数类型的泛型）并避免了自动装箱（通过将`int`原始类型定义为参数）。以下是其用法示例：

```java
        IntFunction<String> iFunc = new IntFunction<String>() {
          public String apply(int i) {
            return String.valueOf(i * 10);
          }
        };
        System.out.println(iFunc.apply(1));    //prints: 10
```

`BiFunction<T,U,R>`函数接口具有抽象方法`R apply(T,U)`。以下是其实现示例：

```java
        BiFunction<String, Integer, Double> biFunc = 
                         new BiFunction<String, Integer, Double >() {
           public Double apply(String s, Integer i) {
             return (s.length() * 10d) / i;
           }
        };
        System.out.println(biFunc.apply("abc", 2)); //prints: 15.0

```

`BinaryOperator<T>`函数接口具有一个抽象方法`T apply(T,T)`。它通过避免重复三次相同类型提供了更短的表示法。以下是其用法示例：

```java
       BinaryOperator<Integer> function = new BinaryOperator<Integer>(){
           public Integer apply(Integer i, Integer j) {
             return i >= j ? i : j;
           }
       };
        System.out.println(binfunc.apply(1, 2));     //prints: 2

```

`IntBinaryOperator`函数接口具有`int applyAsInt(int,int)`抽象方法。我们可以使用它来复制前面示例中的相同功能：

```java
        IntBinaryOperator intBiFunc = new IntBinaryOperator(){
            public int applyAsInt(int i, int j) {
                return i >= j ? i : j;
            }
        };
        System.out.println(intBiFunc.applyAsInt(1, 2)); //prints: 2
```

接下来的食谱将提供更多此类专业化用法示例。

# 它的工作原理...

我们可以仅使用函数来组成整个方法：

```java
void calculate(Supplier<Integer> source, 
  Function<Integer, Double> process, Predicate<Double> condition,
              Consumer<Double> success, Consumer<Double> failure){
    int i = source.get();
    double res = process.apply(i);
    if(condition.test(res)){
        success.accept(res);
    } else {
        failure.accept(res);
    }
}
```

前面的代码从源中获取值，处理它，然后根据提供的函数决定结果是否成功。现在，让我们创建这些函数并调用该方法。我们决定源参数如下：

```java
Supplier<Integer> source = new Supplier<Integer>() {
    public Integer get() {
        Integer res = 42;
        //Do something and return result value
        return res;
    }
};

```

在实际代码中，此函数可以从数据库或任何其他数据源中提取数据。我们保持简单——使用硬编码的返回值——以获得可预测的结果。

处理函数和谓词将保持与以前相同的方式：

```java
Function<Integer, Double> process = new Function<Integer, Double>(){
    public Double apply(Integer i){
        return i * 10.0;
    }
};
Predicate<Double> condition = new Predicate<Double>() {
    public boolean test(Double num) {
        System.out.println("Test if " + num + 
                                    " is smaller than " + 20);
        return num < 20;
    }
}; 
```

消费者几乎相同，只是在打印结果之前有不同的前缀：

```java
Consumer<Double> success = new Consumer<Double>() {
    public void accept(Double d) {
        System.out.println("Success: " + d);
    }
};
Consumer<Double> failure = new Consumer<Double>() {
    public void accept(Double d) {
        System.out.println("Failure: " + d);
    }
};

```

现在我们可以调用 calculate 方法，如下所示：

```java
calculate(source, process, condition, success, failure);

```

结果将如下所示：

```java
Test if 420.0 is smaller than 20.0
Failure: 420.0
```

如果我们需要快速测试源值和谓词条件的各种组合，我们可以创建`testSourceAndCondition(int src, int limit)`方法，如下所示：

```java
void testSourceAndCondition(int src, double condition) {
    Supplier<Integer> source = new Supplier<Integer>() {
        public Integer get() {
            Integer res = src;
            //Do something and return result value
            return res;
        }
    };
    Function<Integer, Double> process = 
      new Function<Integer, Double>() {
         public Double apply(Integer i){
            return i * 10.0;
         }
      };
    Predicate<Double> condition = new Predicate<Double>() {
        public boolean test(Double num) {
            System.out.println("Test if " + num + 
                                " is smaller than " + limit);
            return num < limit;
        }
    };
    Consumer<Double> success = new Consumer<Double>() {
        public void accept(Double d) {
            System.out.println("Success: " + d);
        }
    };
    Consumer<Double> failure = new Consumer<Double>() {
        public void accept(Double d) {
            System.out.println("Failure: " + d);
        }
    };
    calculate(source, process, cond, success, failure);
}
```

注意我们如何将`src`值传递给`source`供应商，将`limit`值传递给`condition`谓词。现在，我们可以运行`testSourceAndCondition(int src, int limit)`方法，使用不同的输入值寻找`src`值和`limit`值的组合，以获得成功：

```java
testSourceAndCondition(10, 20);
testSourceAndCondition(1, 20);
testSourceAndCondition(10, 200);

```

结果将如下所示：

```java
Test if 100.0 is smaller than 20.0
Failure: 100.0
Test if 10.0 is smaller than 20.0
Success: 10.0
Test if 100.0 is smaller than 200.0
Success: 100.0
```

# 还有更多...

`java.util.function`包中的许多函数接口都具有默认方法，不仅增强了它们的功能，还允许您将函数链接在一起，并将一个函数的结果作为输入参数传递给另一个函数。例如，我们可以使用`Function<T,V> andThen(Function<R,V> after)`接口的默认方法：

```java
Function<Integer, Double> before = new Function<Integer, Double>(){
    public Double apply(Integer i){
        return i * 10.0;
    }
};
Function<Double, Double> after = new Function<Double, Double>(){
    public Double apply(Double d){
        return d + 10.0;
    }
};
Function<Integer, Double> process = before.andThen(after);
```

如您所见，我们的`process`函数现在是我们原始函数（将源值乘以 10.0）和一个新函数`after`的组合，该函数将 10.0 添加到第一个函数的结果中。如果我们调用`testSourceAndCondition(int source, int condition)`方法，如`testSourceAndCondition(42, 20)`，结果将如下所示：

```java
Test if 430.0 is smaller than 20
Failure: 430.0
```

`Supplier<T>`接口没有允许我们链接多个函数的方法，但`Predicate<T>`接口有`and(Predicate<T> other)`和`or(Predicate<T> other)`默认方法，允许我们构造更复杂的布尔表达式。`Consumer<T>`接口也有`andThen(Consumer<T> after)`默认方法。

注意`after`函数的输入值类型必须与`before`函数的结果类型匹配：

```java
Function<T,R> before = ...
Function<R,V> after = ...
Function<T,V> result = before.andThen(after);
```

生成的函数接受`T`类型的值并产生`V`类型的值。

实现相同结果的另一种方法是使用`Function<V,R> compose(Function<V,T> before)`默认方法：

```java
Function<Integer, Double> process = after.compose(before);
```

要使用`andThen()`或`compose()`中的哪种方法取决于哪个函数可用于调用聚合方法。然后，一个被认为是基础，而另一个是参数。

如果这种编码看起来有点过度设计和复杂，那是因为确实如此。我们只是为了演示目的而这样做的。好消息是，下一个示例中介绍的 lambda 表达式可以让我们以更简洁和更清晰的方式实现相同的结果。

`java.util.function`包的函数接口还有其他有用的默认方法。其中一个突出的是`identity()`方法，它返回一个始终返回其输入参数的函数：

```java
Function<Integer, Integer> id = Function.identity();
System.out.println(id.apply(4));  //prints: 4
```

`identity()`方法在需要提供某个函数但不希望该函数修改结果时非常有用。

其他默认方法大多与转换、装箱、拆箱以及提取两个参数的最小值和最大值有关。我们鼓励您浏览`java.util.function`的所有函数接口的 API，并了解可能性。

# 创建函数接口

在本示例中，您将学习如何在`java.util.function`包中没有满足要求的标准接口时创建和使用自定义函数接口。

# 准备工作

创建函数接口很容易。只需确保接口中只有一个抽象方法，包括从其他接口继承的方法：

```java
@FunctionalInterface
interface A{
    void m1();
}

@FunctionalInterface
interface B extends A{
    default void m2(){};
}

//@FunctionalInterface
interface C extends B{
    void m3();
}
```

在前面的示例中，接口`C`不是函数接口，因为它有两个抽象方法-`m1()`，从接口`A`继承，以及它自己的方法`m3()`。

我们已经看到了`SpeedModel`函数接口：

```java
@FunctionalInterface
public interface SpeedModel {
  double getSpeedMph(double timeSec, int weightPounds, int horsePower);
}
```

我们已经对其进行了注释以表达意图，并在`SpeedModel`接口中添加另一个抽象方法时得到警告。为了简化，我们已将`enum`类从中删除。此接口用于`Vehicle`接口：

```java
public interface Vehicle {
    void setSpeedModel(SpeedModel speedModel);
    double getSpeedMph(double timeSec);
}
```

`Vehicle`实现需要它的原因是`SpeedModel`是计算速度功能的来源：

```java
public class VehicleImpl implements Vehicle {
    private SpeedModel speedModel;
    private int weightPounds, hoursePower;
    public VehicleImpl(int weightPounds, int hoursePower){
        this.weightPounds = weightPounds;
        this.hoursePower = hoursePower;
    }
    public void setSpeedModel(SpeedModel speedModel){
        this.speedModel = speedModel;
    }
    public double getSpeedMph(double timeSec){
        return this.speedModel.getSpeedMph(timeSec, 
                                 this.weightPounds, this.hoursePower);
    };
}
```

正如我们在第二章中提到的*OOP 快速通道-类和接口*，这种设计被称为聚合。这是组合所需行为的首选方式，因为它允许更灵活性。

使用函数接口，这种设计变得更加灵活。为了演示，让我们实现我们的自定义接口`SpeedModel`。

# 如何做...

传统的方法是创建一个实现`SpeedModel`接口的类：

```java
public class SpeedModelImpl implements SpeedModel {
   public double getSpeedMph(double timeSec, 
                       int weightPounds, int horsePower){
      double v = 2.0 * horsePower * 746 * 
                       timeSec * 32.17 / weightPounds;
      return (double) Math.round(Math.sqrt(v) * 0.68);
   }
}
```

然后，我们可以按以下方式使用此实现：

```java
Vehicle vehicle = new VehicleImpl(3000, 200);
SpeedModel speedModel = new SpeedModelImpl();
vehicle.setSpeedModel(speedModel);
System.out.println(vehicle.getSpeedMph(10.)); //prints: 122.0

```

要更改速度计算的方式，我们需要更改`SpeedModelImpl`类。

或者，利用`SpeedModel`是一个接口的事实，我们可以更快地引入更改，甚至避免首先拥有`SpeedModelImpl`类：

```java
Vehicle vehicle = new VehicleImpl(3000, 200);
SpeedModel speedModel = new SpeedModel(){
   public double getSpeedMph(double timeSec, 
                       int weightPounds, int horsePower){
      double v = 2.0 * horsePower * 746 * 
                       timeSec * 32.17 / weightPounds;
      return (double) Math.round(Math.sqrt(v) * 0.68);
   }
};
vehicle.setSpeedModel(speedModel);
System.out.println(vehicle.getSpeedMph(10.)); //prints: 122.0
```

然而，前面的实现没有利用接口是功能性的优势。如果我们注释掉注解，我们可以向`SpeedModel`接口添加另一个方法：

```java
//@FunctionalInterface
public interface SpeedModel {
    double getSpeedMph(double timeSec, 
                    int weightPounds, int horsePower);
    void m1();
}
Vehicle vehicle = new VehicleImpl(3000, 200);
SpeedModel speedModel = new SpeedModel(){
   public double getSpeedMph(double timeSec, 
                     int weightPounds, int horsePower){
      double v = 2.0 * horsePower * 746 * 
                       timeSec * 32.17 / weightPounds;
      return (double) Math.round(Math.sqrt(v) * 0.68);
   }
   public void m1(){}
   public void m2(){}
};
vehicle.setSpeedModel(speedModel);
System.out.println(vehicle.getSpeedMph(10.)); //prints: 122.0
```

从前面的代码中可以看出，不仅`SpeedModel`接口有另一个抽象方法`m1()`，而且匿名类还有另一个未在`SpeedModel`接口中列出的方法`m2()`。因此，匿名类不需要接口是功能性的。但是 lambda 表达式需要。

# 它是如何工作的...

使用 lambda 表达式，我们可以将前面的代码重写如下：

```java
Vehicle vehicle = new VehicleImpl(3000, 200);
SpeedModel speedModel =  (t, wp, hp) -> {
    double v = 2.0 * hp * 746 * t * 32.17 / wp;
    return (double) Math.round(Math.sqrt(v) * 0.68);
};
vehicle.setSpeedModel(speedModel);
System.out.println(vehicle.getSpeedMph(10.)); //prints: 122.0

```

我们将在下一个示例中讨论 lambda 表达式的格式。现在，我们只想指出功能接口对于前面的实现非常重要。正如您所看到的，只指定了接口的名称，没有任何方法名称。这是可能的，因为功能接口只有一个必须实现的方法，这就是 JVM 如何找出并在幕后生成功能接口实现的方式。

# 还有更多...

可以定义一个类似于标准功能接口的通用自定义功能接口。例如，我们可以创建以下自定义功能接口：

```java
@FunctionalInterface
interface Func<T1,T2,T3,R>{ 
   R apply(T1 t1, T2 t2, T3 t3);
}
```

它允许三个输入参数，这正是我们计算速度所需要的：

```java
Func<Double, Integer, Integer, Double> speedModel = (t, wp, hp) -> {
    double v = 2.0 * hp * 746 * t * 32.17 / wp;
    return (double) Math.round(Math.sqrt(v) * 0.68);
};

```

使用这个函数而不是`SpeedModel`接口，我们可以将`Vehicle`接口及其实现更改如下：

```java
interface Vehicle {
   void setSpeedModel(Func<Double, Integer, Integer, 
                                         Double> speedModel);
   double getSpeedMph(double timeSec);
}
class VehicleImpl  implements Vehicle {
   private Func<Double, Integer, Integer, Double> speedModel;
   private int weightPounds, hoursePower;
   public VehicleImpl(int weightPounds, int hoursePower){
       this.weightPounds = weightPounds;
       this.hoursePower = hoursePower;
   }
   public void setSpeedModel(Func<Double, Integer, 
                               Integer, Double> speedModel){
       this.speedModel = speedModel;
   }
   public double getSpeedMph(double timeSec){
       return this.speedModel.apply(timeSec, 
                             weightPounds, hoursePower);
   };
}
```

前面的代码产生了与`SpeedModel`接口相同的结果。

自定义接口的名称和其唯一方法的名称可以是我们喜欢的任何东西。例如：

```java
@FunctionalInterface
interface FourParamFunction<T1,T2,T3,R>{
     R caclulate(T1 t1, T2 t2, T3 t3);
}
```

既然我们无论如何都要创建一个新接口，使用`SpeedModel`名称和`getSpeedMph()`方法名称可能是更好的解决方案，因为这样可以使代码更易读。但是在某些情况下，通用自定义功能接口是更好的选择。在这种情况下，您可以使用前面的定义，并根据需要进行增强。

# 理解 lambda 表达式

我们已经多次提到 lambda 表达式，并指出它们在 Java 中的使用证明了在`java.util.function`包中引入功能接口的必要性。lambda 表达式允许我们通过删除匿名类的所有样板代码来简化函数实现，只留下最少必要的信息。我们还解释了这种简化是可能的，因为功能接口只有一个抽象方法，所以编译器和 JVM 将提供的功能与方法签名进行匹配，并在幕后生成功能接口实现。

现在，是时候定义 lambda 表达式语法并查看 lambda 表达式的可能形式范围了，在我们开始使用它们使我们的代码比使用匿名类时更短更易读之前。

# 准备工作

在 20 世纪 30 年代，数学家阿隆佐·邱奇在研究数学基础时引入了 lambda 演算——一种通用的计算模型，可以用来模拟任何图灵机。那个时候，图灵机还没有被创建。只有后来，当艾伦·图灵发明了他的*a-机器*（自动机），也称为*通用图灵机*时，他和邱奇联手提出了一个邱奇-图灵论题，表明 lambda 演算和图灵机具有非常相似的能力。

Church 使用希腊字母*lambda*来描述匿名函数，它成为了编程语言理论领域的非官方符号。第一个利用 lambda 演算形式的编程语言是 Lisp。Java 在 2014 年发布 Java 8 时添加了函数式编程能力。

lambda 表达式是一个允许我们省略修饰符、返回类型和参数类型的匿名方法。这使得它非常紧凑。lambda 表达式的语法包括参数列表、箭头标记(`->`)和主体。参数列表可以为空（只有括号，`()`），没有括号（如果只有一个参数），或者由括号括起来的逗号分隔的参数列表。主体可以是一个没有括号的单个表达式，也可以是由括号括起来的语句块。

# 如何做到...

让我们看一些例子。以下 lambda 表达式没有输入参数，总是返回`33`：

```java
() -> 33;
```

以下 lambda 表达式接受一个整数类型的参数，将其增加 1，并返回结果：

```java
i -> i++;
```

以下 lambda 表达式接受两个参数并返回它们的和：

```java
(a, b) -> a + b;
```

以下 lambda 表达式接受两个参数，比较它们，并返回`boolean`结果：

```java
(a, b) -> a == b;
```

最后一个 lambda 表达式接受两个参数，计算并打印结果：

```java
(a, b) -> { 
     double c = a +  Math.sqrt(b); 
     System.out.println("Result: " + c);
}
```

正如你所看到的，lambda 表达式可以包含任意大小的代码块，类似于任何方法。前面的例子没有返回任何值。这里是另一个返回`String`值的代码块的例子：

```java
(a, b) -> { 
     double c = a +  Math.sqrt(b); 
     return c > 10.0 ? "Success" : "Failure";
}
```

# 它是如何工作的...

让我们再次看看最后一个例子。如果在*functional*接口`A`中定义了一个`String m1(double x, double y)`方法，并且有一个接受`A`类型对象的`m2(A a)`方法，我们可以这样调用它：

```java
A a = (a, b) -> { 
     double c = a +  Math.sqrt(b); 
     return c > 10.0 ? "Success" : "Failure";
}
m2(a);
```

前面的代码意味着传入的对象有以下`m1()`方法的实现：

```java
public String m1(double x, double y){
     double c = a +  Math.sqrt(b); 
     return c > 10.0 ? "Success" : "Failure";
}
```

`m2(A a)`有`A`对象作为参数告诉我们，`m2(A a)`的代码可能使用了`A`接口的至少一个方法（`A`接口中也可能有默认或静态方法）。但是，一般来说，不能保证方法使用了传入的对象，因为程序员可能决定停止使用它，但保持签名不变，以避免破坏客户端代码，例如。

然而，客户端必须传入实现`A`接口的对象到方法中，这意味着它的唯一抽象方法必须被实现。这就是 lambda 表达式所做的事情。它使用最少的代码定义抽象方法的功能——输入参数列表和方法实现的代码块。这就是编译器和 JVM 生成实现所需的一切。

编写这样紧凑和高效的代码成为可能，是因为 lambda 表达式和函数接口的结合。

# 还有更多...

与匿名类一样，外部创建但在 lambda 表达式内部使用的变量实际上是最终的，不能被修改。你可以写下以下代码：

```java
double v = 10d;
Function<Integer, Double> multiplyBy10 = i -> i * v;
```

然而，你不能在 lambda 表达式外部改变`v`变量的值：

```java
double v = 10d;
v = 30d; //Causes compiler error
Function<Integer, Double> multiplyBy10 = i -> i * v;
```

你也不能在表达式内部改变它：

```java
double v = 10d;
Function<Integer, Double> multiplyBy10 = i -> {
  v = 30d; //Causes compiler error
  return i * v;
};

```

这种限制的原因是一个函数可以在不同的上下文（例如不同的线程）中传递和执行不同的参数，试图同步这些上下文会破坏函数的分布式评估的原始想法。

另一个值得一提的 lambda 表达式特性是它对`this`关键字的解释，这与匿名类的解释有很大不同。在匿名类内部，`this`指的是匿名类的实例，但在 lambda 表达式内部，`this`指的是包围表达式的类的实例。让我们来演示一下，假设我们有以下类：

```java
class Demo{
    private String prop = "DemoProperty";
    public void method(){
        Consumer<String> consumer = s -> {
            System.out.println("Lambda accept(" + s 
                                      + "): this.prop=" + this.prop);
        };
        consumer.accept(this.prop);
        consumer = new Consumer<>() {
            private String prop = "ConsumerProperty";
            public void accept(String s) {
                System.out.println("Anonymous accept(" + s 
                                      + "): this.prop=" + this.prop);
            }
        };
        consumer.accept(this.prop);
    }
}
```

正如你所看到的，在`method()`代码中，`Consumer`函数接口被实现了两次——使用 lambda 表达式和使用匿名类。让我们在以下代码中调用这个方法：

```java
  Demo d = new Demo();
  d.method();
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/324ceaa7-1714-4153-bd7a-43ae67258283.png)

Lambda 表达式不是内部类，也不能被`this`引用。Lambda 表达式没有字段或属性。它是无状态的。这就是为什么在 lambda 表达式中，`this`关键字指的是周围的上下文。这也是 lambda 表达式要求周围上下文中的所有变量必须是 final 或有效 final 的另一个原因。

# 使用 lambda 表达式

在这个示例中，你将学习如何在实践中使用 lambda 表达式。

# 准备工作

创建和使用 lambda 表达式实际上比编写方法简单得多。只需要列出输入参数（如果有的话），以及执行所需操作的代码。

让我们重新审视本章第一个示例中标准功能接口的实现，并使用 lambda 表达式重写它们。以下是我们使用匿名类实现了四个主要功能接口的方式：

```java
Function<Integer, Double> ourFunc = new Function<Integer, Double>(){
    public Double apply(Integer i){
        return i * 10.0;
    }
};
System.out.println(ourFunc.apply(1));       //prints: 10.0
Consumer<String> consumer = new Consumer<String>() {
    public void accept(String s) {
        System.out.println("The " + s + " is consumed.");
    }
};
consumer.accept("Hello!"); //prints: The Hello! is consumed.
Supplier<String> supplier = new Supplier<String>() {
    public String get() {
        String res = "Success";
        //Do something and return result—Success or Error.
        return res;
    }
};
System.out.println(supplier.get());      //prints: Success
Predicate<Double> pred = new Predicate<Double>() {
    public boolean test(Double num) {
       System.out.println("Test if " + num + " is smaller than 20");
       return num < 20;
    }
};
System.out.println(pred.test(10.0)? "10 is smaller":"10 is bigger");
                           //prints: Test if 10.0 is smaller than 20
                           //        10 is smaller

```

以下是使用 lambda 表达式的样子：

```java
Function<Integer, Double> ourFunc = i -> i * 10.0;
System.out.println(ourFunc.apply(1)); //prints: 10.0

Consumer<String> consumer = 
            s -> System.out.println("The " + s + " is consumed.");
consumer.accept("Hello!");       //prints: The Hello! is consumed.

Supplier<String> supplier = () - > {
        String res = "Success";
        //Do something and return result—Success or Error.
        return res;
    };
System.out.println(supplier.get());  //prints: Success

Predicate<Double> pred = num -> {
   System.out.println("Test if " + num + " is smaller than 20");
   return num < 20;
};
System.out.println(pred.test(10.0)? "10 is smaller":"10 is bigger");
                          //prints: Test if 10.0 is smaller than 20
                          //        10 is smaller
```

我们提供的专门功能接口示例如下：

```java
IntFunction<String> ifunc = new IntFunction<String>() {
    public String apply(int i) {
        return String.valueOf(i * 10);
    }
};
System.out.println(ifunc.apply(1));   //prints: 10
BiFunction<String, Integer, Double> bifunc =
        new BiFunction<String, Integer, Double >() {
            public Double apply(String s, Integer i) {
                return (s.length() * 10d) / i;
            }
        };

System.out.println(bifunc.apply("abc",2));     //prints: 15.0
BinaryOperator<Integer> binfunc = new BinaryOperator<Integer>(){
    public Integer apply(Integer i, Integer j) {
        return i >= j ? i : j;
    }
};
System.out.println(binfunc.apply(1,2));  //prints: 2
IntBinaryOperator intBiFunc = new IntBinaryOperator(){
    public int applyAsInt(int i, int j) {
        return i >= j ? i : j;
    }
};
System.out.println(intBiFunc.applyAsInt(1,2)); //prints: 2

```

以下是使用 lambda 表达式的样子：

```java
IntFunction<String> ifunc = i -> String.valueOf(i * 10);
System.out.println(ifunc.apply(1));             //prints: 10

BiFunction<String, Integer, Double> bifunc = 
                            (s,i) -> (s.length() * 10d) / i;
System.out.println(bifunc.apply("abc",2));      //prints: 15.0

BinaryOperator<Integer> binfunc = (i,j) -> i >= j ? i : j;
System.out.println(binfunc.apply(1,2));         //prints: 2

IntBinaryOperator intBiFunc = (i,j) -> i >= j ? i : j;
System.out.println(intBiFunc.applyAsInt(1,2));  //prints: 2
```

正如你所看到的，代码更简洁，更易读。

# 如何做...

那些有一些传统代码编写经验的人，在开始进行函数式编程时，将函数等同于方法。他们首先尝试创建函数，因为这是我们以前编写传统代码的方式——通过创建方法。然而，在函数式编程中，方法继续提供代码结构，而函数则是它的良好和有用的补充。因此，在函数式编程中，首先创建方法，然后再定义函数。让我们来演示一下。

以下是代码编写的基本步骤。首先，我们确定可以作为方法实现的精心设计的代码块。然后，在我们知道新方法将要做什么之后，我们可以将其功能的一些部分转换为函数：

1.  创建`calculate()`方法：

```java
void calculate(){
    int i = 42;        //get a number from some source
    double res = 42.0; //process the above number 
    if(res < 42){ //check the result using some criteria
        //do something
    } else {
        //do something else
    }
}
```

上述伪代码概述了`calculate()`方法的功能。它可以以传统方式实现——通过使用方法，如下所示：

```java
int getInput(){
   int result;
   //getting value for result variable here
   return result;
}
double process(int i){
    double result;
    //process input i and assign value to result variable
}
boolean checkResult(double res){
    boolean result = false;
    //use some criteria to validate res value
    //and assign value to result
    return result;
}
void processSuccess(double res){
     //do something with res value
}
void processFailure(double res){
     //do something else with res value
}
void calculate(){
    int i = getInput();
    double res = process(i); 
    if(checkResult(res)){     
        processSuccess(res);
    } else {
        processFailure(res);
    }
}
```

但是其中一些方法可能非常小，因此代码变得分散，使用这么多额外的间接会使代码变得不太可读。这个缺点在方法来自实现`calculate()`方法的类外部的情况下尤为明显：

```java
void calculate(){
    SomeClass1 sc1 = new SomeClass1();
    int i = sc1.getInput();
    SomeClass2 sc2 = new SomeClass2();
    double res = sc2.process(i); 
    SomeClass3 sc3 = new SomeClass3();
    SomeClass4 sc4 = new SomeClass4();
    if(sc3.checkResult(res)){     
        sc4.processSuccess(res);
    } else {
        sc4.processFailure(res);
    }
}
```

正如你所看到的，在每个外部方法都很小的情况下，管道代码的数量可能大大超过它所支持的负载。此外，上述实现在类之间创建了许多紧密的依赖关系。

1.  让我们看看如何使用函数来实现相同的功能。优势在于函数可以尽可能小，但是管道代码永远不会超过负载，因为没有管道代码。使用函数的另一个原因是，当我们需要灵活地在算法研究目的上更改功能的部分时。如果这些功能部分需要来自类外部，我们不需要为了将方法传递给`calculate()`而构建其他类。我们可以将它们作为函数传递：

```java
void calculate(Supplier<Integer> souc e, Function<Integer,
             Double> process, Predicate<Double> condition,
      Consumer<Double> success, Consumer<Double> failure){
    int i = source.get();
    double res = process.apply(i);
    if(condition.test(res)){
        success.accept(res);
    } else {
        failure.accept(res);
    }
} 
```

1.  以下是函数可能的样子：

```java
Supplier<Integer> source = () -> 4;
Function<Integer, Double> before = i -> i * 10.0;
Function<Double, Double> after = d -> d + 10.0;
Function<Integer, Double> process = before.andThen(after);
Predicate<Double> condition = num -> num < 100;
Consumer<Double> success = 
                  d -> System.out.println("Success: "+ d);
Consumer<Double> failure = 
                  d -> System.out.println("Failure: "+ d);
calculate(source, process, condition, success, failure);
```

上述代码的结果将如下：

```java
Success: 50.0
```

# 它是如何工作的...

Lambda 表达式就像一个普通的方法，除了当你考虑单独测试每个函数时。如何做呢？

有两种方法来解决这个问题。首先，由于函数通常很小，通常不需要单独测试它们，它们在使用它们的代码测试时间接测试。其次，如果您仍然认为函数必须进行测试，总是可以将其包装在返回函数的方法中，这样您就可以像测试其他方法一样测试该方法。以下是如何做的一个例子：

```java
public class Demo {
  Supplier<Integer> source(){ return () -> 4;}
  Function<Double, Double> after(){ return d -> d + 10.0; }
  Function<Integer, Double> before(){return i -> i * 10.0; }
  Function<Integer, Double> process(){return before().andThen(after());}
  Predicate<Double> condition(){ return num -> num < 100.; }
  Consumer<Double> success(){ 
     return d -> System.out.println("Failure: " + d); }
  Consumer<Double> failure(){ 
     return d-> System.out.println("Failure: " + d); }
  void calculate(Supplier<Integer> souce, Function<Integer,
              Double> process, Predicate<Double> condition,
       Consumer<Double> success, Consumer<Double> failure){
    int i = source.get();
    double res = process.apply(i);
    if(condition.test(res)){
        success.accept(res);
    } else {
        failure.accept(res);
    }
}
void someOtherMethod() {
   calculate(source(), process(), 
                       condition(), success(), failure());
}
```

现在我们可以编写函数单元测试如下：

```java
public class DemoTest {

    @Test
    public void source() {
        int i = new Demo().source().get();
        assertEquals(4, i);
    }
    @Test
    public void after() {
        double d = new Demo().after().apply(1.);
        assertEquals(11., d, 0.01);
    }
    @Test
    public void before() {
        double d = new Demo().before().apply(10);
        assertEquals(100., d, 0.01);
    }
    @Test
    public void process() {
        double d = new Demo().process().apply(1);
        assertEquals(20., d, 0.01);
    }
    @Test
    public void condition() {
        boolean b = new Demo().condition().test(10.);
        assertTrue(b);
    }
}
```

通常，lambda 表达式（以及一般的函数）用于为通用功能添加业务逻辑，从而实现特定功能。一个很好的例子是流操作，我们将在第五章《流和管道》中讨论。库的作者已经创建了它们以便能够并行工作，这需要很多专业知识。现在库的用户可以通过传递 lambda 表达式（函数）来专门定制操作，从而提供应用程序的业务逻辑。

# 还有更多...

由于，正如我们已经提到的，函数通常是简单的一行代码，当作为参数传递时通常会内联，例如：

```java
Consumer<Double> success = d -> System.out.println("Success: " + d);
Consumer<Double> failure = d-> System.out.println("Failure: " + d);
calculate(() -> 4, i -> i * 10.0 + 10, n -> n < 100, success, failure);
```

但是，不要过分推动，因为这样的内联可能会降低代码的可读性。

# 使用方法引用

在这个示例中，您将学习如何使用方法引用，构造函数引用是其中的一种情况。

# 准备工作

当一行 lambda 表达式只包含对其他地方实现的现有方法的引用时，可以进一步简化 lambda 表示法，使用方法引用。

方法引用的语法是`Location::methodName`，其中`Location`表示`methodName`方法所在的位置（对象或类）。两个冒号(`::`)作为位置和方法名之间的分隔符。如果在指定的位置有多个同名方法（因为方法重载），则引用方法由 lambda 表达式实现的函数接口的抽象方法的签名来确定。

# 如何做...

方法引用的确切格式取决于所引用的方法是静态的还是非静态的。方法引用也可以是*绑定的*或*未绑定的*，或者更正式地说，方法引用可以有*绑定的接收者*或*未绑定的接收者*。接收者是用于调用方法的对象或类。它*接收*调用。它可以绑定到特定的上下文或不绑定。我们将在演示过程中解释这意味着什么。

方法引用也可以引用带参数或不带参数的构造函数。

请注意，方法引用仅适用于表达式只包含一个方法调用而没有其他内容的情况。例如，方法引用可以应用于`() -> SomeClass.getCount()` lambda 表达式。它看起来像`SomeClass::getCount`。但是表达式`() -> 5 + SomeClass.getCount()`不能用方法引用替换，因为这个表达式中有比方法调用更多的操作。

# 静态未绑定方法引用

为了演示静态方法引用，我们将使用`Food`类和两个静态方法：

```java
class Food{
    public static String getFavorite(){ return "Donut!"; }
    public static String getFavorite(int num){
        return num > 1 ? String.valueOf(num) + " donuts!" : "Donut!";
    }
}
```

由于第一个方法`String getFavorite()`不接受任何输入参数并返回一个值，它可以作为一个函数接口`Supplier<T>`来实现。实现调用`String getFavorite()`静态方法的 lambda 表达式如下：

```java
Supplier<String> supplier = () -> Food.getFavorite();
```

使用方法引用，前面的行变成了以下内容：

```java
Supplier<String> supplier = Food::getFavorite;
```

正如您所看到的，前面的格式定义了方法的位置（作为`Food`类），方法的名称和返回类型的值（作为`String`）。函数接口的名称表示没有输入参数，因此编译器和 JVM 可以在`Food`类的方法中识别该方法。

静态方法引用是未绑定的，因为没有对象用于调用该方法。在静态方法的情况下，类是调用接收器，而不是对象。

第二个静态方法`String getFavorite(int num)`接受一个参数并返回一个值。这意味着我们可以使用`Function<T,R>`函数接口来实现仅调用此方法的函数：

```java
Function<Integer, String> func = i -> Food.getFavorite(i); 
```

但是当使用方法引用时，它会变成与前面示例完全相同的形式：

```java
Function<Integer, String> func = Food::getFavorite; 
```

区别在于指定的函数接口。它允许编译器和 Java 运行时识别要使用的方法：方法名为`getFavorite()`，接受`Integer`值，并返回`String`值。`Food`类中只有一个这样的方法。实际上，甚至不需要查看方法返回的值，因为仅通过返回值无法重载方法。方法的签名——名称和参数类型列表——足以标识方法。

我们可以按以下方式使用实现的函数：

```java
Supplier<String> supplier = Food::getFavorite;
System.out.println("supplier.get() => " + supplier.get());

Function<Integer, String> func = Food::getFavorite;
System.out.println("func.getFavorite(1) => " + func.apply(1));
System.out.println("func.getFavorite(2) => " + func.apply(2));
```

如果运行上述代码，结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/b59f41b3-3172-45ff-b858-7967323967de.png)

# 非静态绑定方法引用

为了演示非静态绑定方法引用，让我们通过添加`name`字段、两个构造函数和两个`String sayFavorite()`方法来增强`Food`类：

```java
class Food{
     private String name;
     public Food(){ this.name = "Donut"; }
     public Food(String name){ this.name = name; }
     public static String getFavorite(){ return "Donut!"; }
     public static String getFavorite(int num){
         return num > 1 ? String.valueOf(num) + " donuts!" : "Donut!";
     }
     public String sayFavorite(){
         return this.name + (this.name.toLowerCase()
                             .contains("donut")?"? Yes!" : "? D'oh!");
     }
     public String sayFavorite(String name){
         this.name = this.name + " and " + name;
         return sayFavorite();
     }
}
```

现在，让我们创建`Food`类的三个实例：

```java
Food food1 = new Food();
Food food2 = new Food("Carrot");
Food food3 = new Food("Carrot and Broccoli");
```

上述是上下文——我们将要创建的 lambda 表达式周围的代码。我们使用前面上下文的局部变量来实现三个不同的供应商：

```java
Supplier<String> supplier1 = () -> food1.sayFavorite();
Supplier<String> supplier2 = () -> food2.sayFavorite();
Supplier<String> supplier3 = () -> food3.sayFavorite();
```

我们使用`Supplier<T>`，因为`String sayFavorite()`方法不需要任何参数，只产生（提供）`String`值。使用方法引用，我们可以将前面的 lambda 表达式重写如下：

```java
Supplier<String> supplier1 = food1::sayFavorite;
Supplier<String> supplier2 = food2::sayFavorite;
Supplier<String> supplier3 = food3::sayFavorite;
```

方法`sayFavorite()`属于在特定上下文中创建的对象。换句话说，这个对象（调用接收器）绑定到特定的上下文，这就是为什么这样的方法引用被称为*绑定方法引用*或*绑定接收器方法引用*。

我们可以将新创建的函数作为任何其他对象传递，并在需要的任何地方使用它们，例如：

```java
System.out.println("new Food().sayFavorite() => " + supplier1.get());
System.out.println("new Food(Carrot).sayFavorite() => " 
                                                  + supplier2.get());
System.out.println("new Food(Carrot,Broccoli).sayFavorite() => " 
                                                  + supplier3.get());
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/8cf07e4c-f18c-4df7-8b95-20f98446228f.png)

请注意，接收器仍然绑定到上下文，因此其状态可能会改变并影响输出。这就是*绑定*的区别的重要性。使用这样的引用时，必须小心不要在其原始上下文中更改接收器的状态。否则，可能会导致不可预测的结果。在并行处理时，同一函数可以在不同的上下文中使用，这一考虑尤为重要。

让我们看看使用第二个非静态方法`String sayFavorite(String name)`的绑定方法引用的另一个案例。首先，我们使用相同的`Food`类的对象创建了一个`UnaryOperator<T>`函数接口的实现，这与前面的示例中使用的相同：

```java
UnaryOperator<String> op1 = s -> food1.sayFavorite(s);
UnaryOperator<String> op2 = s -> food2.sayFavorite(s);
UnaryOperator<String> op3 = s -> food3.sayFavorite(s);

```

我们使用`UnaryOperator<T>`函数接口的原因是，`String sayFavorite(String name)`方法接受一个参数并产生相同类型的值。这就是它们名称中带有`Operator`的函数接口的目的——支持输入值和结果类型相同的情况。

方法引用允许我们将 lambda 表达式更改如下：

```java
UnaryOperator<String> op1 = food1::sayFavorite;
UnaryOperator<String> op2 = food2::sayFavorite;
UnaryOperator<String> op3 = food3::sayFavorite;
```

现在我们可以在代码的任何地方使用前面的函数（操作符），例如：

```java
System.out.println("new Food()
       .sayFavorite(Carrot) => " + op1.apply("Carrot"));
System.out.println("new Food(Carrot)
   .sayFavorite(Broccoli) => " + op2.apply("Broccoli"));
System.out.println("new Food(Carrot, Broccoli)
       .sayFavorite(Donuts) => " + op3.apply("Donuts"));
```

上述代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/f873fc74-fbd0-4b23-bde2-85d3643d2469.png)

# 非静态未绑定方法引用

为了演示对`String sayFavorite()`方法的非绑定方法引用，我们将使用`Function<T,R>`函数接口，因为我们希望使用`Food`类的对象（调用接收器）作为参数，并返回一个`String`值：

```java
Function<Food, String> func = f -> f.sayFavorite();

```

方法引用允许我们将前面的 lambda 表达式重写为以下形式：

```java
Function<Food, String> func = Food::sayFavorite;
```

使用在前面的例子中创建的`Food`类的相同对象，我们在以下代码中使用新创建的函数，例如：

```java
System.out.println("new Food()
              .sayFavorite() => " + func.apply(food1));
System.out.println("new Food(Carrot)
              .sayFavorite() => " + func.apply(food2));
System.out.println("new Food(Carrot, Broccoli)
              .sayFavorite() => " + func.apply(food3));
```

正如您所看到的，参数（调用接收对象）仅来自当前上下文，就像任何参数一样。无论函数传递到哪里，它都不携带上下文。它的接收器不绑定到用于函数创建的上下文。这就是为什么这个方法引用被称为*未绑定*的原因。

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/3dda0849-946f-42dd-a499-97cd5b6628aa.png)

为了演示未绑定方法引用的另一个案例，我们将使用第二个方法`String sayFavorite(String name)`，并使用一直使用的`Food`对象。我们要实现的功能接口这次叫做`BiFunction<T,U,R>`：

```java
BiFunction<Food, String, String> func = (f,s) -> f.sayFavorite(s);
```

我们选择这个功能接口的原因是它接受两个参数——这正是我们在这种情况下需要的——以便将接收对象和`String`值作为参数。前面 lambda 表达式的方法引用版本如下所示：

```java
BiFunction<Food, String, String> func = Food::sayFavorite;

```

我们可以通过编写以下代码来使用前面的函数，例如：

```java
System.out.println("new Food()
  .sayFavorite(Carrot) => " + func.apply(food1, "Carrot"));
System.out.println("new Food(Carrot)
  .sayFavorite(Broccoli) => " 
                         + func2.apply(food2, "Broccoli"));
System.out.println("new Food(Carrot,Broccoli)
  .sayFavorite(Donuts) => " + func2.apply(food3,"Donuts"));

```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/ce301b7b-80bd-49e0-afb6-7b4b0e72e77e.png)

# 构造函数方法引用

使用构造函数的方法引用与静态方法引用非常相似，因为它使用类作为调用接收器，而不是对象（它尚未被创建）。这是实现`Supplier<T>`接口的 lambda 表达式：

```java
Supplier<Food> foodSupplier = () -> new Food();

```

以下是它的方法引用版本：

```java
Supplier<Food> foodSupplier = Food::new;
System.out.println("new Food()
  .sayFavorite() => " + foodSupplier.get().sayFavorite());
```

如果我们运行前面的代码，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/34b6cfe4-9407-41fb-81a5-f23f2f307e52.png)

现在，让我们向`Food`类添加另一个构造函数：

```java
public Food(String name){ 
     this.name = name; 
} 
```

一旦我们这样做，我们可以通过方法引用来表示前面的构造函数：

```java
Function<String, Food> createFood = Food::new;
Food food = createFood.apply("Donuts");
System.out.println("new Food(Donuts).sayFavorite() => " 
                                   + food.sayFavorite());
food = createFood.apply("Carrot");
System.out.println("new Food(Carrot).sayFavorite() => " 
                                   + food.sayFavorite());
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/882157fe-d4e8-4439-ba19-cc505020fbf8.png)

同样地，我们可以添加一个带有两个参数的构造函数：

```java
public Food(String name, String anotherName) {
     this.name = name + " and " + anotherName;
}
```

一旦我们这样做，我们可以通过`BiFunction<String, String>`来表示它：

```java
BiFunction<String, String, Food> createFood = Food::new;
Food food = createFood.apply("Donuts", "Carrots");
System.out.println("new Food(Donuts, Carrot)
        .sayFavorite() => " + food.sayFavorite());
food = constrFood2.apply("Carrot", "Broccoli");
System.out.println("new Food(Carrot, Broccoli)
          .sayFavorite() => " food.sayFavorite());
```

前面的代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/981b14a2-265d-4fe6-a524-5785d675f49a.png)

为了表示接受多于两个参数的构造函数，我们可以创建一个自定义的功能接口，带有任意数量的参数。例如，我们可以使用前面一篇文章中讨论的以下自定义功能接口：

```java
        @FunctionalInterface
        interface Func<T1,T2,T3,R>{ R apply(T1 t1, T2 t2, T3 t3);}
```

假设我们需要使用`AClass`类：

```java
class AClass{
    public AClass(int i, double d, String s){ }
    public String get(int i, double d){ return ""; }
    public String get(int i, double d, String s){ return ""; }
}
```

我们可以通过使用方法引用来编写以下代码：

```java
Func<Integer, Double, String, AClass> func1 = AClass::new;
AClass obj = func1.apply(1, 2d, "abc");

Func<Integer, Double, String, String> func2 = obj::get;    //bound
String res1 = func2.apply(42, 42., "42");

Func<AClass, Integer, Double, String> func3 = AClass::get; //unbound
String res21 = func3.apply(obj, 42, 42.);

func1 function that allows us to create an object of class AClass. The func2 function applies to the resulting object obj the method String get(int i, double d) using the bound method reference because its call receiver (object obj) comes from a particular context (bound to it). By contrast, the func3 function is implemented as an unbound method reference because it gets its call receiver (class AClass) not from a context. 
```

# 还有更多...

有几个简单但非常有用的方法引用，因为它得到了通常在实践中使用的调用接收器：

```java
Function<String, Integer> strLength = String::length;
System.out.println(strLength.apply("3"));  //prints: 1

Function<String, Integer> parseInt = Integer::parseInt;
System.out.println(parseInt.apply("3"));    //prints: 3

Consumer<String> consumer = System.out::println;
consumer.accept("Hello!");             //prints: Hello!
```

还有一些用于处理数组和列表的有用方法：

```java
Function<Integer, String[]> createArray = String[]::new;
String[] arr = createArray.apply(3);
System.out.println("Array length=" + arr.length); 

int i = 0;
for(String s: arr){ arr[i++] = String.valueOf(i); }
Function<String[], List<String>> toList = Arrays::<String>asList;
List<String> l = toList.apply(arr);
System.out.println("List size=" + l.size());
for(String s: l){ System.out.println(s); }
```

以下是前面代码的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/dda4ac9d-511a-44dd-918d-7d48e26f2c87.png)

让我们由你来分析前面的 lambda 表达式是如何创建和使用的。

# 利用 lambda 表达式在您的程序中

在这个示例中，您将学习如何将 lambda 表达式应用到您的代码中。我们将回到演示应用程序，并通过引入 lambda 表达式来修改它。

# 准备工作

配备了功能接口、lambda 表达式和友好的 lambda API 设计最佳实践，我们可以通过使其设计更加灵活和用户友好来大大改进我们的速度计算应用程序。让我们尽可能接近真实问题的背景，而不要使它过于复杂。

无人驾驶汽车如今成为新闻头条，有充分的理由相信它将在相当长的一段时间内保持这种状态。在这个领域的任务之一是基于真实数据对城市区域的交通流进行分析和建模。这样的数据已经存在很多，并且将继续在未来被收集。假设我们可以通过日期、时间和地理位置访问这样的数据库。还假设来自该数据库的交通数据以单位形式存在，每个单位捕捉有关一个车辆和驾驶条件的详细信息：

```java
public interface TrafficUnit {
  VehicleType getVehicleType();
  int getHorsePower();
  int getWeightPounds();
  int getPayloadPounds();
  int getPassengersCount();
  double getSpeedLimitMph();
  double getTraction();
  RoadCondition getRoadCondition();
  TireCondition getTireCondition();
  int getTemperature();
} 
```

`enum`类型——`VehicleType`、`RoadCondition`和`TireCondition`——已经在第二章中构建，*OOP 快速通道-类和接口*：

```java
enum VehicleType { 
  CAR("Car"), TRUCK("Truck"), CAB_CREW("CabCrew");
  private String type;
  VehicleType(String type){ this.type = type; }
  public String getType(){ return this.type;}
}
enum RoadCondition {
  DRY(1.0), 
  WET(0.2) { public double getTraction() { 
    return temperature > 60 ? 0.4 : 0.2; } }, 
  SNOW(0.04);
  public static int temperature;
  private double traction;
  RoadCondition(double traction){ this.traction = traction; }
  public double getTraction(){return this.traction;}
}
enum TireCondition {
  NEW(1.0), WORN(0.2);
  private double traction;
  TireCondition(double traction){ this.traction = traction; }
  public double getTraction(){ return this.traction;}
}

```

访问交通数据的接口可能如下所示：

```java
TrafficUnit getOneUnit(Month month, DayOfWeek dayOfWeek, 
                       int hour, String country, String city, 
                       String trafficLight);
List<TrafficUnit> generateTraffic(int trafficUnitsNumber, 
                  Month month, DayOfWeek dayOfWeek, int hour,
                  String country, String city, String trafficLight);
```

以下是访问前述方法的示例：

```java
TrafficUnit trafficUnit = FactoryTraffic.getOneUnit(Month.APRIL, 
               DayOfWeek.FRIDAY, 17, "USA", "Denver", "Main103S");
```

数字`17`是一天中的小时（下午 5 点），`Main1035`是交通灯的标识。

对第二个方法的调用返回多个结果：

```java
List<TrafficUnit> trafficUnits = 
    FactoryTrafficModel.generateTraffic(20, Month.APRIL, 
        DayOfWeek.FRIDAY, 17, "USA", "Denver", "Main103S");
```

第一个参数`20`是请求的交通单位数。

如您所见，这样的交通工厂提供了关于特定时间（在我们的示例中为下午 5 点至 6 点之间）特定地点的交通数据。每次调用工厂都会产生不同的结果，而交通单位列表描述了统计上正确的数据（包括指定位置的最可能天气条件）。

我们还将更改`FactoryVehicle`和`FactorySpeedModel`的接口，以便它们可以基于`TrafficUnit`接口构建`Vehicle`和`SpeedModel`。结果演示代码如下：

```java
double timeSec = 10.0;
TrafficUnit trafficUnit = FactoryTraffic.getOneUnit(Month.APRIL, 
              DayOfWeek.FRIDAY, 17, "USA", "Denver", "Main103S");
Vehicle vehicle = FactoryVehicle.build(trafficUnit);
SpeedModel speedModel =  
               FactorySpeedModel.generateSpeedModel(trafficUnit);
vehicle.setSpeedModel(speedModel);
printResult(trafficUnit, timeSec, vehicle.getSpeedMph(timeSec));
```

`printResult()`方法包含以下代码：

```java
void printResult(TrafficUnit tu, double timeSec, double speedMph){
   System.out.println("Road " + tu.getRoadCondition()
                 + ", tires " + tu.getTireCondition() + ": " 
                              + tu.getVehicleType().getType() 
                              + " speedMph (" + timeSec + " sec)=" 
                                              + speedMph + " mph");
}
```

此代码的输出可能如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/51e23141-3a9a-4765-9790-3e73337b7c89.png)

由于我们现在使用“真实”数据，因此该程序的每次运行都会产生不同的结果，这取决于数据的统计特性。在某个地点，汽车或干燥天气可能更常出现在该日期和时间，而在另一个地点，卡车或雪更典型。

在这次运行中，交通单位带来了湿地面、新轮胎和`Truck`，具有这样的发动机功率和负载，以至于在 10 秒内能够达到 22 英里/小时的速度。我们用来计算速度的公式（在`SpeedModel`对象内部）对您来说是熟悉的：

```java
double weightPower = 2.0 * horsePower * 746 * 32.174 / weightPounds;
double speed = (double) Math.round(Math.sqrt(timeSec * weightPower) 
                                                 * 0.68 * traction);
```

这里，`traction`值来自`TrafficUnit`。在实现`TrafficUnit`接口的类中，`getTraction()`方法如下所示：

```java
public double getTraction() {
  double rt = getRoadCondition().getTraction();
  double tt = getTireCondition().getTraction();
  return rt * tt;
}
```

`getRoadCondition()`和`getTireCondition()`方法返回我们刚刚描述的相应`enum`类型的元素。

现在我们准备使用前面讨论的 lambda 表达式来改进我们的速度计算应用程序。

# 如何做…

按照以下步骤学习如何使用 lambda 表达式：

1.  让我们开始构建一个 API。我们将其称为`Traffic`。如果不使用函数接口，它可能如下所示：

```java
public interface Traffic {
   void speedAfterStart(double timeSec, int trafficUnitsNumber);
}  
```

其实现可能如下所示：

```java
public class TrafficImpl implements Traffic {
   private int hour;
   private Month month;
   private DayOfWeek dayOfWeek;
   private String country, city, trafficLight;
   public TrafficImpl(Month month, DayOfWeek dayOfWeek, int hour, 
                String country, String city, String trafficLight){
      this.hour = hour;
      this.city = city;
      this.month = month;
      this.country = country;
      this.dayOfWeek = dayOfWeek;
      this.trafficLight = trafficLight;
   }
   public void speedAfterStart(double timeSec, 
                                      int trafficUnitsNumber){
      List<TrafficUnit> trafficUnits = 
        FactoryTraffic.generateTraffic(trafficUnitsNumber, 
          month, dayOfWeek, hour, country, city, trafficLight);
      for(TrafficUnit tu: trafficUnits){
         Vehicle vehicle = FactoryVehicle.build(tu);
         SpeedModel speedModel = 
                      FactorySpeedModel.generateSpeedModel(tu);
         vehicle.setSpeedModel(speedModel);
         double speed = vehicle.getSpeedMph(timeSec);
         printResult(tu, timeSec, speed);
      }
   }
}
```

1.  让我们编写使用`Traffic`接口的示例代码：

```java
Traffic traffic = new TrafficImpl(Month.APRIL, 
  DayOfWeek.FRIDAY, 17, "USA", "Denver", "Main103S");
double timeSec = 10.0;
int trafficUnitsNumber = 10;
traffic.speedAfterStart(timeSec, trafficUnitsNumber); 
```

我们得到类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/038d044d-970e-4fa4-bb1f-cea021a97788.png)

如前所述，由于我们使用真实数据，因此相同的代码不会每次产生完全相同的结果。不应该期望看到前面截图中的速度值，而是看到非常相似的结果。

1.  让我们使用 lambda 表达式。前面的 API 相当有限。例如，它不允许您在不更改`FactorySpeedModel`的情况下测试不同的速度计算公式。同时，`SpeedModel`接口只有一个名为`getSpeedMph()`的抽象方法（这使它成为函数接口）：

```java
public interface SpeedModel {
  double getSpeedMph(double timeSec, 
           int weightPounds, int horsePower);
}
```

我们可以利用`SpeedModel`是函数接口的特性，并向`Traffic`接口添加另一个方法，该方法能够接受`SpeedModel`实现作为 lambda 表达式：

```java
public interface Traffic {
  void speedAfterStart(double timeSec, 
                       int trafficUnitsNumber);
  void speedAfterStart(double timeSec, 
    int trafficUnitsNumber, SpeedModel speedModel);
}
```

不过问题在于`traction`值不作为`getSpeedMph()`方法的参数传递，因此我们无法将其作为一个函数传递到`speedAfterStart()`方法中。仔细查看`FactorySpeedModel.generateSpeedModel(TrafficUnit trafficUnit)`的速度计算：

```java
double getSpeedMph(double timeSec, int weightPounds, 
                                           int horsePower) {
    double traction = trafficUnit.getTraction();
    double v = 2.0 * horsePower * 746 * timeSec * 
                                    32.174 / weightPounds;
    return Math.round(Math.sqrt(v) * 0.68 * traction);
}
```

正如你所看到的，`traction`值是计算出的`speed`值的乘数，这是对交通单位的唯一依赖。我们可以从速度模型中移除`traction`，并在使用速度模型计算速度后应用`traction`。这意味着我们可以改变`TrafficImpl`类的`speedAfterStart()`的实现，如下所示：

```java
public void speedAfterStart(double timeSec, 
           int trafficUnitsNumber, SpeedModel speedModel) {
   List<TrafficUnit> trafficUnits = 
     FactoryTraffic.generateTraffic(trafficUnitsNumber, 
       month, dayOfWeek, hour, country, city, trafficLight);
   for(TrafficUnit tu: trafficUnits){
       Vehicle vehicle = FactoryVehicle.build(tu);
       vehicle.setSpeedModel(speedModel);
       double speed = vehicle.getSpeedMph(timeSec);
       speed = (double) Math.round(speed * tu.getTraction());
       printResult(tu, timeSec, speed);
   }
}
```

这个改变允许`Traffic` API 的用户将`SpeedModel`作为一个函数传递：

```java
Traffic traffic = new TrafficImpl(Month.APRIL, 
     DayOfWeek.FRIDAY, 17, "USA", "Denver", "Main103S");
double timeSec = 10.0;
int trafficUnitsNumber = 10;
SpeedModel speedModel = (t, wp, hp) -> {
   double weightPower = 2.0 * hp * 746 * 32.174 / wp;
   return (double) Math
              .round(Math.sqrt(t * weightPower) * 0.68);
};
traffic.speedAfterStart(timeSec, trafficUnitsNumber, 
                                            speedModel);
```

1.  上述代码的结果与通过`FactorySpeedModel`生成`SpeedModel`时相同。但现在 API 用户可以自己想出自己的速度计算函数。

1.  我们可以将`SpeedModel`接口注释为`@FunctionalInterface`，这样所有试图向其添加另一个方法的人都会得到警告，并且不能在删除此注释并意识到破坏已经实现此功能接口的现有客户端代码的风险的情况下添加另一个抽象方法。

1.  我们可以通过添加各种标准来丰富 API，将所有可能的交通划分为不同的片段。

例如，API 用户可能只想分析汽车、卡车、引擎大于 300 马力的汽车，或引擎大于 400 马力的卡车。传统的方法是创建这样的方法：

```java
void speedAfterStartCarEngine(double timeSec, 
              int trafficUnitsNumber, int horsePower);
void speedAfterStartCarTruckOnly(double timeSec, 
                              int trafficUnitsNumber);
void speedAfterStartEngine(double timeSec, 
         int trafficUnitsNumber, int carHorsePower, 
                                 int truckHorsePower);
```

相反，我们可以将标准的函数接口添加到`Traffic`接口的现有`speedAfterStart()`方法中，并让 API 用户决定要提取哪一部分交通：

```java
void speedAfterStart(double timeSec, int trafficUnitsNumber,
  SpeedModel speedModel, Predicate<TrafficUnit> limitTraffic);
```

`TrafficImpl`类中`speedAfterStart()`方法的实现将如下更改：

```java
public void speedAfterStart(double timeSec, 
          int trafficUnitsNumber, SpeedModel speedModel, 
                    Predicate<TrafficUnit> limitTraffic) {
  List<TrafficUnit> trafficUnits = 
    FactoryTraffic.generateTraffic(trafficUnitsNumber, 
    month, dayOfWeek, hour, country, city, trafficLight);
  for(TrafficUnit tu: trafficUnits){
      if(limitTraffic.test(tu){
         Vehicle vehicle = FactoryVehicle.build(tu);
         vehicle.setSpeedModel(speedModel);
         double speed = vehicle.getSpeedMph(timeSec);
         speed = (double) Math.round(speed * 
                                   tu.getTraction());
         printResult(tu, timeSec, speed);
      }
    }
}
```

然后，`Traffic` API 用户可以按以下方式定义他们需要的交通情况：

```java
Predicate<TrafficUnit> limit = tu ->
  (tu.getHorsePower() < 250 
      && tu.getVehicleType() == VehicleType.CAR) || 
  (tu.getHorsePower() < 400 
      && tu.getVehicleType() == VehicleType.TRUCK);
traffic.speedAfterStart(timeSec, 
            trafficUnitsNumber, speedModel, limit);
```

结果现在被限制为引擎小于 250 `hp`的汽车和引擎小于 400 `hp`的卡车：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/d601ea9c-2be1-4f90-971f-e6ecb0259f05.png)

事实上，`Traffic` API 用户现在可以应用任何限制交通的标准，只要它们适用于`TrafficUnit`对象中的值。例如，用户可以写以下内容：

```java
Predicate<TrafficUnit> limitTraffic = 
 tu -> tu.getTemperature() > 65 
 && tu.getTireCondition() == TireCondition.NEW 
 && tu.getRoadCondition() == RoadCondition.WET;
```

或者，他们可以写任何其他限制`TrafficUnit`值的组合。如果用户决定移除限制并分析所有交通情况，这段代码也可以做到：

```java
traffic.speedAfterStart(timeSec, trafficUnitsNumber, 
                              speedModel, tu -> true);
```

1.  如果需要通过速度选择交通单位，我们可以在速度计算后应用谓词标准（请注意，我们用`BiPredicate`替换了`Predicate`，因为我们现在需要使用两个参数）：

```java
public void speedAfterStart(double timeSec,  
           int trafficUnitsNumber, SpeedModel speedModel,
             BiPredicate<TrafficUnit, Double> limitSpeed){
   List<TrafficUnit> trafficUnits = 
     FactoryTraffic.generateTraffic(trafficUnitsNumber, 
     month, dayOfWeek, hour, country, city, trafficLight);
   for(TrafficUnit tu: trafficUnits){
      Vehicle vehicle = FactoryVehicle.build(tu);
      vehicle.setSpeedModel(speedModel);
      double speed = vehicle.getSpeedMph(timeSec);
      speed = (double) Math.round(speed*tu.getTraction());
      if(limitSpeed.test(tu, speed)){
           printResult(tu, timeSec, speed);
      }
   }
}
```

`Traffic` API 用户现在可以编写以下代码：

```java
BiPredicate<TrafficUnit, Double> limit = (tu, sp) ->
   (sp > (tu.getSpeedLimitMph() + 8.0) && 
          tu.getRoadCondition() == RoadCondition.DRY) || 
   (sp > (tu.getSpeedLimitMph() + 5.0) && 
          tu.getRoadCondition() == RoadCondition.WET) || 
    (sp > (tu.getSpeedLimitMph() + 0.0) && 
           tu.getRoadCondition() == RoadCondition.SNOW);
traffic.speedAfterStart(timeSec, 
                 trafficUnitsNumber, speedModel, limit);
```

上面的谓词选择超过一定数量的速度限制的交通单位（对于不同的驾驶条件是不同的）。如果需要，它可以完全忽略速度，并且以与之前的谓词完全相同的方式限制交通。这种实现的唯一缺点是它略微不那么高效，因为谓词是在速度计算之后应用的。这意味着速度计算将针对每个生成的交通单位进行，而不是像之前的实现中那样限制数量。如果这是一个问题，你可以留下我们在本文中讨论过的所有不同签名：

```java
public interface Traffic {
   void speedAfterStart(double timeSec, int trafficUnitsNumber);
   void speedAfterStart(double timeSec, int trafficUnitsNumber,
                                         SpeedModel speedModel);
   void speedAfterStart(double timeSec, 
            int trafficUnitsNumber, SpeedModel speedModel, 
                           Predicate<TrafficUnit> limitTraffic);
   void speedAfterStart(double timeSec, 
             int trafficUnitsNumber, SpeedModel speedModel,
                  BiPredicate<TrafficUnit,Double> limitTraffic);
}
```

这样，API 用户可以决定使用哪种方法，更灵活或更高效，并决定默认的速度计算实现是否可接受。

# 还有更多...

到目前为止，我们还没有给 API 用户选择输出格式的选择。目前，它是作为`printResult()`方法实现的：

```java
void printResult(TrafficUnit tu, double timeSec, double speedMph) {
  System.out.println("Road " + tu.getRoadCondition() +
                  ", tires " + tu.getTireCondition() + ": " 
                     + tu.getVehicleType().getType() + " speedMph (" 
                     + timeSec + " sec)=" + speedMph + " mph");
}
```

为了使其更加灵活，我们可以向我们的 API 添加另一个参数：

```java
Traffic traffic = new TrafficImpl(Month.APRIL, DayOfWeek.FRIDAY, 17,
                                        "USA", "Denver", "Main103S");
double timeSec = 10.0;
int trafficUnitsNumber = 10;
BiConsumer<TrafficUnit, Double> output = (tu, sp) ->
  System.out.println("Road " + tu.getRoadCondition() + 
                  ", tires " + tu.getTireCondition() + ": " 
                     + tu.getVehicleType().getType() + " speedMph (" 
                     + timeSec + " sec)=" + sp + " mph");
traffic.speedAfterStart(timeSec, trafficUnitsNumber, speedModel, output);
```

注意我们取`timeSec`值不是作为函数参数之一，而是从函数的封闭范围中取得。我们之所以能够这样做，是因为它在整个计算过程中保持不变（并且可以被视为最终值）。同样地，我们可以向`output`函数添加任何其他对象，比如文件名或另一个输出设备，从而将所有与输出相关的决策留给 API 用户。为了适应这个新函数，API 的实现发生了变化，如下所示：

```java
public void speedAfterStart(double timeSec, int trafficUnitsNumber,
        SpeedModel speedModel, BiConsumer<TrafficUnit, Double> output) {
  List<TrafficUnit> trafficUnits = 
     FactoryTraffic.generateTraffic(trafficUnitsNumber, month, 
                      dayOfWeek, hour, country, city, trafficLight);
  for(TrafficUnit tu: trafficUnits){
     Vehicle vehicle = FactoryVehicle.build(tu);
     vehicle.setSpeedModel(speedModel);
     double speed = vehicle.getSpeedMph(timeSec);
     speed = (double) Math.round(speed * tu.getTraction());
     output.accept(tu, speed);
  }
}
```

我们花了一些时间才达到这一点——函数式编程的威力开始显现并证明了学习它的努力是值得的。然而，当用于处理流时，如下一章所述，lambda 表达式会产生更大的威力。


# 第五章：流和管道

在 Java 8 和 9 中，通过引入流和利用 lambda 表达式进行内部迭代，集合 API 得到了重大改进。在 Java 10（JDK 18.3）中，添加了新方法`List.copyOf`、`Set.copyOf`和`Map.copyOf`，允许我们从现有实例创建新的不可变集合。此外，在`java.util.stream`包的`Collectors`类中添加了新方法`toUnmodifiableList`、`toUnmodifiableSet`和`toUnmodifiableMap`，允许将`Stream`的元素收集到不可变集合中。本章将向您展示如何使用流并链接多个操作来创建管道。此外，读者将学习如何并行进行这些操作。示例包括以下内容：

+   使用`of()`和`copyOf()`工厂方法创建不可变集合

+   创建和操作流

+   使用数字流进行算术运算

+   通过生成集合来完成流

+   通过生成映射来完成流

+   通过对流元素进行分组来完成流

+   创建流操作管道

+   并行处理流

# 介绍

在 Java 8 中引入的 lambda 表达式在上一章中有所描述和演示。它们与函数接口一起，为 Java 增加了函数式编程能力，允许将行为（函数）作为参数传递给专为数据处理性能优化的库。这样，应用程序员可以专注于开发系统的业务方面，将性能方面留给专家-库的作者。

这样的库的一个例子是`java.util.stream`包，它将成为本章的重点。该包允许您以声明性的方式呈现随后可以应用于数据的过程，也可以并行进行；这些过程被呈现为流，是`Stream`接口的对象。为了更好地从传统集合过渡到流，`java.util.Collection`接口添加了两个默认方法（`stream()`和`parallelStream()`），并向`Stream`接口添加了新的流生成工厂方法。

这种方法利用了聚合的强大功能，如第二章中所讨论的那样，*OOP 快速通道-类和接口*。结合其他设计原则-封装、接口和多态性-它促进了高度可扩展和灵活的设计，而 lambda 表达式允许您以简洁和简洁的方式实现它。

如今，随着机器学习对大规模数据处理和操作的需求变得普遍，这些新功能加强了 Java 在少数现代编程语言中的地位。

# 使用`of()`和`copyOf()`工厂方法创建不可变集合

在这个示例中，我们将重新审视创建集合的传统方法，并将它们与 Java 9 中引入的`List.of()`、`Set.of()`、`Map.of()`和`Map.ofEntries()`工厂方法，以及 Java 10 中引入的`List.copyOf()`、`Set.copyOf()`和`Map.copyOf()`方法进行比较。

# 准备工作

在 Java 9 之前，有几种创建集合的方式。以下是创建`List`最流行的方式：

```java
List<String> list = new ArrayList<>();
list.add("This ");
list.add("is ");
list.add("built ");
list.add("by ");
list.add("list.add()");
list.forEach(System.out::print);
```

如果我们运行上述代码，将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/97a3612f-48c9-423e-9155-16cc369dc50d.png)

创建`List`集合的更简洁方式是通过使用数组开始：

```java
Arrays.asList("This ", "is ", "created ", "by ", 
              "Arrays.asList()").forEach(System.out::print);
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/378ce09a-1858-4ddb-9424-44f2f1179348.png)

创建`Set`集合的方式类似：

```java
Set<String> set = new HashSet<>();
set.add("This ");
set.add("is ");
set.add("built ");
set.add("by ");
set.add("set.add() ");
set.forEach(System.out::print);
```

或者，我们可以通过使用数组来构建`Set`：

```java
new HashSet<>(Arrays.asList("This ", "is ", "created ", "by ", 
                            "new HashSet(Arrays.asList()) "))
                            .forEach(System.out::print);
```

以下是最后两个示例的结果的示例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/0e8f0748-76b5-43bf-ab84-a53ada4ad9bc.png)

请注意，与`List`不同，`Set`中元素的顺序不是固定的。它取决于哈希码的实现，并且可能因计算机而异。但是在同一台计算机上的多次运行中，顺序保持不变。请注意这一点，因为我们稍后会回到这个问题。

这是在 Java 9 之前创建`Map`的方法：

```java
Map<Integer, String> map = new HashMap<>();
map.put(1, "This ");
map.put(2, "is ");
map.put(3, "built ");
map.put(4, "by ");
map.put(5, "map.put() ");
map.entrySet().forEach(System.out::print);
```

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/069d62ab-e65a-4550-a366-cafb7e8d7fbf.png)

尽管前面的输出保留了元素的顺序，但对于`Map`来说并不是保证的，因为它是基于在`Set`中收集的键。

那些经常以这种方式创建集合的人赞赏 JDK 增强提案 269 *集合的便利工厂方法*（JEP 269）的声明，

"*Java 经常因其冗长而受到批评*"，它的目标是"*在集合接口上提供静态工厂方法，用于创建紧凑的、不可修改的集合实例*。"

作为对批评和提案的回应，Java 9 为 3 个接口——`List`、`Set`和`Map`引入了 12 个`of()`静态工厂方法。以下是`List`的工厂方法：

```java
static <E> List<E> of()  //Returns list with zero elements
static <E> List<E> of(E e1) //Returns list with one element
static <E> List<E> of(E e1, E e2)  //etc
static <E> List<E> of(E e1, E e2, E e3)
static <E> List<E> of(E e1, E e2, E e3, E e4)
static <E> List<E> of(E e1, E e2, E e3, E e4, E e5)
static <E> List<E> of(E e1, E e2, E e3, E e4, E e5, E e6)
static <E> List<E> of(E e1, E e2, E e3, E e4, E e5, E e6, E e7)
static <E> List<E> of(E e1, E e2, E e3, E e4, E e5, 
                                        E e6, E e7, E e8)
static <E> List<E> of(E e1, E e2, E e3, E e4, E e5, 
                                  E e6, E e7, E e8, E e9)
static <E> List<E> of(E e1, E e2, E e3, E e4, E e5, 
                            E e6, E e7, E e8, E e9, E e10)
static <E> List<E> of(E... elements)
```

具有固定数量元素的 10 个重载工厂方法被优化为性能，并且正如 JEP 269 所述（[`openjdk.java.net/jeps/269`](http://openjdk.java.net/jeps/269)），这些方法

"*避免了由* *varargs 调用引起的数组分配、初始化和垃圾回收开销。**"*

使用`of()`工厂方法使代码更加紧凑：

```java
List.of("This ", "is ", "created ", "by ", "List.of()")
                                            .forEach(System.out::print);
System.out.println();
Set.of("This ", "is ", "created ", "by ", "Set.of() ")
                                            .forEach(System.out::print);
System.out.println();
Map.of(1, "This ", 2, "is ", 3, "built ", 4, "by ", 5,"Map.of() ")
                                 .entrySet().forEach(System.out::print);
```

`System.out.println()`语句被添加以在结果之间插入换行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/d60ff266-9bf0-4ad4-bcc0-dba9c10badb5.png)

`Map`接口中的 12 个静态工厂方法之一与其他`of()`方法不同：

```java
Map<K,V> ofEntries(Map.Entry<K,V>... entries)
```

以下是其用法示例：

```java
Map.ofEntries(
  entry(1, "This "),
  entry(2, "is "),
  entry(3, "built "),
  entry(4, "by "),
  entry(5, "Map.ofEntries() ")
).entrySet().forEach(System.out::print);
```

它产生了以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/5541fd5e-21ac-4d8c-97fb-9a1d9bcdc4d1.png)

并且没有`Map.of()`工厂方法用于无限数量的元素。当创建一个包含超过 10 个元素的映射时，必须使用`Map.ofEntries()`。

在 Java 10 中，引入了`List.copyOf()`、`Set.copyOf()`和`Map.copyOf()`方法。它们允许我们将任何集合转换为相应类型的不可变集合。

# 如何做到...

正如我们已经提到的，`Set.of()`、`Map.of()`和`Map.ofEntries()`方法不保留集合元素的顺序。这与之前（Java 9 之前）的`Set`和`Map`实例在同一台计算机上运行时保持相同顺序的行为不同。`Set.of()`、`Map.of()`和`Map.ofEntries()`方法会在同一台计算机上的多次运行中改变元素的顺序。顺序只在同一次运行中保持不变，无论集合被迭代多少次。在同一台计算机上从一次运行到另一次运行改变元素的顺序有助于程序员避免对特定顺序的不必要依赖。

`List`、`Set`和`Map`接口的`of()`静态方法生成的集合的另一个特性是它们是不可变的。这是什么意思？考虑以下代码：

```java
List<String> list = List.of("This ", "is ", "immutable");
list.add("Is it?");     //throws UnsupportedOperationException
list.set(1, "is not "); //throws UnsupportedOperationException
```

如您所见，任何尝试向使用`List.of()`方法创建的集合中添加新元素或修改现有元素都会导致`java.lang.UnsupportedOperationException`运行时异常。

此外，`List.of()`方法不接受`null`元素，因此以下代码会抛出`java.lang.NullPointerException`运行时异常：

```java
List<String> list = List.of("This ", "is ", "not ", "created ", null);
```

`Set.of()`和`Map.of()`创建的集合与前面描述的`List.of()`方法的行为相同：

```java
Set<String> set = Set.of("a", "b", "c");
//set.remove("b");  //UnsupportedOperationException
//set.add("e");     //UnsupportedOperationException
//set = Set.of("a", "b", "c", null); //NullPointerException

Map<Integer, String> map = Map.of(1, "one", 2, "two", 3, "three");
//map.remove(2);                    //UnsupportedOperationException
//map.put(5, "five ");              //UnsupportedOperationException
//map = Map.of(1, "one", 2, "two", 3, null); //NullPointerException
//map = Map.ofEntries(entry(1, "one"), null); //NullPointerException

```

`List.copyOf()`、`Set.copyOf()`和`Map.copyOf()`方法提供了另一种基于另一个集合创建不可变集合的方法：

```java
List<Integer> list = Arrays.asList(1,2,3);
list = List.copyOf(list);
//list.set(1, 0);     //UnsupportedOperationException
//list.remove(1);     //UnsupportedOperationException

Set<Integer> setInt = Set.copyOf(list);
//setInt.add(42);       //UnsupportedOperationException
//setInt.remove(3);  //UnsupportedOperationException

Set<String> set = new HashSet<>(Arrays.asList("a","b","c"));
set = Set.copyOf(set);
//set.add("d");     //UnsupportedOperationException
//set.remove("b");  //UnsupportedOperationException

Map<Integer, String> map = new HashMap<>();
map.put(1, "one ");
map.put(2, "two ");
map = Map.copyOf(map);
//map.remove(2);          //UnsupportedOperationException
//map.put(3, "three ");    //UnsupportedOperationException

```

请注意，输入参数可以是任何具有相同类型元素或扩展传入集合元素类型的类型的集合：

```java
class A{}
class B extends A{}

List<A> listA = Arrays.asList(new B(), new B());
Set<A> setA = new HashSet<>(listA);

List<B> listB = Arrays.asList(new B(), new B());
setA = new HashSet<>(listB);

//List<B> listB = Arrays.asList(new A(), new A()); //compiler error
//Set<B> setB = new HashSet<>(listA);              //compiler error

```

# 还有更多...

在 lambda 表达式和流引入后不久，非空值和不可变性被强制执行并非偶然。正如您将在后续的示例中看到的，函数式编程和流管道鼓励一种流畅的编码风格（使用方法链式编程，以及在本示例中使用`forEach()`方法）。流畅的风格提供了更紧凑和可读的代码。消除了对`null`值的检查有助于保持这种方式——紧凑且专注于主要的处理过程。

不可变性特性与 lambda 表达式使用的变量的*effectively final*概念相吻合。例如，可变集合允许我们绕过这个限制：

```java
List<Integer> list = Arrays.asList(1,2,3,4,5);
list.set(2, 0);
list.forEach(System.out::print);  //prints: 12045

list.forEach(i -> {
  int j = list.get(2);
  list.set(2, j + 1);
});
System.out.println();
list.forEach(System.out::print);   //prints: 12545
```

在上述代码中，第二个`forEach()`操作使用的 lambda 表达式在原始列表的第三个（索引为 2）元素中保持状态。这可能会有意或无意地在 lambda 表达式中引入状态，并导致在不同上下文中同一函数的不同结果。这在并行处理中尤其危险，因为无法预测每个可能上下文的状态。这就是为什么集合的不可变性是一个有用的补充，使代码更健壮和可靠。

# 创建和操作流

在本示例中，我们将描述如何创建流以及如何对流发出的元素应用操作。讨论和示例适用于任何类型的流，包括专门的数值流：`IntStream`、`LongStream`和`DoubleStream`。数值流特有的行为没有呈现，因为它在下一个示例中描述，即*使用数值流进行算术操作*。

# 准备就绪

有许多创建流的方法：

+   `stream()`和`parallelStream()`方法属于`java.util.Collection`接口——这意味着所有的子接口，包括`Set`和`List`，也有这些方法

+   `java.util.Arrays`类的两个重载的`stream()`方法，将数组和子数组转换为流

+   `java.util.stream.Stream`接口的`of()`、`generate()`和`iterate()`方法

+   `java.nio.file.Files`类的`Stream<Path> list()`、`Stream<String> lines()`和`Stream<Path> find()`方法

+   `java.io.BufferedReader`类的`Stream<String> lines()`方法

创建流后，可以对其元素应用各种方法（称为操作）。流本身不存储数据。相反，它根据需要从源获取数据（并将其提供或发出给操作）。操作可以使用流畅的风格形成管道，因为许多中间操作也可以返回流。这些操作称为*中间*操作。中间操作的示例包括以下内容：

+   `map()`: 根据函数转换元素

+   `flatMap()`: 根据函数将每个元素转换为流

+   `filter()`: 选择符合条件的元素

+   `limit()`: 将流限制为指定数量的元素

+   `sorted()`: 将无序流转换为有序流

+   `distinct()`: 移除重复项

+   `Stream`接口的其他返回`Stream`的方法

管道以**终端操作**结束。实际上，只有在执行终端操作时，流元素的处理才会开始。然后，所有中间操作（如果存在）开始处理，流关闭并且在终端操作完成执行之前不能重新打开。终端操作的示例包括：

+   `forEach()`

+   `findFirst()`

+   `reduce()`

+   `collect()`

+   `Stream`接口的其他不返回`Stream`的方法

终端操作返回结果或产生副作用，但它们不返回`Stream`对象。

所有的`Stream`操作都支持并行处理，在多核计算机上处理大量数据时尤其有帮助。所有 Java Stream API 接口和类都在`java.util.stream`包中。

在本示例中，我们将演示顺序流。并行流处理并没有太大的不同。只需注意处理管道不使用在不同处理环境中可能变化的上下文状态。我们将在本章后面的另一个示例中讨论并行处理。

# 如何做到...

在本节中，我们将介绍创建流的方法。实现`Set`接口或`List`接口的每个类都有`stream()`方法和`parallelStream()`方法，它们返回`Stream`接口的实例：

1.  考虑以下流创建的示例：

```java
List.of("This", "is", "created", "by", "List.of().stream()")
                            .stream().forEach(System.out::print);
System.out.println();
Set.of("This", "is", "created", "by", "Set.of().stream()")
                            .stream().forEach(System.out::print);
System.out.println();
Map.of(1, "This ", 2, "is ", 3, "built ", 4, "by ", 5,
                             "Map.of().entrySet().stream()")
                 .entrySet().stream().forEach(System.out::print);
```

我们使用了流畅的风格使代码更加简洁，并插入了`System.out.println()`以便在输出中开始新的一行。

1.  运行上述示例，你应该会看到以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/936e8f84-eacb-4d72-b5bc-04e165a78f25.png)

注意，`List`保留了元素的顺序，而`Set`元素的顺序在每次运行时都会改变。后者有助于发现基于对特定顺序的依赖而未能保证顺序时的缺陷。

1.  查看`Arrays`类的 Javadoc。它有两个重载的静态`stream()`方法：

```java
Stream<T> stream(T[] array)
Stream<T> stream(T[] array, int startInclusive, int endExclusive)
```

1.  写出最后两种方法的用法示例：

```java
String[] array = {"That ", "is ", "an ", "Arrays.stream(array)"};
Arrays.stream(array).forEach(System.out::print);
System.out.println();
String[] array1 = { "That ", "is ", "an ", 
                                    "Arrays.stream(array,0,2)" };
Arrays.stream(array1, 0, 2).forEach(System.out::print);
```

1.  运行它并查看结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/3c9d5ca8-f851-446c-a7e2-8f4eb2260372.png)

在第二个例子中，注意只有第一个和第二个元素，即索引为`0`和`1`的元素被选中并包含在流中，这正是预期的结果。

1.  打开`Stream`接口的 Javadoc 并查看`of()`、`generate()`和`iterate()`静态工厂方法：

```java
Stream<T> of(T t)          //Stream of one element
Stream<T> ofNullable(T t)  //Stream of one element
       // if not null. Otherwise, returns an empty Stream
Stream<T> of(T... values)
Stream<T> generate(Supplier<T> s)
Stream<T> iterate(T seed, UnaryOperator<T> f)
Stream<T> iterate(T seed, Predicate<T> hasNext, 
                           UnaryOperator<T> next)
```

前两种方法很简单，所以我们跳过它们的演示，直接从第三种方法`of()`开始。它可以接受数组或逗号分隔的元素。

1.  将示例写成如下形式：

```java
String[] array = { "That ", "is ", "a ", "Stream.of(array)" };
Stream.of(array).forEach(System.out::print); 
System.out.println();
Stream.of( "That ", "is ", "a ", "Stream.of(literals)" )
                                  .forEach(System.out::print);
```

1.  运行它并观察输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/89515668-5eb9-44d4-a2be-a3abf325b39c.png)

1.  按照以下方式写出`generate()`和`iterate()`方法的用法示例：

```java
Stream.generate(() -> "generated ")
                           .limit(3).forEach(System.out::print);
System.out.println();
System.out.print("Stream.iterate().limit(10): ");
Stream.iterate(0, i -> i + 1)
                          .limit(10).forEach(System.out::print);
System.out.println();
System.out.print("Stream.iterate(Predicate < 10): ");
Stream.iterate(0, i -> i < 10, i -> i + 1)
                                    .forEach(System.out::print);
```

我们必须对前两个示例生成的流的大小进行限制，否则它们将是无限的。第三个示例接受一个提供迭代何时停止的条件的谓词。

1.  运行示例并观察结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/64c9332d-924f-46c9-a8f6-ff57b57517c9.png)

1.  让我们看一下`Files.list(Path dir)`方法的示例，它返回目录中所有条目的`Stream<Path>`：

```java
System.out.println("Files.list(dir): ");
Path dir = FileSystems.getDefault()
  .getPath("src/main/java/com/packt/cookbook/ch05_streams/");
try(Stream<Path> stream = Files.list(dir)) {
      stream.forEach(System.out::println);
} catch (Exception ex){ 
      ex.printStackTrace(); 
}
```

以下内容来自 JDK API：

*"必须在 try-with-resources 语句或类似的控制结构中使用此方法，以确保在流操作完成后及时关闭流的打开目录。"*

这就是我们所做的；我们使用了 try-with-resources 语句。或者，我们可以使用 try-catch-finally 结构，在 finally 块中关闭流，结果不会改变。

1.  运行上述示例并观察输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/9faf4c8d-cc86-43ce-9bcc-d116b5953269.png)

并非所有流都必须显式关闭，尽管`Stream`接口扩展了`AutoCloseable`，人们可能期望所有流都必须使用 try-with-resources 语句自动关闭。但事实并非如此。`Stream`接口的 Javadoc（[`docs.oracle.com/javase/8/docs/api/java/util/stream/Stream.html`](https://docs.oracle.com/javase/8/docs/api/java/util/stream/Stream.html)）中说道：

“流具有`BaseStream.close()`方法并实现`AutoCloseable`。大多数流实例实际上在使用后不需要关闭，因为它们由集合、数组或生成函数支持，不需要特殊的资源管理。通常，只有其源是 I/O 通道的流，例如`Files.lines(Path)`返回的流，才需要关闭。”

这意味着程序员必须知道流的来源，因此请确保如果源的 API 要求关闭流，则关闭流。

1.  写一个`Files.lines()`方法的使用示例：

```java
  System.out.println("Files.lines().limit(3): ");
  String file = "src/main/java/com/packt/cookbook/" +
                              "ch05_streams/Chapter05Streams.java";
  try(Stream<String> stream=Files.lines(Paths.get(file)).limit(3)){ 
       stream.forEach(l -> { 
            if( l.length() > 0 ) {
                System.out.println("   " + l); 
            }
       });
  } catch (Exception ex){ 
      ex.printStackTrace(); 
  }
```

前面的例子的目的是读取指定文件的前三行，并打印缩进三个空格的非空行。

1.  运行上面的例子并查看结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/05f2f40a-65c6-48cf-9e2f-7d674d05efda.png)

1.  编写使用`Files.find()`方法的代码：

```java
Stream<Path> find(Path start, int maxDepth, BiPredicate<Path, 
    BasicFileAttributes> matcher, FileVisitOption... options)
```

1.  与前面的情况类似，`Files.find()`方法生成的流也必须显式关闭。`Files.find()`方法遍历以给定起始文件为根的文件树，并返回与谓词匹配的文件的路径（包括文件属性）。写下以下代码：

```java
Path dir = FileSystems.getDefault()
 .getPath("src/main/java/com/packt/cookbook/ch05_streams/");
BiPredicate<Path, BasicFileAttributes> select = 
   (p, b) -> p.getFileName().toString().contains("Factory");
try(Stream<Path> stream = Files.find(f, 2, select)){
        stream.map(path -> path.getFileName())
                              .forEach(System.out::println);
} catch (Exception ex){ 
   ex.printStackTrace(); 
}
```

1.  运行上面的例子，你会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/186d2a93-23ed-480f-b4e7-37fa6bbc3e44.png)

如果需要，`FileVisitorOption.FOLLOW_LINKS`可以作为`Files.find()`方法的最后一个参数包含，如果我们需要执行一个会遵循它可能遇到的所有符号链接的搜索。

1.  使用`BufferedReader.lines()`方法的要求有点不同，它返回从文件中读取的行的`Stream<String>`。根据 Javadoc（[`docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html`](https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html)），

“在终端流操作执行期间，不能对读取器进行操作。否则，终端流操作的结果是未定义的。”

JDK 中有许多其他生成流的方法。但它们更加专业化，由于空间不足，我们将不在这里演示它们。

# 它是如何工作的...

在前面的例子中，我们已经演示了几个流操作，即`Stream`接口的方法。我们最常使用`forEach()`，有时使用`limit()`。第一个是终端操作，第二个是中间操作。现在让我们看看`Stream`接口的其他方法。

以下是中间操作，即返回`Stream`并可以以流畅的方式连接的方法：

```java
//1
Stream<T> peek(Consumer<T> action)
//2
Stream<T> distinct()       //Returns stream of distinct elements
Stream<T> skip(long n)     //Discards the first n elements 
Stream<T> limit(long n)    //Allows the first n elements to be processed 
Stream<T> filter(Predicate<T> predicate)
Stream<T> dropWhile(Predicate<T> predicate) 
Stream<T> takeWhile(Predicate<T> predicate)
//3 
Stream<R> map(Function<T, R> mapper)
IntStream mapToInt(ToIntFunction<T> mapper)
LongStream mapToLong(ToLongFunction<T> mapper)
DoubleStream mapToDouble(ToDoubleFunction<T> mapper)
//4
Stream<R> flatMap(Function<T, Stream<R>> mapper)
IntStream flatMapToInt(Function<T, IntStream> mapper)
LongStream flatMapToLong(Function<T, LongStream> mapper)
DoubleStream flatMapToDouble(Function<T, DoubleStream> mapper)
//5
static Stream<T> concat(Stream<T> a, Stream<T> b) 
//6
Stream<T> sorted()
Stream<T> sorted(Comparator<T> comparator)
```

前面方法的签名通常包括``"? super T"``作为输入参数和``"? extends R"``作为结果（请参阅 Javadoc 以获取正式定义）。我们通过删除这些标记来简化它们，以便更好地概述这些方法的多样性和共性。为了弥补这一点，我们想简要回顾相关泛型标记的含义，因为它们在 Stream API 中被广泛使用，可能会引起混淆。

让我们看看`flatMap()`方法的正式定义，因为它包含了所有这些内容：

```java
<R> Stream<R> flatMap(Function<? super T,
                      ? extends Stream<? extends R>> mapper)
```

方法前面的`<R>`符号表示给编译器它是一个通用方法（具有自己的类型参数）。没有它，编译器将寻找`R`类型的定义。`T`类型没有列在方法前面，因为它包含在`Stream<T>`接口定义中（查看接口声明的页面顶部）。`? super T`表示`T`类型或其超类在此处允许。`? extends R`表示`R`类型或其子类在此处允许。`? extends Stream<...>`也是一样的：`Stream`类型或其子类在此处允许。

现在，让我们回到我们（简化的）中间操作列表。我们根据相似性将它们分成了几个组：

+   第一组中只包含一个`peek()`方法，它允许您对每个流元素应用`Consumer`函数，而不影响元素，因为`Consumer`函数不返回任何内容。它通常用于调试：

```java
       int sum = Stream.of( 1,2,3,4,5,6,7,8,9 )
                       .filter(i -> i % 2 != 0)
                       .peek(i -> System.out.print(i))
                       .mapToInt(Integer::intValue)
                       .sum();
       System.out.println("sum = " + sum);
```

如果您执行上述代码，结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/c805401d-0eff-4b09-b9e4-cadfb5c23d9a.png)

+   在上面列出的第二组中间操作中，前三个——`distinct()`、`skip()`、`limit()`——都是不言自明的。`filter(Predicate p)`方法是最常用的方法之一。它做的就是它的名字所暗示的——从流中删除不符合作为`Predicate`函数传递的标准的元素。我们在前面的代码片段中看到了它的使用示例：只有奇数才能通过过滤器。`dropWhile()`方法丢弃元素，只要标准得到满足（然后允许流的其余元素流向下一个操作）。`takeWhile()`方法则相反——只要标准得到满足（然后丢弃其余的元素）。以下是这些操作的使用示例：

```java
System.out.println("Files.lines().dropWhile().takeWhile():");
String file = "src/main/java/com/packt/cookbook/" + 
                        "ch05_streams/Chapter05Streams.java";
try(Stream<String> stream = Files.lines(Paths.get(file))){
    stream.dropWhile(l -> 
                  !l.contains("dropWhile().takeWhile()"))
        .takeWhile(l -> !l.contains("} catc" + "h"))
        .forEach(System.out::println);
} catch (Exception ex){ 
    ex.printStackTrace(); 
}   
```

此代码读取存储上述代码的文件。我们希望它首先打印`"Files.lines().dropWhile().takeWhile():"`，然后打印除最后三行之外的所有前面的行。因此，上述代码丢弃文件中不包含`dropWhile().takeWhile()`子字符串的所有第一行，然后允许所有行流动，直到找到`"} catch`子字符串为止。

请注意，我们必须写`"} catc" + "h"`而不是`"} catch"`。否则，代码会找到`contains(" catch")`，并且不会继续执行。

上述代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/31315eab-c83a-4822-a762-baadf73b4b4e.png)

+   `map()`操作组也非常简单。这样的操作通过将作为参数传递的函数应用于流的每个元素来转换流的每个元素。我们已经看到了`mapToInt()`方法的使用示例。以下是`map()`操作的另一个示例：

```java
Stream.of( "That ", "is ", "a ", "Stream.of(literals)" )
              .map(s -> s.contains("i"))
              .forEach(System.out::println);
```

在这个例子中，我们将`String`文字转换为`boolean`。结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/514474c8-0a6c-4f97-9c78-74174d928e3b.png)

+   下一组中间操作称为`flatMap()`，提供更复杂的处理。`flatMap()`操作将传入的函数（返回流）应用于每个元素，以便操作可以生成由从每个元素提取的流组成的流。以下是`flatMap()`的使用示例：

```java
Stream.of( "That ", "is ", "a ", "Stream.of(literals)" )
     .filter(s -> s.contains("Th"))
     .flatMap(s -> Pattern.compile("(?!^)").splitAsStream(s))
     .forEach(System.out::print);
```

上述代码从流元素中仅选择包含`Th`的文字，并将它们转换为字符流，然后由`forEach()`打印出来。其结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/d98ba1f7-0686-4ad3-8ac5-15eb4f80b2f7.png)

+   `concat()`方法从两个输入流创建一个流，以便第一个流的所有元素后跟第二个流的所有元素。以下是此功能的示例：

```java
Stream.concat(Stream.of(4,5,6), Stream.of(1,2,3))
                                  .forEach(System.out::print);
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/a374487c-d5a2-4ee3-86cc-54f05d75f8c1.png)

如果有两个以上的流连接，可以编写如下内容：

```java
Stream.of(Stream.of(4,5,6), Stream.of(1,2,3), Stream.of(7,8,9))
 .flatMap(Function.identity())
 .forEach(System.out::print);
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/b4687d8d-f14e-49b3-896c-7736483e1d18.png)

请注意，在上述代码中，`Function.identity()`是一个返回其输入参数的函数。我们使用它是因为我们不需要转换输入流，而只是将它们原样传递给生成的流。如果不使用这个`flatMap()`操作，流将由`Stream`对象组成，而不是它们的元素，输出将显示`java.util.stream.ReferencePipeline$Head@548b7f67java.util.stream.ReferencePipeline$Head@7ac7a4e4 java.util.stream.ReferencePipeline$Head@6d78f375`。

+   中间操作的最后一组由`sorted()`方法组成，该方法按自然顺序（如果它们是`Comparable`类型）或根据传入的`Comparator`对象对流元素进行排序。它是一个有状态的操作（以及`distinct()`、`limit()`和`skip()`），在并行处理的情况下会产生非确定性结果（这是下面*在并行中处理流*主题的食谱）。

现在，让我们看看终端操作（我们通过删除`? super T`和`? extends R`来简化它们的签名）：

```java
//1
long count()                     //Returns total count of elements
//2
Optional<T> max(Comparator<T> c) //Returns max according to Comparator
Optional<T> min(Comparator<T> c) //Returns min according to Comparator
//3
Optional<T> findAny()    //Returns any or empty Optional
Optional<T> findFirst()  //Returns the first element or empty Optional 
//4
boolean allMatch(Predicate<T> p)   //All elements match Predicate?
boolean anyMatch(Predicate<T> p)   //Any element matches Predicate?
boolean noneMatch(Predicate<T> p)  //No element matches Predicate?
//5
void forEach(Consumer<T> action)   //Apply action to each element 
void forEachOrdered(Consumer<T> action) 
//6
Optional<T> reduce(BinaryOperator<T> accumulator) 
T reduce(T identity, BinaryOperator<T> accumulator) 
U reduce(U identity, BiFunction<U,T,U> accumulator, 
                                          BinaryOperator<U> combiner) 
//7
R collect(Collector<T,A,R> collector) 
R collect(Supplier<R> supplier, BiConsumer<R,T> accumulator, 
                                            BiConsumer<R,R> combiner) 
//8
Object[] toArray() 
A[] toArray(IntFunction<A[]> generator)
```

前四组操作都不言自明，但是我们需要对`Optional`说几句话。Javadoc（[`docs.oracle.com/javase/8/docs/api/java/util/Optional.html`](https://docs.oracle.com/javase/8/docs/api/java/util/Optional.html)）将其定义为，

“可能包含非空值的容器对象。如果存在值，则`isPresent()`返回`true`，`get()`返回该值。”

它允许您避免`NullPointerException`或检查`null`（无论如何，您都必须调用`isPresent()`）。它有自己的方法——`map()`、`filter()`和`flatMap()`。此外，`Optional`还有一些包含`isPresent()`检查的方法：

+   `ifPresent(Consumer<T> action)`: 如果存在值，则执行该操作，否则不执行任何操作

+   `ifPresentOrElse(Consumer<T> action, Runnable emptyAction)`: 如果存在值，则执行提供的操作，否则执行提供的基于空的操作

+   `or(Supplier<Optional<T>> supplier)`: 如果存在值，则返回描述该值的`Optional`类，否则返回由提供的函数产生的`Optional`类

+   `orElse(T other)`: 如果存在值，则返回该值，否则返回提供的`other`对象

+   `orElseGet(Supplier<T> supplier)`: 如果存在值，则返回该值，否则返回由提供的函数产生的结果

+   `orElseThrow(Supplier<X> exceptionSupplier)`: 如果存在值，则返回该值，否则抛出由提供的函数产生的异常

请注意，`Optional`在可能返回`null`的情况下用作返回值。以下是其用法示例。我们使用`reduce()`操作重新实现了流连接代码，该操作返回`Optional`：

```java
    Stream.of(Stream.of(4,5,6), Stream.of(1,2,3), Stream.of(7,8,9))
          .reduce(Stream::concat)
          .orElseGet(Stream::empty)
          .forEach(System.out::print);
```

使用`flatMap()`方法的结果与以前的实现相同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/ca8a1a49-61ac-43cd-94b1-2385161bf443.png)

下一组终端操作称为`forEach()`。这些操作保证给定的函数将应用于流的每个元素。但是`forEach()`对顺序没有任何要求，这可能会改变以获得更好的性能。相比之下，`forEachOrdered()`保证不仅处理流的所有元素，而且无论流是顺序还是并行，都会按照其源指定的顺序进行处理。以下是几个示例：

```java
Stream.of("3","2","1").parallel().forEach(System.out::print);
System.out.println();
Stream.of("3","2","1").parallel().forEachOrdered(System.out::print);
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/62fc8016-1719-485e-9767-68ada906d7f5.png)

如您所见，在并行处理的情况下，`forEach()`不能保证顺序，而`forEachOrdered()`可以。以下是使用`Optional`和`forEach()`的另一个示例：

```java
 Stream.of( "That ", "is ", "a ", null, "Stream.of(literals)" )
       .map(Optional::ofNullable) 
       .filter(Optional::isPresent)
       .map(Optional::get)
       .map(String::toString)
       .forEach(System.out::print);
```

我们无法使用`Optional.of()`，而是使用`Optional.ofNullable()`，因为`Optional.of()`在`null`上会抛出`NullPointerException`。在这种情况下，`Optional.ofNullable()`只会返回空的`Optional`。结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/062c4c7d-21e1-4ad9-8e69-c21ec4476bb5.png)

现在，让我们谈谈下一组终端操作，称为`reduce()`。这三个重载方法中的每一个在处理所有流元素后返回单个值。最简单的例子包括找到流元素的和（如果它们是数字），或者最大值、最小值等。但是对于任何类型的对象流，也可以构造更复杂的结果。

第一个方法`Optional<T> reduce(BinaryOperator<T> accumulator)`返回`Optional<T>`对象，因为由提供的累加器函数负责计算结果，JDK 实现的作者无法保证它总是包含非空值：

```java
 int sum = Stream.of(1,2,3).reduce((p,e) -> p + e).orElse(0);
 System.out.println("Stream.of(1,2,3).reduce(acc): " +sum);
```

传入的函数接收相同函数之前执行的结果（作为第一个参数`p`）和流的下一个元素（作为第二个参数`e`）。对于第一个元素，`p`获得其值，而`e`是第二个元素。您可以按如下方式打印`p`的值：

```java
int sum = Stream.of(1,2,3)
        .reduce((p,e) -> {
            System.out.println(p);   //prints: 1 3
            return p + e;
        })
        .orElse(10);
System.out.println("Stream.of(1,2,3).reduce(acc): " + sum);
```

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/51f1c284-f957-449d-af72-1eae5e35d77c.png)

为了避免使用`Optional`的额外步骤，第二种方法`T reduce(T identity, BinaryOperator<T> accumulator)`在流为空的情况下返回作为第一个参数`identity`的值，类型为`T`（即`Stream<T>`的元素类型）。该参数必须符合对于所有`t`的要求，因为`accumulator.apply(identity, t)`等于`t`的要求（来自 Javadoc）。在我们的例子中，它必须为`0`，以符合`0 + e == e`。以下是如何使用第二种方法的示例：

```java
int sum = Stream.of(1,2,3).reduce(0, (p,e) -> p + e);
System.out.println("Stream.of(1,2,3).reduce(0, acc): " + sum);
```

结果与第一个`reduce()`方法相同。

第三种方法`U reduce(U identity, BiFunction<U,T,U> accumulator, BinaryOperator<U> combiner)`，使用`BiFunction<U,T,U>`函数将`T`类型的值转换为`U`类型的值。`BiFunction<U,T,U>`用作累加器，使得其应用于前一个元素（`T`类型）的结果（`U`类型）成为函数的输入，同时与流的当前元素一起成为函数的输入。以下是一个代码示例：

```java
String sum = Stream.of(1,2,3)
    .reduce("", (p,e) -> p + e.toString(), (x,y) -> x + "," + y);
System.out.println("Stream.of(1,2,3).reduce(,acc,comb): " + sum);

```

自然地期望看到结果为`1,2,3`。但实际上我们看到的是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/64da187d-c5b8-4c95-9ac9-d47990d7dd77.png)

前面结果的原因是使用了组合器，因为流是顺序的。但现在让流并行化：

```java
String sum = Stream.of(1,2,3).parallel()  
    .reduce("", (p,e) -> p + e.toString(), (x,y) -> x + "," + y);
System.out.println("Stream.of(1,2,3).reduce(,acc,comb): " + sum);
```

前面的代码执行结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/012b5675-5bff-4cec-ac3d-9f36597dde57.png)

这意味着组合器仅在并行处理时才会被调用，以组装（合并）并行处理的不同子流的结果。这是我们迄今为止从声明意图提供顺序和并行流相同行为的唯一偏差。但是有许多方法可以在不使用`reduce()`的第三个版本的情况下实现相同的结果。例如，考虑以下代码：

```java
String sum = Stream.of(1,2,3)
                   .map(i -> i.toString() + ",")
                   .reduce("", (p,e) -> p + e);
System.out.println("Stream.of(1,2,3).map.reduce(,acc): " 
                   + sum.substring(0, sum.length()-1));

```

它产生与前一个示例相同的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/2619716a-1f9f-4782-8a21-9e330b1f5494.png)

现在让我们将其改为并行流：

```java
String sum = Stream.of(1,2,3).parallel()
                   .map(i -> i.toString() + ",")
                   .reduce("", (p,e) -> p + e);
System.out.println("Stream.of(1,2,3).map.reduce(,acc): " 
                   + sum.substring(0, sum.length()-1));

```

结果保持不变：`1,2,3`。

下一组中间操作称为`collect()`，包括两种方法：

```java
R collect(Collector<T,A,R> collector) 
R collect(Supplier<R> supplier, BiConsumer<R,T> accumulator, 
                                            BiConsumer<R,R> combiner) 
```

第一种接受`Collector<T,A,R>`作为参数。它比第二种更受欢迎，因为它由`Collectors`类支持，该类提供了`Collector`接口的多种实现。我们鼓励您查看`Collectors`类的 Javadoc 并了解其提供的功能。

让我们讨论一些使用`Collectors`类的示例。首先，我们将创建一个名为`Thing`的小型演示类：

```java
public class Thing {
  private int someInt;
  public Thing(int i) { this.someInt = i; }
  public int getSomeInt() { return someInt; }
  public String getSomeStr() { 
    return Integer.toString(someInt); }
} 
```

现在我们可以用它来演示一些收集器：

```java
double aa = Stream.of(1,2,3).map(Thing::new)
              .collect(Collectors.averagingInt(Thing::getSomeInt));
System.out.println("stream(1,2,3).averagingInt(): " + aa);

String as = Stream.of(1,2,3).map(Thing::new).map(Thing::getSomeStr)
                                 .collect(Collectors.joining(","));
System.out.println("stream(1,2,3).joining(,): " + as);

String ss = Stream.of(1,2,3).map(Thing::new).map(Thing::getSomeStr)
                       .collect(Collectors.joining(",", "[", "]"));
System.out.println("stream(1,2,3).joining(,[,]): " + ss);
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/c86fc553-23f1-4679-aa5e-e41571816ee9.png)

连接收集器对于任何曾经不得不编写代码来检查添加的元素是否是第一个、最后一个或删除最后一个字符的程序员来说都是一种乐趣的来源（就像我们在`reduce()`操作的示例中所做的那样）。`joining()`方法生成的收集器在幕后执行此操作。程序员唯一需要提供的是分隔符、前缀和后缀。

大多数程序员永远不需要编写自定义收集器。但是如果有需要，可以使用`Stream`的第二种方法`collect()`，并提供组成收集器的函数，或者使用两种`Collector.of()`静态方法之一来生成可以重复使用的收集器。

如果比较`reduce()`和`collect()`操作，您会注意到`reduce()`的主要目的是对不可变对象和原始类型进行操作。`reduce()`的结果通常是一个值，通常（但不一定）与流的元素类型相同。相比之下，`collect()`产生了一个不同类型的结果，包装在一个可变容器中。`collect()`的最常见用法是使用相应的`Collectors.toList()`、`Collectors.toSet()`或`Collectors.toMap()`收集器生成`List`、`Set`或`Map`对象。

最后一组终端操作包括两个`toArray()`方法：

```java
Object[] toArray() 
A[] toArray(IntFunction<A[]> generator)
```

第一个返回`Object[]`，第二个返回指定类型的数组。让我们看一下它们的使用示例：

```java
 Object[] os = Stream.of(1,2,3).toArray();
 Arrays.stream(os).forEach(System.out::print);
 System.out.println();
 String[] sts = Stream.of(1,2,3)
                      .map(i -> i.toString())
                      .toArray(String[]::new);
 Arrays.stream(sts).forEach(System.out::print);
```

这些示例的输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/fa432b46-098d-4fbe-b97d-1646a94aafbe.png)

第一个示例非常简单。值得注意的是，我们不能写以下内容：

```java
Stream.of(1,2,3).toArray().forEach(System.out::print);
```

这是因为`toArray()`是一个终端操作，流在执行后会自动关闭。这就是为什么我们必须在前面代码示例的第二行中打开一个新的流。

第二个示例——使用重载的`A[] toArray(IntFunction<A[]> generator)`方法——更加复杂。Javadoc ([`docs.oracle.com/javase/8/docs/api/java/util/stream/Stream.html`](https://docs.oracle.com/javase/8/docs/api/java/util/stream/Stream.html))中说，

“生成函数接受一个整数，这个整数是所需数组的大小，并生成所需大小的数组。”

这意味着在最后一个示例中对`toArray(String[]::new)`构造函数的方法引用是`toArray(size -> new String[size])`的缩写版本。

# 使用数字流进行算术运算

除了`Stream`接口之外，`java.util.stream`包还提供了专门的接口——`IntStream`、`DoubleStream`和`LongStream`——专门用于处理相应原始类型的流。它们非常方便使用，并且具有数字操作，如`max()`、`min()`、`average()`、`sum()`。

数字接口具有类似于`Stream`接口的方法，这意味着我们在前面的*创建和操作流*中讨论的所有内容也适用于数字流。这就是为什么在本节中，我们只会讨论`Stream`接口中不存在的方法。

# 准备工作

除了*创建和操作流*中描述的方法之外，还可以使用以下方法创建数字流：

+   `IntStream`和`LongStream`接口的`range(int startInclusive, int endInclusive)`和`rangeClosed(int startInclusive, int endInclusive)`方法

+   `java.util.Arrays`类的六个重载的`stream()`方法，将数组和子数组转换为数字流

特定于数字流的中间操作列表包括以下内容：

+   `boxed()`: 将原始类型的数字流转换为相应包装类型的流

+   `mapToObj(mapper)`: 使用提供的函数映射器将原始类型的数字流转换为对象流

+   `asDoubleStream()`的`LongStream`接口：将`LongStream`转换为`DoubleStream`

+   `asLongStream()`和`asDoubleStream()`的`IntStream`接口：将`IntStream`转换为相应的数字流

特定于数字流的终端算术操作列表包括以下内容：

+   `sum()`: 计算数字流元素的总和

+   `average()`: 计算数字流元素的平均值

+   `summaryStatistics()`：创建一个包含有关流元素的各种摘要数据的对象

# 如何做到...

1.  尝试使用`IntStream`和`LongStream`接口的`range(int startInclusive, int endInclusive)`和`rangeClosed(int startInclusive, int endInclusive)`方法：

```java
IntStream.range(1,3).forEach(System.out::print); //prints: 12
LongStream.range(1,3).forEach(System.out::print); //prints: 12
IntStream.rangeClosed(1,3).forEach(System.out::print);  // 123
LongStream.rangeClosed(1,3).forEach(System.out::print); // 123

```

如您所见，`range()`和`rangeClosed()`方法之间的区别在于第二个参数的排除或包含。这也导致了在两个参数具有相同值的情况下产生以下结果：

```java
IntStream.range(3,3).forEach(System.out::print);
                                                //prints:
LongStream.range(3,3).forEach(System.out::print);      
                                                //prints:
IntStream.rangeClosed(3,3).forEach(System.out::print); 
                                                //prints: 3
LongStream.rangeClosed(3,3).forEach(System.out::print);
                                                //prints: 3

```

在前面的示例中，`range()`方法不会发出任何元素，而`rangeClosed()`方法只会发出一个元素。

请注意，当第一个参数大于第二个参数时，这些方法都不会生成错误。它们只是不发出任何内容，随后的语句也不会产生输出：

```java
IntStream.range(3,1).forEach(System.out::print);        
LongStream.range(3,1).forEach(System.out::print);       
IntStream.rangeClosed(3,1).forEach(System.out::print);  
LongStream.rangeClosed(3,1).forEach(System.out::print); 

```

1.  如果您不需要流元素的值是顺序的，可以首先创建一个值的数组，然后使用`java.util.Arrays`类的六个重载的`stream()`静态方法之一生成流：

```java
IntStream stream(int[] array)
IntStream stream(int[] array, int startInclusive, 
 int endExclusive)
LongStream stream(long[] array)
LongStream stream(long[] array, int startInclusive, 
                                           int endExclusive)
DoubleStream stream(double[] array)
DoubleStream stream(double[] array, int startInclusive, 
                                           int endExclusive)
```

以下是`Arrays.stream()`方法的使用示例：

```java
int[] ai = {2, 3, 1, 5, 4};
Arrays.stream(ai)
      .forEach(System.out::print);  //prints: 23154
Arrays.stream(ai, 1, 3)
      .forEach(System.out::print);  //prints: 31
long[] al = {2, 3, 1, 5, 4};
Arrays.stream(al)
       .forEach(System.out::print);  //prints: 23154
Arrays.stream(al, 1, 3)
       .forEach(System.out::print);  //prints: 31
double[] ad = {2., 3., 1., 5., 4.};
Arrays.stream(ad)
  .forEach(System.out::print);  //prints: 2.03.01.05.04.0
Arrays.stream(ad, 1, 3)
      .forEach(System.out::print);  //prints: 3.01.0

```

最后两个流水线可以通过使用我们在上一篇文章中讨论的 joining 收集器来改进，以更加人性化的格式打印`DoubleStream`的元素：

```java
double[] ad = {2., 3., 1., 5., 4.};
String res = Arrays.stream(ad).mapToObj(String::valueOf)
                       .collect(Collectors.joining(" ")); 
System.out.println(res);   //prints: 2.0 3.0 1.0 5.0 4.0
res = Arrays.stream(ad, 1, 3).mapToObj(String::valueOf)
                       .collect(Collectors.joining(" "));  
System.out.println(res);               //prints: 3.0 1.0

```

由于`Collector<CharSequence, ?, String>` joining 收集器接受`CharSequence`作为输入类型，我们必须使用中间操作`mapToObj()`将数字转换为`String`。

1.  使用`mapToObj(mapper)`中间操作将原始类型元素转换为引用类型。我们在第 2 步中看到了它的使用示例。mapper 函数可以简单也可以复杂，以便实现必要的转换。

还有一个专门的操作`boxed()`，没有参数，可以将原始数值类型的元素转换为相应的包装类型——`int`值转换为`Integer`值，`long`值转换为`Long`值，`double`值转换为`Double`值。例如，我们可以使用它来实现与`mapToObj(mapper)`操作的最后两个示例相同的结果：

```java
double[] ad = {2., 3., 1., 5., 4.};
String res = Arrays.stream(ad).boxed()
                   .map(Object::toString)
                   .collect(Collectors.joining(" ")); 
System.out.println(res); //prints: 2.0 3.0 1.0 5.0 4.0
res = Arrays.stream(ad, 1, 3).boxed()
                     .map(Object::toString)
                     .collect(Collectors.joining(" ")); 
System.out.println(res); //prints: 3.0 1.0
```

1.  还有一些中间操作，可以将数值流的元素从一个原始类型转换为另一个原始类型：`IntStream`接口中的`asLongStream()`和`asDoubleStream()`，以及`LongStream`接口中的`asDoubleStream()`。让我们看看它们的使用示例：

```java
IntStream.range(1, 3).asLongStream()
              .forEach(System.out::print); //prints: 12
IntStream.range(1, 3).asDoubleStream()
 .forEach(d -> System.out.print(d + " ")); //prints: 1.0 2.0
LongStream.range(1, 3).asDoubleStream()
 .forEach(d -> System.out.print(d + " ")); //prints: 1.0 2.0

```

您可能已经注意到，这些操作仅适用于扩展原始转换：从`int`类型到`long`和`double`，以及从`long`到`double`。

1.  特定于数值流的终端算术操作非常简单。以下是`IntStream`的`sum()`和`average()`操作的示例：

```java
         int sum = IntStream.empty().sum();
         System.out.println(sum);                   //prints: 0
         sum = IntStream.range(1, 3).sum();
         System.out.println(sum);                   //prints: 3
         double av = IntStream.empty().average().orElse(0);
         System.out.println(av);                   //prints: 0.0
         av = IntStream.range(1, 3).average().orElse(0);
         System.out.println(av);                   //prints: 1.5

```

如您所见，`average()`操作返回`OptionalDouble`。有趣的是考虑为什么作者决定为`average()`返回`OptionalDouble`，但对于`sum()`却没有。这个决定可能是为了将空流映射到空的`OptionalDouble`，但是当`sum()`应用于空流时返回`0`的决定似乎是不一致的。

这些操作对`LongStream`和`DoubleStream`的行为方式相同：

```java
        long suml = LongStream.range(1, 3).sum();
        System.out.println(suml);                 //prints: 3
        double avl = LongStream.range(1, 3).average().orElse(0);
        System.out.println(avl);                  //prints: 1.5

        double sumd = DoubleStream.of(1, 2).sum();
        System.out.println(sumd);                 //prints: 3.0
        double avd = DoubleStream.of(1, 2).average().orElse(0);
        System.out.println(avd);                  //prints: 1.5

```

1.  `summaryStatistics()`终端操作收集有关流元素的各种摘要数据：

```java
     IntSummaryStatistics iss = 
                    IntStream.empty().summaryStatistics();
     System.out.println(iss);   //count=0, sum=0, 
       //min=2147483647, average=0.000000, max=-2147483648
     iss = IntStream.range(1, 3).summaryStatistics();
     System.out.println(iss);    //count=2, sum=3, min=1, 
                                 //average=1.500000, max=2

     LongSummaryStatistics lss = 
                    LongStream.empty().summaryStatistics();
     System.out.println(lss);  //count=0, sum=0, 
                               //min=9223372036854775807, 
               //average=0.000000, max=-9223372036854775808
     lss = LongStream.range(1, 3).summaryStatistics();
     System.out.println(lss);  //count=2, sum=3, min=1, 
                               //average=1.500000, max=2

     DoubleSummaryStatistics dss = 
                   DoubleStream.empty().summaryStatistics();
     System.out.println(dss);  //count=0, sum=0.000000, 
            //min=Infinity, average=0.000000, max=-Infinity
     dss = DoubleStream.of(1, 2).summaryStatistics();
     System.out.println(dss);  //count=2, sum=3.000000, 
             //min=1.000000, average=1.500000, max=2.000000

```

添加到前面打印行的注释来自`IntSummaryStatistics`、`LongSummaryStatistics`或`DoubleSummaryStatistics`对象的`toString()`方法。这些对象的其他方法包括`getCount()`、`getSum()`、`getMin()`、`getAverage()`和`getMax()`，允许访问收集统计的特定方面。

请注意，在空流的情况下，最小值（最大值）是相应 Java 类型的最小（最大）可能值：

```java
    System.out.println(Integer.MAX_VALUE); // 2147483647
    System.out.println(Integer.MIN_VALUE); //-2147483648
    System.out.println(Long.MAX_VALUE);    // 9223372036854775807
    System.out.println(Long.MIN_VALUE);    //-9223372036854775808
    System.out.println(Double.MAX_VALUE);  //1.7976931348623157E308
    System.out.println(Double.MIN_VALUE);  //4.9E-324

```

只有`DoubleSummaryStatistics`显示`Infinity`和`-Infinity`作为最小和最大值，而不是这里显示的实际数字。根据这些方法的 Javadoc，`getMax()`返回“记录的最大值，如果任何记录的值为`NaN`，则返回`Double.NaN`，如果没有记录值，则返回`Double.NEGATIVE_INFINITY`”，`getMin()`返回“记录的最小值，如果任何记录的值为`NaN`，则返回`Double.NaN`，如果没有记录值，则返回`Double.POSITIVE_INFINITY`”。

另外，请注意，与`average()`终端流操作相比，前述摘要统计的`getAverage()`方法返回流数值的算术平均值，如果从流中没有发出值，则返回零，而不是`Optional`对象。

# 还有更多...

`IntSummaryStatistics`、`LongSummaryStatistics`和`DoubleSummaryStatistics`对象不仅可以通过`summaryStatistics()`数字流终端操作创建。这样的对象也可以通过应用于任何`Stream`对象的`collect()`终端操作来创建，而不仅仅是`IntStream`、`LongStream`或`DoubleStream`。

每个摘要统计对象都有`accept()`和`combine()`方法，允许我们创建一个可以传递到`collect()`操作并产生相应摘要统计对象的`Collector`对象。我们将通过创建`IntSummaryStatistics`对象来演示这种可能性。`LongSummaryStatistics`和`DoubleSummaryStatistics`对象可以类似地创建。

`IntSummaryStatistics`类有以下两种方法：

+   void accept(int value)：将新值包含到统计摘要中

+   void combine(`IntSummaryStatistics` other)：将提供的`other`对象的收集统计信息添加到当前对象中

这些方法允许我们在任何`Stream`对象上使用`R collect(Supplier<R> supplier, BiConsumer<R,? super T> accumulator, BiConsumer<R,R> combiner)`操作的重载版本，如下所示：

```java
IntSummaryStatistics iss = Stream.of(3, 1)
        .collect(IntSummaryStatistics::new,
                 IntSummaryStatistics::accept,
                 IntSummaryStatistics::combine
        );
System.out.println(iss);  //count=2, sum=4, min=1, 
                          //average=2.000000, max=3

```

正如您所看到的，该流不是专门的数字流。它只有与创建的摘要统计对象相同类型的数值元素。尽管如此，我们仍然能够创建一个`IntSummaryStatistics`类的对象。同样，也可以创建`LongSummaryStatistics`和`DoubleSummaryStatistics`类的对象。

请注意，第三个参数`combiner`仅用于并行流处理——它将并行处理的子流的结果合并起来。为了演示这一点，我们可以将前面的示例更改如下：

```java
IntSummaryStatistics iss = Stream.of(3, 1)
   .collect(IntSummaryStatistics::new,
      IntSummaryStatistics::accept,
      (r, r1) -> {
        System.out.println("Combining...");  //is not printing
        r.combine(r1);
      }
   );
System.out.println(iss); //count=2, sum=4, min=1, 
                          //average=2.000000, max=3
```

`Combining...`行没有打印。让我们将流更改为并行流：

```java
IntSummaryStatistics iss = Stream.of(3, 1)
     .parallel()
     .collect(IntSummaryStatistics::new,
         IntSummaryStatistics::accept,
         (r, r1) -> {
             System.out.println("Combining...");  //Now it prints!
             r.combine(r1);
         }
     );
System.out.println(iss); //count=2, sum=4, min=1, 
                          //average=2.000000, max=3
```

如果现在运行前面的代码，您将看到`Combining...`行。

收集统计信息的另一种方法是使用`Collectors`类的以下方法之一创建的`Collector`对象：

```java
Collector<T, ?, IntSummaryStatistics> 
                   summarizingInt (ToIntFunction<T> mapper)
Collector<T, ?, LongSummaryStatistics> 
                  summarizingLong(ToLongFunction<T> mapper)
Collector<T, ?, DoubleSummaryStatistics> 
              summarizingDouble(ToDoubleFunction<T> mapper)
```

同样，我们将使用前述方法中的第一个来创建`IntSummaryStatistics`对象。假设我们有以下`Person`类：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.name = name;
        this.age = age;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
}
```

如果有一个`Person`类对象的流，我们可以按如下方式收集人的年龄（流元素）的统计信息：

```java
IntSummaryStatistics iss = 
   Stream.of(new Person(30, "John"), new Person(20, "Jill"))
         .collect(Collectors.summarizingInt(Person::getAge));
System.out.println(iss);     //count=2, sum=50, min=20, 
                             //average=25.000000, max=30

```

正如您所看到的，我们只能收集与收集统计信息类型匹配的对象字段的统计信息。流及其元素都不是数字。

在尝试创建自定义的`Collector`对象之前，查看`java.util.stream.Collectors`类的 Javadoc，看看它提供了哪些其他功能。

# 通过生成集合完成流

您将学习并练习如何使用`collect()`终端操作将流元素重新打包到目标集合结构中。

# 做好准备

`collect()`终端操作有两个重载版本，允许我们创建流元素的集合：

+   `R collect(Supplier<R> supplier, BiConsumer<R,T> accumulator, BiConsumer<R,R> combiner)`: 使用传入的函数应用于`T`类型的流元素产生`R`结果。提供的供应商和累加器一起工作如下：

```java
                 R result = supplier.get();
                 for (T element : this stream) {
                    accumulator.accept(result, element);
                 }
                 return result;
```

提供的组合器仅用于并行流的处理。它合并并行处理的子流的结果。

+   `R collect(Collector<T, A, R> collector)`: 使用传入的`Collector`对象应用于`T`类型的流元素产生`R`结果。`A`类型是`Collector`的中间累积类型。`Collector`对象可以使用`Collector.of()`工厂方法构建，但我们不打算在本教程中讨论它，因为`java.util.stream.Collectors`类中有许多可用的工厂方法可以满足大部分需求。此外，学会如何使用`Collectors`类后，您也将能够使用`Collector.of()`方法。

在本教程中，我们将演示如何使用`Collectors`类的以下方法：

+   `Collector<T, ?, List<T>> toList()`: 创建一个`Collector`对象，将`T`类型的流元素收集到一个`List<T>`对象中

+   `Collector<T, ?, Set<T>> toSet()`: 创建一个`Collector`对象，将`T`类型的流元素收集到一个`Set<T>`对象中

+   `Collector<T, ?, C> toCollection(Supplier<C> collectionFactory)`: 创建一个`Collector`对象，将`T`类型的流元素收集到由`collectionFactor`供应商产生的`C`类型的`Collection`中

+   `Collector<T, ?, List<T>> toUnmodifiableList()`: 创建一个`Collector`对象，将`T`类型的流元素收集到一个不可变的`List<T>`对象中

+   `Collector<T, ?, Set<T>> toUnmodifiableSet()`: 创建一个`Collector`对象，将`T`类型的流元素收集到一个不可变的`Set<T>`对象中

对于我们的演示，我们将使用以下`Person`类：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Person)) return false;
        Person person = (Person) o;
        return getAge() == person.getAge() &&
                Objects.equals(getName(), person.getName());
    }
    @Override
    public int hashCode() {
        return Objects.hash(getName(), getAge());
    }
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + this.age + "}";
    }
}
```

# 如何做到这一点...

我们将带您完成一系列实际步骤，演示如何使用前面的方法和类：

1.  编写使用`Stream<T>`接口的`R collect(Supplier<R> supplier, BiConsumer<R,T> accumulator, BiConsumer<R,R> combiner)`操作产生`List<T>`对象的用法示例：

```java
 List<Person> list = 
    Stream.of(new Person(30, "John"), new Person(20, "Jill"))
    .collect(ArrayList::new,
             List::add,      //same as: (a,p)-> a.add(p),
             List::addAll    //same as: (r, r1)-> r.addAll(r1)
    );
 System.out.println(list);
   //prints: [Person{name:John,age:30}, Person{name:Jill,age:20}]  
```

在前面的示例中，累加器和组合器的注释演示了如何将这些函数表示为 lambda 表达式，而不仅仅是方法引用。

第一个参数`Supplier<R>`返回结果的容器。在我们的例子中，我们将其定义为`ArrayList<Person>`类的构造函数，因为它实现了`List<Person>`接口，这是我们想要构造的对象类型。

累加器接受当前结果`a`（在我们的例子中将是`List<Person>`类型），并将下一个流元素`p`（在我们的例子中是`Person`对象）添加到其中。示例的输出显示为最后一行注释。

组合器将并行处理的子流的结果合并。它获取第一个结果`r`（任何第一个完成处理的子流的结果），并添加另一个结果`r1`，依此类推。这意味着组合器仅用于并行处理。为了证明这一点，让我们修改前面的代码如下：

```java
  List<Person> list = 
     Stream.of(new Person(30, "John"), new Person(20, "Jill"))
           .collect(ArrayList::new,
                    ArrayList::add,
                    (r, r1)-> {
                        System.out.println("Combining...");
                        r.addAll(r1);
                    }
           );
  System.out.println(list1);  
   //prints: [Person{name:John,age:30}, Person{name:Jill,age:20}]

```

如果运行前面的示例，您将看不到打印出`Combining...`行，因为`combiner`在顺序流处理中未被使用。

现在，让我们将流转换为并行流：

```java
 List<Person> list = 
    Stream.of(new Person(30, "John"), new Person(20, "Jill"))
          .parallel()
          .collect(ArrayList::new,
                   ArrayList::add,
                   (r, r1)-> {
                      System.out.println("Combining...");
                      r.addAll(r1);
                   }
          );
  System.out.println(list1);  
    //prints: [Person{name:John,age:30}, Person{name:Jill,age:20}]

```

如果运行前面的代码，将显示`Combining...`行。

只要每个函数的输入和返回类型保持不变，就可以根据需要修改提供的函数。

`Set<Person>`对象可以以相同的方式创建：

```java
 Set<Person> set = 
   Stream.of(new Person(30, "John"), new Person(20, "Jill"))
         .collect(HashSet::new,
                  Set::add,      //same as: (a,p)-> a.add(p),
                  Set::addAll    //same as: (r, r1)-> r.addAll(r1)
         );
 System.out.println(set);  
   //prints: [Person{name:John,age:30}, Person{name:Jill,age:20}]
```

创建的`List`或`Set`对象可以随时修改：

```java
list.add(new Person(30, "Bob"));
System.out.println(list);  //prints: [Person{name:John,age:30}, 
                           //         Person{name:Jill,age:20}, 
                           //         Person{name:Bob,age:30}]
list.set(1, new Person(15, "Bob"));
System.out.println(list);  //prints: [Person{name:John,age:30}, 
                           //         Person{name:Bob,age:15}, 
                           //         Person{name:Bob,age:30}]
set.add(new Person(30, "Bob"));
System.out.println(set);   //prints: [Person{name:John,age:30}, 
                           //         Person{name:Jill,age:20}, 
                           //         Person{name:Bob,age:30}]
```

我们已经提到它是为了与不可变集合的行为进行对比，我们很快就会讨论。

1.  编写使用由`Collector<T, ?, List<T>> Collectors.toList()`和`Collector<T, ?, Set<T>> Collectors.toSet()`方法创建的收集器的`R collect(Collector<T, A, R> collector)`操作的`Stream<T>`接口的用法示例：

```java
       List<Person> list = Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"))
                .collect(Collectors.toList());
       System.out.println(list);  //prints: [Person{name:John,age:30}, 
                                  //         Person{name:Jill,age:20}]

       Set<Person> set1 = Stream.of(new Person(30, "John"), 
                                    new Person(20, "Jill"))
                .collect(Collectors.toSet());
       System.out.println(set1); //prints: [Person{name:John,age:30}, 
                                            Person{name:Jill,age:20}]

       Set<Person> set2 = Stream.of(new Person(30, "John"), 
                                    new Person(20, "Jill"), 
                                    new Person(30, "John"))
                .collect(Collectors.toSet());
        System.out.println(set2); //prints: [Person{name:John,age:30}, 
                                             Person{name:Jill,age:20}]
        set2.add(new Person(30, "Bob"));
        System.out.println(set2); //prints: [Person{name:John,age:30}, 
                                             Person{name:Jill,age:20}, 
                                             Person{name:Bob,age:30}]

```

正如预期的那样，`Set`不允许由`equals()`方法实现定义的重复元素。在`Person`类的情况下，`equals()`方法比较年龄和姓名，因此这些属性的任何差异都会使两个`Person`对象不相等。

1.  编写使用由`Collector<T, ?, C> Collectors.toCollection(Supplier<C> collectionFactory)`方法创建的收集器的`R collect(Collector<T, A, R> collector)`操作的`Stream<T>`接口的用法示例。这个收集器的优点是它不仅可以收集流元素到`List`或`Set`中，而且可以收集到实现`Collection`接口的任何对象中。收集`T`类型的流元素的目标对象由`collectionFactor`供应商生成：

```java
LinkedList<Person> list = Stream.of(new Person(30, "John"), 
                                    new Person(20, "Jill"))
        .collect(Collectors.toCollection(LinkedList::new));
System.out.println(list);  //prints: [Person{name:John,age:30}, 
                            //        Person{name:Jill,age:20}]

LinkedHashSet<Person> set = Stream.of(new Person(30, "John"), 
                                      new Person(20, "Jill"))
        .collect(Collectors.toCollection(LinkedHashSet::new));
System.out.println(set);  //prints: [Person{name:John,age:30}, 
                                     Person{name:Jill,age:20}]
```

1.  编写使用由`Collector<T, ?, List<T>> Collectors.toUnmodifiableList()`和`Collector<T, ?, Set<T>> Collectors.toUnmodifiableSet()`方法创建的收集器的`R collect(Collector<T, A, R> collector)`操作的`Stream<T>`接口的用法示例：

```java
List<Person> list = Stream.of(new Person(30, "John"), 
                              new Person(20, "Jill"))
        .collect(Collectors.toUnmodifiableList());
System.out.println(list);  //prints: [Person{name:John,age:30}, 
                           //         Person{name:Jill,age:20}]

list.add(new Person(30, "Bob"));  //UnsupportedOperationException
list.set(1, new Person(15, "Bob")); //UnsupportedOperationException
list.remove(new Person(30, "John")); //UnsupportedOperationException

Set<Person> set = Stream.of(new Person(30, "John"), 
                            new Person(20, "Jill"))
        .collect(Collectors.toUnmodifiableSet());
System.out.println(set);  //prints: [Person{name:John,age:30}, 
                          //         Person{name:Jill,age:20}]

set.add(new Person(30, "Bob"));  //UnsupportedOperationException

```

从前面代码中的注释中可以看出，使用由`Collector<T, ?, List<T>> Collectors.toUnmodifiableList()`和`Collector<T, ?, Set<T>> Collectors.toUnmodifiableSet()`方法生成的收集器创建的对象是不可变的。当在 lambda 表达式中使用时，这样的对象非常有用，因为这样我们可以保证它们不会被修改，因此相同的表达式即使在不同的上下文中传递和执行，也只会产生依赖于其输入参数的结果，并且不会由于修改它使用的`List`或`Set`对象而产生意外的副作用。

例如：

```java
Set<Person> set = Stream.of(new Person(30, "John"), 
                            new Person(20, "Jill"))
        .collect(Collectors.toUnmodifiableSet());

Predicate<Person> filter = p -> set.contains(p);
```

在前面的例子中创建的过滤器可以在任何地方使用，以选择属于提供的集合的`Person`对象。

# 通过生成映射来完成流

您将学习并练习如何使用`collect()`终端操作将流元素重新打包到目标`Map`结构中。在讨论收集器时，我们不会包括使用分组的收集器，因为它们将在下一篇中介绍。

# 准备工作

如前一篇中提到的，`collect()`终端操作有两个重载版本，允许我们创建流元素的集合：

+   `R collect(Supplier<R> supplier, BiConsumer<R,T> accumulator, BiConsumer<R,R> combiner)`: 使用应用于`T`类型的流元素的传入函数生成`R`结果

+   `R collect(Collector<T, A, R> collector)`: 使用应用于`T`类型的流元素的传入`Collector`对象生成`R`结果

这些操作也可以用来创建`Map`对象，在本篇中，我们将演示如何做到这一点。

支持前述`collect()`操作的第二个版本，`Collectors`类提供了四组工厂方法，用于创建`Collector`对象。第一组包括与前一篇中讨论和演示的将流元素收集到`List`或`Set`中的`Collector`对象非常相似的工厂方法：

+   `Collector<T,?,Map<K,U>> toMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到`Map<K,U>`对象中，这些函数从流元素作为输入参数产生键和值。

+   `Collector<T,?,Map<K,U>> toMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到一个`Map<K,U>`对象中，这些函数从流元素中产生一个键和一个值作为输入参数。提供的`mergeFunction`仅用于并行流处理；它将子流的结果合并为最终结果——`Map<K,U>`对象。

+   `Collector<T,?,M> toMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction, Supplier<M> mapFactory)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到一个`Map<K,U>`对象中，这些函数从流元素中产生一个键和一个值作为输入参数。提供的`mergeFunction`仅用于并行流处理；它将子流的结果合并为最终结果——`Map<K,U>`对象。提供的`mapFactory`供应商创建一个空的`Map<K,U>`对象，结果将被插入其中。

+   `Collector<T,?,Map<K,U>> toUnmodifiableMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到一个*不可变*的`Map<K,U>`对象中，这些函数从流元素中产生一个键和一个值作为输入参数。

+   `Collector<T,?,Map<K,U>> toUnmodifiableMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到一个*不可变*的`Map<K,U>`对象中，这些函数从流元素中产生一个键和一个值作为输入参数。提供的`mergeFunction`仅用于并行流处理；它将子流的结果合并为最终结果——一个不可变的`Map<K,U>`对象。

第二组包括三个工厂方法，类似于我们刚刚列出的三个`toMap()`方法。唯一的区别是，由`toConcurrentMap()`方法创建的收集器将流元素收集到`ConcurrentMap`对象中：

+   `Collector<T,?,ConcurrentMap<K,U>> toConcurrentMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到一个`ConcurrentMap<K,U>`对象中，这些函数从流元素中产生一个键和一个值作为输入参数。

+   `Collector<T,?,ConcurrentMap<K,U>> toConcurrentMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到一个`ConcurrentMap<K,U>`对象中，这些函数从流元素中产生一个键和一个值作为输入参数。提供的`mergeFunction`仅用于并行流处理；它将子流的结果合并为最终结果——`ConcurrentMap<K,U>`对象。

+   `Collector<T,?,M> toConcurrentMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction, Supplier<M> mapFactory)`: 创建一个`Collector`对象，使用提供的函数（映射器）将`T`类型的流元素收集到一个`ConcurrentMap<K,U>`对象中，这些函数从流元素中产生一个键和一个值作为输入参数。提供的`mergeFunction`仅用于并行流处理；它将子流的结果合并为最终结果——`ConcurrentMap<K,U>`对象。提供的`mapFactory`供应商创建一个空的`ConcurrentMap<K,U>`对象，结果将被插入其中。

对于并行流，需要第二组工厂方法的原因是，合并不同子流的结果是一项昂贵的操作。当结果必须按照遇到的顺序合并到结果`Map`中时，这种操作尤其繁重——这就是`toMap()`工厂方法创建的收集器所做的。这些收集器创建多个中间结果，然后通过多次调用收集器的供应商和组合器来合并它们。

当结果合并的顺序不重要时，由`toConcurrentMap()`方法创建的收集器可以用作较轻量级的，因为它们只调用一次供应商，在*共享*结果容器中插入元素，并且从不调用组合器。

因此，`toMap()`和`toConcurrentMap()`收集器之间的区别只在并行流处理期间显现。这就是为什么通常建议对于串行流处理使用`toMap()`收集器，对于并行流处理使用`toConcurrentMap()`收集器（如果收集流元素的顺序不重要）。

第三组包括三个`groupingBy()`工厂方法，我们将在下一个示例中讨论。

第四组包括三个`groupingByConcurrent()`工厂方法，我们也将在下一个示例中讨论。

对于我们的演示，我们将使用与上一个示例中创建集合时相同的`Person`类：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Person)) return false;
        Person person = (Person) o;
        return getAge() == person.getAge() &&
                Objects.equals(getName(), person.getName());
    }
    @Override
    public int hashCode() {
        return Objects.hash(getName(), getAge());
    }
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + this.age + "}";
    }
}
```

# 如何做...

我们将带你走过一系列实际步骤，演示如何使用前面的方法和类：

1.  使用`Stream<T>`接口的`R collect(Supplier<R> supplier, BiConsumer<R,T> accumulator, BiConsumer<R,R> combiner)`操作的用法示例，生成`Map`对象。创建`Map<String, Person>`，以人名作为键：

```java
Map<String, Person> map = Stream.of(new Person(30, "John"), 
                                    new Person(20, "Jill"))
        .collect(HashMap::new,
                (m,p) -> m.put(p.getName(), p),
                Map::putAll
        );
System.out.println(map); //prints: {John=Person{name:John,age:30}, 
                         //         Jill=Person{name:Jill,age:20}}
```

或者，为了避免结果`Map`中的冗余数据，我们可以使用年龄字段作为`Map`的值：

```java
Map<String, Integer> map = Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"))
        .collect(HashMap::new,
                (m,p) -> m.put(p.getName(), p.getAge()),
                Map::putAll
        );
System.out.println(map);       //prints: {John=30, Jill=20}

```

组合器仅在并行流中调用，因为它用于组合不同子流处理的结果。为了证明这一点，我们已经用打印消息`Combining...`的代码块替换了方法引用`Map::putAll`：

```java
Map<String, Integer> map = Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"))
      //.parallel()     //conversion to a parallel stream
        .collect(HashMap::new,
                (m,p) -> m.put(p.getName(), p.getAge()),
                (m,m1) -> {
                      System.out.println("Combining...");
                      m.putAll(m1);
                }
        );
System.out.println(map);  //prints: {John=30, Jill=20}
```

只有在未注释掉转换为并行流时，才会显示`Combining...`消息。

如果我们添加另一个具有相同名称的`Person`对象，其中一个将在结果`Map`中被覆盖：

```java
Map<String, Integer> map = Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"),
                                     new Person(15, "John"))
        .collect(HashMap::new,
                (m,p) -> m.put(p.getName(), p.getAge()),
                Map::putAll
        );
System.out.println(map);       //prints: {John=15, Jill=20}
```

如果这种行为不可取，并且我们需要查看所有重复键的所有值，我们可以将结果`Map`更改为具有`List`对象作为值，这样在这个列表中我们可以收集所有具有相同键的值：

```java
BiConsumer<Map<String, List<Integer>>, Person> consumer = 
(m,p) -> {
    List<Integer> list = m.get(p.getName());
    if(list == null) {
        list = new ArrayList<>(); 
        m.put(p.getName(), list);
    }
    list.add(p.getAge());
};
Map<String, List<Integer>> map = 
  Stream.of(new Person(30, "John"), 
            new Person(20, "Jill"), 
            new Person(15, "John"))
        .collect(HashMap::new, consumer, Map::putAll);
System.out.println(map);
                   //prints: {John=[30, 15], Jill=[20]}

```

正如你所看到的，我们没有将`BiConsumer`函数内联到`collect()`操作中作为参数，因为现在它是多行代码，这样阅读起来更容易。

在这种情况下，收集相同键的多个值的另一种方法是创建具有`String`值的`Map`，如下所示：

```java
BiConsumer<Map<String, String>, Person> consumer2 = (m,p) -> {
 if(m.keySet().contains(p.getName())) {
   m.put(p.getName(), m.get(p.getName()) + "," + p.getAge());
 } else {
   m.put(p.getName(), String.valueOf(p.getAge()));
 }
};
Map<String, String> map = Stream.of(new Person(30, "John"), 
                                    new Person(20, "Jill"), 
                                    new Person(15, "John"))
        .collect(HashMap::new, consumer, Map::putAll);
System.out.println(map);    //prints: {John=30,15, Jill=20}
```

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ?, Map<K,U>> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`方法创建的收集器：

```java
Map<String, Integer> map = Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"))
  .collect(Collectors.toMap(Person::getName, Person::getAge));
System.out.println(map);     //prints: {John=30, Jill=20}
```

只要没有遇到重复键，前面的解决方案就能正常工作，就像下面的情况一样：

```java
Map<String, Integer> map = Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"),
                                     new Person(15, "John"))
.collect(Collectors.toMap(Person::getName, Person::getAge));

```

前面的代码抛出了`IllegalStateException`，并显示了`Duplicate key John`（尝试合并值 30 和 15）的消息，我们无法为重复键添加检查，就像之前做的那样。因此，如果存在重复键的可能性，就必须使用`toMap()`方法的重载版本。

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ?, Map<K,U>> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`方法创建的收集器：

```java
Function<Person, List<Integer>> valueMapper = p -> {
    List<Integer> list = new ArrayList<>();
    list.add(p.getAge());
    return list;
};
BinaryOperator<List<Integer>> mergeFunction = (l1, l2) -> {
    l1.addAll(l2);
    return l1;
};
Map<String, List<Integer>> map = 
   Stream.of(new Person(30, "John"), 
             new Person(20, "Jill"), 
             new Person(15, "John"))
         .collect(Collectors.toMap(Person::getName, 
                           valueMapper, mergeFunction));
System.out.println(map); 
                     //prints: {John=[30, 15], Jill=[20]}

```

这就是`mergeFunction`的目的——合并重复键的值。我们还可以将重复键的值收集到一个`String`对象中，而不是`List<Integer>`：

```java
Function<Person, String> valueMapper = 
                        p -> String.valueOf(p.getAge());
BinaryOperator<String> mergeFunction = 
                              (s1, s2) -> s1 + "," + s2;
Map<String, String> map = 
  Stream.of(new Person(30, "John"), 
            new Person(20, "Jill"), 
            new Person(15, "John"))
        .collect(Collectors.toMap(Person::getName, 
                           valueMapper, mergeFunction));
System.out.println(map3);//prints: {John=30,15, Jill=20}
```

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ?, M> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction, Supplier<M> mapFactory)`方法创建的收集器：

```java
Function<Person, String> valueMapper = 
                           p -> String.valueOf(p.getAge());
BinaryOperator<String> mergeFunction = 
                                 (s1, s2) -> s1 + "," + s2;
LinkedHashMap<String, String> map = 
   Stream.of(new Person(30, "John"), 
             new Person(20, "Jill"), 
             new Person(15, "John"))
         .collect(Collectors.toMap(Person::getName, 
           valueMapper, mergeFunction, LinkedHashMap::new));
System.out.println(map3);    //prints: {John=30,15, Jill=20} 
```

正如你所看到的，这个`toMap()`方法的版本允许我们指定所需的`Map`接口实现（在这种情况下是`LinkedHashMap`类），而不是使用默认的实现。

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ?, Map<K,U>> Collectors.toUnmodifiableMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`方法创建的收集器：

```java
Map<String, Integer> map = Stream.of(new Person(30, "John"), 
                                      new Person(20, "Jill"))
        .collect(Collectors.toUnmodifiableMap(Person::getName, 
                                              Person::getAge));
System.out.println(map);          //prints: {John=30, Jill=20}

map.put("N", new Person(42, "N")); //UnsupportedOperationExc
map.remove("John");                //UnsupportedOperationExc

Map<String, Integer> map = Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"), 
                                     new Person(15, "John"))
  .collect(Collectors.toUnmodifiableMap(Person::getName, 
    Person::getAge)); //IllegalStateExc: Duplicate key John

```

正如你所看到的，由`toUnmpdifiableMap()`方法创建的收集器的行为与由`Collector<T, ?, Map<K,U>> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`方法创建的收集器相同，只是它生成一个不可变的`Map`对象。

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ?, Map<K,U>> Collectors.toUnmodifiableMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`方法创建的收集器：

```java
Function<Person, List<Integer>> valueMapper = p -> {
    List<Integer> list = new ArrayList<>();
    list.add(p.getAge());
    return list;
};
BinaryOperator<List<Integer>> mergeFunction = (l1, l2) -> {
    l1.addAll(l2);
    return l1;
};
Map<String, List<Integer>> map = 
    Stream.of(new Person(30, "John"), 
              new Person(20, "Jill"), 
              new Person(15, "John"))
      .collect(Collectors.toUnmodifiableMap(Person::getName, 
                                valueMapper, mergeFunction));
System.out.println(map); //prints: {John=[30, 15], Jill=[20]}
```

由`toUnmpdifiableMap()`方法创建的收集器的行为与由`Collector<T, ?, Map<K,U>> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`方法创建的收集器相同，只是它生成一个不可变的`Map`对象。它的目的是处理重复键的情况。以下是另一种组合重复键值的方法：

```java
Function<Person, String> valueMapper = 
                             p -> String.valueOf(p.getAge());
BinaryOperator<String> mergeFunction = 
                                   (s1, s2) -> s1 + "," + s2;
Map<String, String> map = Stream.of(new Person(30, "John"), 
                                    new Person(20, "Jill"), 
                                    new Person(15, "John"))
    .collect(Collectors.toUnmodifiableMap(Person::getName, 
                                valueMapper, mergeFunction));
System.out.println(map);      //prints: {John=30,15, Jill=20}
```

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ? ,ConcurrentMap<K,U>> Collectors.toConcurrentMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`方法创建的收集器：

```java
ConcurrentMap<String, Integer> map = 
                            Stream.of(new Person(30, "John"), 
                                      new Person(20, "Jill"))
        .collect(Collectors.toConcurrentMap(Person::getName, 
                                            Person::getAge));
System.out.println(map);          /prints: {John=30, Jill=20}

map.put("N", new Person(42, "N")); //UnsupportedOperationExc
map.remove("John");                //UnsupportedOperationExc

ConcurrentMap<String, Integer> map = 
                           Stream.of(new Person(30, "John"), 
                                     new Person(20, "Jill"), 
                                     new Person(15, "John"))
  .collect(Collectors.toConcurrentMap(Person::getName, 
    Person::getAge)); //IllegalStateExc: Duplicate key John
```

正如你所看到的，由`toConcurrentMap()`方法创建的收集器的行为与由`Collector<T, ?, Map<K,U>> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`和`Collector<T, ?, Map<K,U>> Collectors.toUnmodifiableMap(Function<T,K> keyMapper, Function<T,U> valueMapper)`方法创建的收集器相同，只是它生成一个可变的`Map`对象，并且在流是并行的时候，在子流之间共享结果`Map`。

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ?, ConcurrentMap<K,U>> Collectors.toConcurrentMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`方法创建的收集器：

```java
Function<Person, List<Integer>> valueMapper = p -> {
    List<Integer> list = new ArrayList<>();
    list.add(p.getAge());
    return list;
};
BinaryOperator<List<Integer>> mergeFunction = (l1, l2) -> {
    l1.addAll(l2);
    return l1;
};
ConcurrentMap<String, List<Integer>> map = 
  Stream.of(new Person(30, "John"), 
            new Person(20, "Jill"), 
            new Person(15, "John"))
       .collect(Collectors.toConcurrentMap(Person::getName, 
                              valueMapper, mergeFunction));
System.out.println(map);
                       //prints: {John=[30, 15], Jill=[20]}
```

正如你所看到的，由`toConcurrentMap()`方法创建的收集器的行为与由`Collector<T, ?, Map<K,U>> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`和`Collector<T, ?, Map<K,U>> Collectors.toUnmodifiableMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction)`方法创建的收集器相同，只是它生成一个可变的`Map`对象，并且在流是并行的时候，在子流之间共享结果`Map`。以下是另一种组合重复键值的方法：

```java
Function<Person, String> valueMapper = 
                              p -> String.valueOf(p.getAge());
BinaryOperator<String> mergeFunction = 
                                    (s1, s2) -> s1 + "," + s2;
ConcurrentMap<String, String> map = 
                          Stream.of(new Person(30, "John"), 
                                    new Person(20, "Jill"), 
                                    new Person(15, "John"))
    .collect(Collectors.toConcurrentMap(Person::getName, 
                                 valueMapper, mergeFunction));
System.out.println(map);       //prints: {John=30,15, Jill=20}
```

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用`Collector<T, ?, M> Collectors.toConcurrentMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction, Supplier<M> mapFactory)`方法创建的收集器：

```java
ConcurrentSkipListMap<String, String> map = 
                             Stream.of(new Person(30, "John"), 
                                       new Person(20, "Jill"), 
                                       new Person(15, "John"))
   .collect(Collectors.toConcurrentMap(Person::getName, 
     valueMapper, mergeFunction, ConcurrentSkipListMap::new));
System.out.println(map4);      //prints: {Jill=20, John=30,15}
```

正如您所看到的，这个`toConcurrentMap()`方法的版本允许我们指定所需的`Map`接口实现（在本例中是`ConcurrentSkipListMap`类），而不是使用默认的实现。

`toConcurrentMap()`方法创建的收集器与`Collector<T, ?, Map<K,U>> Collectors.toMap(Function<T,K> keyMapper, Function<T,U> valueMapper, BinaryOperator<U> mergeFunction, Supplier<M> mapFactory)`方法创建的收集器行为相同，但在流并行时，它在子流之间共享结果`Map`。

# 通过使用分组收集器生成地图来完成流

在这个配方中，您将学习并练习如何使用`collect()`终端操作来按属性对元素进行分组，并使用收集器将结果存储在`Map`实例中。

# 准备工作

有两组收集器使用分组功能，类似于 SQL 语句的*group by*功能，将流数据呈现为`Map`对象。第一组包括三个重载的`groupingBy()`工厂方法：

+   `Collector<T, ?, Map<K,List<T>>> groupingBy(Function<T,K> classifier)`: 创建一个`Collector`对象，使用提供的`classifier`函数将`T`类型的流元素收集到`Map<K,List<T>>`对象中，将当前元素映射到结果地图中的键。

+   `Collector<T,?,Map<K,D>> groupingBy(Function<T,K> classifier, Collector<T,A,D> downstream)`: 创建一个`Collector`对象，使用提供的`classifier`函数将`T`类型的流元素收集到`Map<K,D>`对象中，将当前元素映射到中间地图`Map<K,List<T>>`中的键。然后使用`downstream`收集器将中间地图的值转换为结果地图`Map<K,D>`的值。

+   `Collector<T, ?, M> groupingBy(Function<T,K> classifier, Supplier<M> mapFactory, Collector<T,A,D> downstream)`: 创建一个`Collector`对象，使用提供的`classifier`函数将`T`类型的流元素收集到`M`地图对象中，将当前元素映射到`Map<K,List<T>>`中的键。然后使用`downstream`收集器将中间地图的值转换为`mapFactory`供应商提供的类型的结果地图的值。

第二组收集器包括三个`groupingByConcurrent()`工厂方法，用于在并行流处理期间处理并发。这些收集器接受与前面列出的`groupingBy()`收集器的相应重载版本相同的参数。唯一的区别是`groupingByConcurrent()`收集器的返回类型是`ConcurrentHashMap`类或其子类的实例：

+   `Collector<T, ?, ConcurrentMap<K,List<T>>> groupingByConcurrent(Function<T,K> classifier)`: 创建一个`Collector`对象，使用提供的`classifier`函数将`T`类型的流元素收集到`ConcurrentMap<K,List<T>>`对象中，将当前元素映射到结果地图中的键。

+   `Collector<T, ?, ConcurrentMap<K,D>> groupingByConcurrent(Function<T,K> classifier, Collector<T,A,D> downstream)`: 创建一个`Collector`对象，使用提供的`classifier`函数将`T`类型的流元素收集到`ConcurrentMap<K,D>`对象中，将当前元素映射到`ConcurrentMap<K,List<T>>`中的键。然后使用`downstream`收集器将中间地图的值转换为结果地图`ConcurrentMap<K,D>`的值。

+   `Collector<T, ?, M> groupingByConcurrent(Function<T,K> classifier, Supplier<M> mapFactory, Collector<T,A,D> downstream)`: 创建一个`Collector`对象，使用提供的`classifier`函数将`T`类型的流元素收集到`M`地图对象中，将当前元素映射到`ConcurrentMap<K,List<T>>`中的键。然后使用`downstream`收集器将中间地图的值转换为由`mapFactory`供应商提供的结果地图的值类型。

对于我们的演示，我们将使用在上一个示例中创建地图时使用的相同`Person`类：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Person)) return false;
        Person person = (Person) o;
        return getAge() == person.getAge() &&
                Objects.equals(getName(), person.getName());
    }
    @Override
    public int hashCode() {
        return Objects.hash(getName(), getAge());
    }
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + this.age + "}";
    }
}
```

我们还将使用`Person2`类：

```java
class Person2 {
    private int age;
    private String name, city;
    public Person2(int age, String name, String city) {
        this.age = age;
        this.name = name;
        this.city = city;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    public String getCity() { return this.city; }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Person)) return false;
        Person2 person = (Person2) o;
        return getAge() == person.getAge() &&
                Objects.equals(getName(), person.getName()) &&
                Objects.equals(getCity(), person.getCity());
    }
    @Override
    public int hashCode() {
        return Objects.hash(getName(), getAge(), getCity());
    }
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + this.age  + 
                                       ",city:" + this.city + "}";
    }
}
```

`Person2`类不同于`Person`类，因为它有一个额外的字段——城市。它将用于展示分组功能的强大功能。`Person2`类的变体`Person3`类将用于演示如何创建`EnumMap`对象。`Person3`类使用`enum City`作为其`city`属性的值类型：

```java
enum City{
    Chicago, Denver, Seattle
}

class Person3 {
    private int age;
    private String name;
    private City city;
    public Person3(int age, String name, City city) {
        this.age = age;
        this.name = name;
        this.city = city;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    public City getCity() { return this.city; }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Person)) return false;
        Person3 person = (Person3) o;
        return getAge() == person.getAge() &&
                Objects.equals(getName(), person.getName()) &&
                Objects.equals(getCity(), person.getCity());
    }
    @Override
    public int hashCode() {
        return Objects.hash(getName(), getAge(), getCity());
    }
    @Override
    public String toString() {
        return "Person{name:" + this.name + ",age:" + this.age  + 
                                       ",city:" + this.city + "}";
    }
}
```

为了使示例更简洁，我们将使用以下方法生成测试流：

```java
Stream<Person> getStreamPerson() {
    return Stream.of(new Person(30, "John"), 
                     new Person(20, "Jill"), 
                     new Person(20, "John"));
}
Stream<Person2> getStreamPerson2(){
    return Stream.of(new Person2(30, "John", "Denver"), 
                     new Person2(30, "John", "Seattle"), 
                     new Person2(20, "Jill", "Seattle"), 
                     new Person2(20, "Jill", "Chicago"), 
                     new Person2(20, "John", "Denver"),
                     new Person2(20, "John", "Chicago"));
}
Stream<Person3> getStreamPerson3(){
    return Stream.of(new Person3(30, "John", City.Denver), 
                     new Person3(30, "John", City.Seattle),
                     new Person3(20, "Jill", City.Seattle), 
                     new Person3(20, "Jill", City.Chicago),
                     new Person3(20, "John", City.Denver),
                     new Person3(20, "John", City.Chicago));
}
```

# 如何做...

我们将带您逐步演示如何使用前面的方法和类：

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用由`Collector<T, ?, Map<K,List<T>>> groupingBy(Function<T,K> classifier)`方法创建的收集器：

```java
Map<String, List<Person>> map = getStreamPerson()
        .collect(Collectors.groupingBy(Person::getName));
System.out.println(map);  
               //prints: {John=[Person{name:John,age:30}, 
               //               Person{name:John,age:20}], 
               //         Jill=[Person{name:Jill,age:20}]}

```

这是`Collector`对象的最简单版本。您只需定义结果地图的键是什么，收集器将把具有相同键值的所有流元素添加到结果地图中与该键关联的元素列表中。

这是另一个例子：

```java
Map<Integer, List<Person>> map = getStreamPerson()
        .collect(Collectors.groupingBy(Person::getAge));
System.out.println(map);  
                //prints: {20=[Person{name:Jill,age:20}, 
                //             Person{name:John,age:20}], 
                //         30=[Person{name:John,age:30}]}
```

如果流元素必须按属性组合分组，可以创建一个可以包含必要组合的类。这个类的对象将作为复杂键。例如，让我们读取`Person2`元素的流，并按年龄和姓名对它们进行分组。这意味着需要一个可以携带两个值的类。例如，这是一个这样的类，叫做`TwoStrings`：

```java
class TwoStrings {
    private String one, two;
    public TwoStrings(String one, String two) {
        this.one = one;
        this.two = two;
    }
    public String getOne() { return this.one; }
    public String getTwo() { return this.two; }
    @Override
    public boolean equals(Object o) {
       if (this == o) return true;
       if (!(o instanceof TwoStrings)) return false;
       TwoStrings twoStrings = (TwoStrings) o;
       return Objects.equals(getOne(), twoStrings.getOne()) 
           && Objects.equals(getTwo(), twoStrings.getTwo());
    }
    @Override
    public int hashCode() {
        return Objects.hash(getOne(), getTwo());
    }
    @Override
    public String toString() {
        return "(" + this.one + "," + this.two + ")";
    }
}
```

我们必须实现`equals()`和`hashCode()`方法，因为`TwoStrings`类的对象将被用作键，其值必须对于两个值的每个组合是特定的。现在我们可以这样使用它：

```java
Map<TwoStrings, List<Person2>> map = getStreamPerson2()
  .collect(Collectors.groupingBy(p -> 
            new TwoStrings(String.valueOf(p.getAge()), 
                                        p.getName())));
System.out.println(map);  
//prints: 
//   {(20,Jill)=[Person{name:Jill,age:20,city:Seattle}, 
//               Person{name:Jill,age:20,city:Chicago}], 
//    (20,John)=[Person{name:John,age:20,city:Denver}, 
//               Person{name:John,age:20,city:Chicago}], 
//    (30,John)=[Person{name:John,age:30,city:Denver}, 
//               Person{name:John,age:30,city:Seattle}]}

```

1.  使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的用法示例，使用由`Collector<T,?,Map<K,D>> groupingBy(Function<T,K> classifier, Collector<T,A,D> downstream)`方法创建的收集器：

```java
Map<String, Set<Person>> map = getStreamPerson()
   .collect(Collectors.groupingBy(Person::getName, 
                                  Collectors.toSet()));
System.out.println(map);  
             //prints: {John=[Person{name:John,age:30}, 
             //               Person{name:John,age:20}], 
             //         Jill=[Person{name:Jill,age:20}]}

```

如您所见，由`Collectors.groupingBy(Person::getName)`收集器产生的地图的`List<Person>`值后来（下游）被`Collectors.toSet()`收集器更改为集合。

或者，每个`List<Person>`值可以转换为列表元素的计数，如下所示：

```java
Map<String, Long> map = getStreamPerson()
        .collect(Collectors.groupingBy(Person::getName, 
                                        Collectors.counting()));
System.out.println(map);   //prints: {John=2, Jill=1}
```

要计算流中相同的`Person`对象（根据`equals()`方法相等的对象）的数量，我们可以使用 identity 函数，它被定义为返回不变的输入。例如：

```java
Stream.of("a","b","c")
      .map(s -> Function.identity()
      .apply(s))
      .forEach(System.out::print);  //prints: abc    
```

使用这个函数，我们可以计算相同人的数量，如下所示：

```java
Map<Person, Long> map = Stream.of(new Person(30, "John"), 
                                  new Person(20, "Jill"), 
                                  new Person(30, "John"))
        .collect(Collectors.groupingBy(Function.identity(), 
                                        Collectors.counting()));
System.out.println(map);  //prints: {Person{name:Jill,age:20}=1, 
                          //         Person{name:John,age:30}=2}
```

我们还可以计算每个人群中的平均年龄（一个群体被定义为具有相同的结果键值）：

```java
Map<String, Double> map = getStreamPerson()
        .collect(Collectors.groupingBy(Person::getName, 
                Collectors.averagingInt(Person::getAge)));
System.out.println(map);  //prints: {John=25.0, Jill=20.0}
```

要列出具有相同名称的人的年龄的所有值，我们可以使用由`Collector<T, ?, R> Collectors.mapping (Function<T,U> mapper, Collector<U,A,R> downstream)`方法创建的下游收集器：

```java
Map<String, List<Integer>> map = getStreamPerson()
   .collect(Collectors.groupingBy(Person::getName, 
            Collectors.mapping(Person::getAge, 
                               Collectors.toList())));
System.out.println(map);     
                  //prints: {John=[30, 20], Jill=[20]}

```

这个解决方案的另一个变化是下面的例子，对于每个年龄，创建一个逗号分隔的名称列表：

```java
Map<Integer, String> map = getStreamPerson()
 .collect(Collectors.groupingBy(Person::getAge, 
             Collectors.mapping(Person::getName, 
                            Collectors.joining(","))));
System.out.println(map);
                     //prints: {20=Jill, John, 30=John}
```

最后，为了演示另一种技术，我们可以使用嵌套的`groupingBy()`收集器创建一个包含年龄作为键和人名到他们所在城市的地图：

```java

Map<Integer, Map<String, String>> map = getStreamPerson2()
  .collect(Collectors.groupingBy(Person2::getAge, 
           Collectors.groupingBy(Person2::getName, 
                  Collectors.mapping(Person2::getCity, 
                              Collectors.joining(",")))));
System.out.println(map);  //prints: 
                          //   {20={John=Denver,Chicago, 
                          //        Jill=Seattle,Chicago}, 
                          //   30={John=Denver,Seattle}}
```

请注意，在前面的例子中我们使用了`Person2`流。

1.  写一个使用`Stream<T>`接口的`R collect(Collector<T, A, R> collector)`操作的示例，该操作使用`Collector<T, ?, M> groupingBy(Function<T,K> classifier, Supplier<M> mapFactory, Collector<T,A,D> downstream)`方法创建的收集器：

```java
LinkedHashMap<String, Long> map = getStreamPerson()
        .collect(Collectors.groupingBy(Person::getName, 
                                       LinkedHashMap::new, 
                                       Collectors.counting()));
System.out.println(map);  //prints: {John=2, Jill=1}
```

前面示例中的代码计算了在`Person`对象流中遇到每个名称的次数，并将结果放在由`mapFactory`函数（`groupingBy()`方法的第二个参数）定义的容器中（在本例中是`LinkedHashMap`）。

以下示例演示了如何告诉收集器基于`enum City`作为最终结果的容器使用`EnumMap`：

```java
EnumMap<City, List<Person3>> map = getStreamPerson3()
        .collect(Collectors.groupingBy(Person3::getCity, 
                            () -> new EnumMap<>(City.class), 
                                      Collectors.toList()));
System.out.println(map);  
 //prints: {Chicago=[Person{name:Jill,age:20,city:Chicago},  
 //                  Person{name:John,age:20,city:Chicago}], 
 //          Denver=[Person{name:John,age:30,city:Denver}, 
 //                  Person{name:John,age:20,city:Denver}], 
 //         Seattle=[Person{name:Jill,age:20,city:Seattle}, 
 //                  Person{name:John,age:30,city:Seattle}]}

```

请注意，在前面的例子中我们使用了`Person3`流。为了简化结果（避免在同一结果中重复显示城市）并且按年龄（对于每个城市）对人员进行分组，我们可以再次使用嵌套的`groupingBy()`收集器：

```java
EnumMap<City, Map<Integer, String>> map = getStreamPerson3()
   .collect(Collectors.groupingBy(Person3::getCity, 
                   () -> new EnumMap<>(City.class), 
             Collectors.groupingBy(Person3::getAge, 
             Collectors.mapping(Person3::getName, 
                                Collectors.joining(",")))));
System.out.println(map);  
                       //prints: {Chicago={20=Jill,John}, 
                       //         Denver={20=John, 30=John}, 
                       //         Seattle={20=Jill, 30=John}}
```

1.  作为第二组收集器的示例，那些由`groupingByConcurrent()`方法创建的收集器，所有前面的代码片段（最后两个使用`EnumMap`的除外）都可以通过将`groupingBy()`替换为`groupingByConcurrent()`和将结果的`Map`替换为`ConcurrentMap`类或其子类来使用。例如：

```java
ConcurrentMap<String, List<Person>> map1 = 
   getStreamPerson().parallel()
      .collect(Collectors.groupingByConcurrent(Person::getName));
System.out.println(map1);  
                     //prints: {John=[Person{name:John,age:30}, 
                     //               Person{name:John,age:20}], 
                     //         Jill=[Person{name:Jill,age:20}]}

ConcurrentMap<String, Double> map2 = 
   getStreamPerson().parallel()
    .collect(Collectors.groupingByConcurrent(Person::getName,       
                     Collectors.averagingInt(Person::getAge)));
System.out.println(map2);      //prints: {John=25.0, Jill=20.0}

ConcurrentSkipListMap<String, Long> map3 = 
    getStreamPerson().parallel()
       .collect(Collectors.groupingByConcurrent(Person::getName, 
           ConcurrentSkipListMap::new, Collectors.counting()));
System.out.println(map3);        //prints: {Jill=1, John=2}

```

正如我们之前提到的，`groupingByConcurrent()`收集器也可以处理顺序流，但它们设计用于处理并行流数据，因此我们已将前面的流转换为并行流。返回的结果是`ConcurrentHashMap`类型或其子类。

# 还有更多...

`Collectors`类还提供了由`partitioningBy()`方法生成的两个收集器，这些收集器是`groupingBy()`收集器的专门版本：

+   `Collector<T, ?, Map<Boolean,List<T>>> partitioningBy(Predicate<T> predicate)`: 使用提供的`predicate`函数将`T`类型的流元素收集到`Map<Boolean,List<T>>`对象中，创建一个`Collector`对象。

+   `Collector<T, ?, Map<Boolean,D>> partitioningBy(Predicate<T> predicate, Collector<T,A,D> downstream)`：创建一个`Collector`对象，使用提供的`predicate`函数将`T`类型的流元素收集到`Map<Boolean,D>`对象中，将当前元素映射到`Map<K,List<T>>`中的键。然后使用`downstream`收集器将中间映射的值转换为结果映射的值，`Map<Boolean,D>`。

让我们来看一些例子。以下是如何使用前面的方法之一将`Person`流元素收集到两个组中的示例——一个组包含包含字母`i`的名称，另一个组包含不包含字母`i`的名称：

```java
Map<Boolean, List<Person>> map = getStreamPerson()
  .collect(Collectors.partitioningBy(p-> p.getName().contains("i")));
System.out.println(map);  //prints: {false=[Person{name:John,age:30}, 
                          //                Person{name:John,age:20}], 
                          //          true=[Person{name:Jill,age:20}]}
```

为了演示第二种方法的使用，我们可以将在前面示例中创建的地图中的每个`List<Person>`值转换为列表大小：

```java
Map<Boolean, Long> map = getStreamPerson()
  .collect(Collectors.partitioningBy(p-> p.getName().contains("i"),  
                                           Collectors.counting()));
System.out.println(map);  //prints: {false=2, true=1}

```

使用`groupingBy()`方法也可以实现相同的结果：

```java
Map<Boolean, List<Person>> map1 = getStreamPerson()
   .collect(Collectors.groupingBy(p-> p.getName().contains("i")));
System.out.println(map); //prints: {false=[Person{name:John,age:30}, 
                          //               Person{name:John,age:20}], 
                          //         true=[Person{name:Jill,age:20}]}

Map<Boolean, Long> map2 = getStreamPerson()
     .collect(Collectors.groupingBy(p-> p.getName().contains("i"),  
                                          Collectors.counting()));
System.out.println(map2);  //prints: {false=2, true=1}
```

由`partitioningBy()`方法创建的收集器被认为是`groupingBy()`方法创建的收集器的一个特殊版本，并且预计允许我们在流元素被分成两组并存储在具有布尔键的地图中时编写更少的代码。但是，正如您从前面的代码中看到的那样，并非总是如此。我们的示例中的`partitioningBy()`收集器要求我们编写与`groupingBy()`收集器完全相同数量的代码。

# 创建流操作管道

在这个示例中，您将学习如何从`Stream`操作构建管道。

# 准备工作

在上一章，第四章，*函数式编程*中，当创建一个 lambda 友好的 API 时，我们最终得到了以下 API 方法：

```java
public interface Traffic {
  void speedAfterStart(double timeSec, 
    int trafficUnitsNumber, SpeedModel speedModel, 
    BiPredicate<TrafficUnit, Double> limitTraffic,     
    BiConsumer<TrafficUnit, Double> printResult);
 }
```

指定数量的`TrafficUnit`实例是在`speedAfterStart()`方法中生成的。它们受到`limitTrafficAndSpeed`函数的限制，并根据`speedModel`函数在`speedAfterStart()`方法中进行处理。结果由`printResults`函数格式化。

这是一个非常灵活的设计，可以通过修改传递给 API 的函数来进行各种实验。但实际上，在数据分析的早期阶段，创建 API 需要更多的代码编写。这只有在长期内并且设计的灵活性允许我们在零或非常少的代码更改的情况下才能回报。

在研究阶段，情况发生了根本性的变化。当新算法被开发或者需要处理大量数据时，系统的各个层面之间的透明度成为基本要求。没有它，今天在大数据分析方面的许多成功将是不可能的。

流和管道解决了透明度问题，并最小化了编写基础设施代码的开销。

# 如何做到这一点...

让我们回顾一下用户如何调用 lambda-friendly API：

```java
double timeSec = 10.0;
int trafficUnitsNumber = 10;

SpeedModel speedModel = (t, wp, hp) -> ...;
BiConsumer<TrafficUnit, Double> printResults = (tu, sp) -> ...;
BiPredicate<TrafficUnit, Double> limitSpeed = (tu, sp) -> ...;

Traffic api = new TrafficImpl(Month.APRIL, DayOfWeek.FRIDAY, 17, 
                              "USA", "Denver", "Main103S");
api.speedAfterStart(timeSec, trafficUnitsNumber, speedModel, 
                    limitSpeed, printResults);
```

正如我们已经注意到的，这样的 API 可能无法涵盖模型可能发展的所有可能方式，但它是一个很好的起点，可以让我们以更透明和灵活的实验方式构建操作流和管道。

现在，让我们来看一下 API 的实现：

```java
double timeSec = 10.0;
int trafficUnitsNumber = 10;

SpeedModel speedModel = (t, wp, hp) -> ...;
BiConsumer<TrafficUnit, Double> printResults = (tu, sp) -> ...;
BiPredicate<TrafficUnit, Double> limitSpeed = (tu, sp) -> ...;
List<TrafficUnit> trafficUnits = FactoryTraffic
     .generateTraffic(trafficUnitsNumber, Month.APRIL, 
                      DayOfWeek.FRIDAY, 17, "USA", "Denver",
                      "Main103S");
for(TrafficUnit tu: trafficUnits){
  Vehicle vehicle = FactoryVehicle.build(tu);
  vehicle.setSpeedModel(speedModel);
  double speed = vehicle.getSpeedMph(timeSec);
  speed = Math.round(speed * tu.getTraction());
    if(limitSpeed.test(tu, speed)){
      printResults.accept(tu, speed);
    }
  }
```

我们可以将`for`循环转换为交通单位的流，并直接将相同的函数应用于流的元素。但首先，我们可以要求交通生成系统向我们提供一个`Stream`，而不是数据的`List`。这样可以避免将所有数据存储在内存中：

```java
Stream<TrafficUnit> stream = FactoryTraffic
       .getTrafficUnitStream(trafficUnitsNumber, Month.APRIL,
            DayOfWeek.FRIDAY, 17, "USA", "Denver", "Main103S");
```

现在，我们可以处理无限数量的交通单位，而不需要一次存储超过一个单位的内存。在演示代码中，我们仍然使用`List`，因此流式处理并不能节省我们的内存。但在真实系统中，例如从各种传感器收集数据的系统中，使用流可以帮助减少或完全避免内存使用方面的问题。

我们还将创建一个便利的方法：

```java
Stream<TrafficUnit>getTrafficUnitStream(int trafficUnitsNumber){
  return FactoryTraffic.getTrafficUnitStream(trafficUnitsNumber,
                       Month.APRIL, DayOfWeek.FRIDAY, 17, "USA", 
                                          "Denver", "Main103S");
}
```

有了这个，我们可以写下以下内容：

```java
getTrafficUnitStream(trafficUnitsNumber).map(tu -> {
   Vehicle vehicle = FactoryVehicle.build(tu);
   vehicle.setSpeedModel(speedModel);
   return vehicle;
})
.map(v -> {
   double speed = v.getSpeedMph(timeSec);
   return Math.round(speed * tu.getTraction());
})
.filter(s -> limitSpeed.test(tu, s))
.forEach(tuw -> printResults.accept(tu, s));
```

我们将`TrafficUnit`映射（转换）为`Vehicle`，然后将`Vehicle`映射为`speed`，然后使用当前的`TrafficUnit`实例和计算出的`speed`来限制交通并打印结果。如果您在现代编辑器中有这段代码，您会注意到它无法编译，因为在第一个映射之后，当前的`TrafficUnit`元素不再可访问——它被`Vehicle`替换了。这意味着我们需要携带原始元素，并在途中添加新值。为了实现这一点，我们需要一个容器——一种交通单位包装器。让我们创建一个：

```java
class TrafficUnitWrapper {
  private double speed;
  private Vehicle vehicle;
  private TrafficUnit trafficUnit;
  public TrafficUnitWrapper(TrafficUnit trafficUnit){
    this.trafficUnit = trafficUnit;
  }
  public TrafficUnit getTrafficUnit(){ return this.trafficUnit; }
  public Vehicle getVehicle() { return vehicle; }
  public void setVehicle(Vehicle vehicle) { 
    this.vehicle = vehicle; 
  }
  public double getSpeed() { return speed; }
  public void setSpeed(double speed) { this.speed = speed; }
}
```

现在，我们可以构建一个有效的管道：

```java
getTrafficUnitStream(trafficUnitsNumber)
  .map(TrafficUnitWrapper::new)
  .map(tuw -> {
       Vehicle vehicle = FactoryVehicle.build(tuw.getTrafficUnit());
       vehicle.setSpeedModel(speedModel);
       tuw.setVehicle(vehicle);
       return tuw;
   })
  .map(tuw -> {
       double speed = tuw.getVehicle().getSpeedMph(timeSec);
       speed = Math.round(speed * tuw.getTrafficUnit().getTraction());
       tuw.setSpeed(speed);
       return tuw;
  })
  .filter(tuw -> limitSpeed.test(tuw.getTrafficUnit(),tuw.getSpeed()))
  .forEach(tuw -> printResults.accept(tuw.getTrafficUnit(), 
                                                     tuw.getSpeed()));
```

代码看起来有点冗长，特别是`Vehicle`和`SpeedModel`的设置。我们可以通过将它们移动到`TrafficUntiWrapper`类中来隐藏这些细节：

```java
class TrafficUnitWrapper {
  private double speed;
  private Vehicle vehicle;
  private TrafficUnit trafficUnit;
  public TrafficUnitWrapper(TrafficUnit trafficUnit){
    this.trafficUnit = trafficUnit;
    this.vehicle = FactoryVehicle.build(trafficUnit);
  }
  public TrafficUnitWrapper setSpeedModel(SpeedModel speedModel) {
    this.vehicle.setSpeedModel(speedModel);
    return this;
  }
  pubic TrafficUnit getTrafficUnit(){ return this.trafficUnit; }
  public Vehicle getVehicle() { return vehicle; }
  public double getSpeed() { return speed; }
  public TrafficUnitWrapper setSpeed(double speed) { 
    this.speed = speed;
    return this; 
  }
}
```

请注意，我们从`setSpeedModel()`和`setSpeed()`方法中返回`this`。这使我们能够保持流畅的风格。现在，管道看起来更加清晰：

```java
getTrafficUnitStream(trafficUnitsNumber)
  .map(TrafficUnitWrapper::new)
  .map(tuw -> tuw.setSpeedModel(speedModel))
  .map(tuw -> {
       double speed = tuw.getVehicle().getSpeedMph(timeSec);
       speed = Math.round(speed * tuw.getTrafficUnit().getTraction());
       return tuw.setSpeed(speed);
   })
  .filter(tuw -> limitSpeed.test(tuw.getTrafficUnit(),tuw.getSpeed()))
  .forEach(tuw -> printResults.accept(tuw.getTrafficUnit(), 
                                                     tuw.getSpeed()));
```

如果不需要轻松访问速度计算的公式，我们可以通过将其移动到`TrafficUnitWrapper`类中，将`setSpeed()`方法更改为`calcSpeed()`：

```java
TrafficUnitWrapper calcSpeed(double timeSec) {
   double speed = this.vehicle.getSpeedMph(timeSec);
   this.speed = Math.round(speed * this.trafficUnit.getTraction());
   return this;
}
```

因此，管道变得更加简洁：

```java
getTrafficUnitStream(trafficUnitsNumber)
   .map(TrafficUnitWrapper::new)
   .map(tuw -> tuw.setSpeedModel(speedModel))
   .map(tuw -> tuw.calcSpeed(timeSec))
   .filter(tuw -> limitSpeed.test(tuw.getTrafficUnit(),
                                                  tuw.getSpeed()))
   .forEach(tuw -> printResults.accept(tuw.getTrafficUnit(),
                                                  tuw.getSpeed()));
```

基于这种技术，我们现在可以创建一个计算交通密度的方法——在多车道道路的每条车道上，根据每条车道的速度限制计算车辆的数量：

```java
Integer[] trafficByLane(Stream<TrafficUnit> stream,
       int trafficUnitsNumber, double timeSec, 
       SpeedModel speedModel, double[] speedLimitByLane) {
   int lanesCount = speedLimitByLane.length;
   Map<Integer, Integer> trafficByLane = stream
     .limit(trafficUnitsNumber)
     .map(TrafficUnitWrapper::new)
     .map(tuw -> tuw.setSpeedModel(speedModel))
     .map(tuw -> tuw.calcSpeed(timeSec))
     .map(speed -> countByLane(lanesCount, 
                               speedLimitByLane, speed))
     .collect(Collectors.groupingBy(CountByLane::getLane, 
           Collectors.summingInt(CountByLane::getCount)));
   for(int i = 1; i <= lanesCount; i++){
      trafficByLane.putIfAbsent(i, 0);
   }
   return trafficByLane.values()
                       .toArray(new Integer[lanesCount]);
}
```

前面方法使用的私有`CountByLane`类如下所示：

```java
private class CountByLane {
  int count, lane;
  private CountByLane(int count, int lane){
    this.count = count;
    this.lane = lane;
  }
  public int getLane() { return lane; }
  public int getCount() { return count; }
}
```

以下是私有`TrafficUnitWrapper`类的样子：

```java
private static class TrafficUnitWrapper {
  private Vehicle vehicle;
  private TrafficUnit trafficUnit;
  public TrafficUnitWrapper(TrafficUnit trafficUnit){
    this.vehicle = FactoryVehicle.build(trafficUnit);
    this.trafficUnit = trafficUnit;
  }
  public TrafficUnitWrapper setSpeedModel(SpeedModel speedModel) {
    this.vehicle.setSpeedModel(speedModel);
    return this;
  }
  public double calcSpeed(double timeSec) {
    double speed = this.vehicle.getSpeedMph(timeSec);
    return Math.round(speed * this.trafficUnit.getTraction());
  }
}
```

`countByLane()`私有方法的代码如下：

```java
private CountByLane countByLane(int lanesNumber, 
                                   double[] speedLimit, double speed){
  for(int i = 1; i <= lanesNumber; i++){
     if(speed <= speedLimit[i - 1]){ 
        return new CountByLane(1, i);
     }
  }
  return new CountByLane(1, lanesNumber);
}
```

在第十四章中，*测试*，我们将更详细地讨论`TrafficDensity`类的这种方法，并重新审视这个实现以便更好地进行单元测试。这就是为什么在代码开发的同时编写单元测试会带来更高的生产力；它消除了之后改变代码的需要。它还会产生更可测试（更高质量）的代码。

# 还有更多…

管道允许轻松添加另一个过滤器，或者任何其他操作：

```java
Predicate<TrafficUnit> limitTraffic = tu ->
    tu.getVehicleType() == Vehicle.VehicleType.CAR
    || tu.getVehicleType() == Vehicle.VehicleType.TRUCK;

getTrafficUnitStream(trafficUnitsNumber)
   .filter(limitTraffic)
   .map(TrafficUnitWrapper::new)
   .map(tuw -> tuw.setSpeedModel(speedModel))
   .map(tuw -> tuw.calcSpeed(timeSec))
   .filter(tuw -> limitSpeed.test(tuw.getTrafficUnit(), 
                                            tuw.getSpeed()))
   .forEach(tuw -> printResults.accept(tuw.getTrafficUnit(), 
                                           tuw.getSpeed()));
```

当需要处理多种类型的数据时，这一点尤为重要。值得一提的是，在进行计算之前进行过滤是提高性能的最佳方式，因为它可以避免不必要的计算。

使用流的另一个主要优势是可以在不额外编码的情况下使流程并行化。你只需要将管道的第一行改为`getTrafficUnitStream(trafficUnitsNumber).parallel()`（假设源不生成并行流，可以通过`.isParallel()`操作来识别）。我们将在下一个示例中更详细地讨论并行处理。

# 并行处理流

在之前的示例中，我们演示了一些并行流处理的技术。在这个示例中，我们将更详细地讨论处理，并分享常见问题的最佳实践和解决方案。

# 做好准备

很诱人的是将所有流都设置为并行，然后不再考虑它。不幸的是，并行并不总是有利的。事实上，它会因为工作线程的协调而产生开销。此外，一些流源是顺序的，一些操作可能共享相同的（同步的）资源。更糟糕的是，在并行处理中使用有状态的操作可能导致不可预测的结果。这并不意味着不能在并行流中使用有状态的操作，但它需要仔细规划和清晰理解在并行处理的子流之间如何共享状态。

# 如何做…

正如前面的示例中提到的，可以通过集合的`parallelStream()`方法或应用于流的`parallel()`方法来创建并行流。相反，可以使用`sequential()`方法将现有的并行流转换为顺序流。

首先，应该默认使用顺序流，并且只有在必要和可能的情况下才考虑并行流。通常情况下，如果性能不够好并且需要处理大量数据，才会出现这种需求。流源和操作的性质限制了可能性。例如，从文件中读取是顺序的，基于文件的流在并行中表现并不更好。任何阻塞操作也会抵消并行的性能提升。

顺序流和并行流不同的一个领域是顺序。这里有一个例子：

```java
List.of("This ", "is ", "created ", "by ",
         "List.of().stream()").stream().forEach(System.out::print);
System.out.println();
List.of("This ", "is ", "created ", "by ", 
          "List.of().parallelStream()")
                      .parallelStream().forEach(System.out::print);
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/f3c994e3-4ae8-4123-b7d8-8c13afe401a2.png)

正如你所看到的，`List`保留了元素的顺序，但在并行处理的情况下不保持顺序。

在*创建和操作流*的示例中，我们演示了对于`reduce()`和`collect()`操作，组合器只会在并行流中被调用。因此，在顺序流处理时不需要组合器，但在并行流操作时必须存在。没有组合器，多个工作线程的结果就无法正确聚合。

我们还演示了在并行处理的情况下，`sorted()`、`distinct()`、`limit()`和`skip()`这些有状态的操作会产生非确定性的结果。

如果顺序很重要，我们已经证明您可以依赖`forEachOrdered()`操作。它不仅保证处理流的所有元素，而且按照其源指定的顺序进行处理，无论流是顺序的还是并行的。

并行流可以通过`parallelStream()`方法或`parallel()`方法创建。一旦创建，它在处理过程中使用`ForkJoin`框架：原始流被分成段（子流），然后分配给不同的工作线程进行处理，然后所有结果（每个子流处理的结果）被聚合并呈现为原始流处理的最终结果。在只有一个处理器的计算机上，这样的实现没有优势，因为处理器是共享的。但在多核计算机上，工作线程可以由不同的处理器执行。更重要的是，如果一个工作线程变得空闲，它可以从忙碌的工作线程那里*偷取*一部分工作。然后从所有工作线程收集结果，并为终端操作的完成（即收集操作的组合器变得繁忙时）进行聚合。

一般来说，如果有一个资源在并发访问时不安全，那么在并行流处理期间使用它也是不安全的。考虑这两个例子（`ArrayList`不被认为是线程安全的）：

```java
List<String> wordsWithI = new ArrayList<>();
Stream.of("That ", "is ", "a ", "Stream.of(literals)")
      .parallel()
      .filter(w -> w.contains("i"))
      .forEach(wordsWithI::add);
System.out.println(wordsWithI);
System.out.println();

wordsWithI = Stream.of("That ", "is ", "a ", "Stream.of(literals)" )
                   .parallel()
                   .filter(w -> w.contains("i"))
                   .collect(Collectors.toList());
System.out.println(wordsWithI);
```

如果运行多次，此代码可能会产生以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java11-cb/img/85352637-6444-46ab-a438-087e3d601812.png)

`Collectors.toList()`方法总是生成相同的列表，其中包括`is`和`Stream.of(literals)`，而`forEach()`偶尔会漏掉`is`或`Stream.of(literals)`。

如果可能的话，首先尝试使用`Collectors`类构造的收集器，并避免在并行计算期间使用共享资源。

总的来说，使用无状态函数是并行流管道的最佳选择。如果有疑问，请测试您的代码，最重要的是多次运行相同的测试，以检查结果是否稳定。
