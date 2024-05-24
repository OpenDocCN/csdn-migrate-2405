# Java 编程入门（六）

> 原文：[`zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B`](https://zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：管理集合和数组

我们将在本章中讨论的类允许我们创建、初始化和修改 Java 集合和数组的对象。它们还允许创建不可修改和不可变集合。这些类中的一些属于 Java 标准库，其他属于流行的 Apache Commons 库。了解这些类并熟悉它们的方法对于任何 Java 程序员都是必不可少的。

我们将涵盖以下功能领域：

+   管理集合

+   管理数组

概述的类列表包括：

+   `java.util.Collections`

+   `org.apache.commons.collections4.CollectionUtils`

+   `java.util.Arrays`

+   `org.apache.commons.lang3.ArrayUtils`

# 管理集合

在本节中，我们将回顾如何创建和初始化集合对象，什么是不可变集合，以及如何对集合执行基本操作——复制、排序和洗牌，例如。

# 初始化集合

我们已经看到了一些不带参数的集合构造函数的示例。现在，我们将看到创建和初始化集合对象的其他方法。

# 集合构造函数

每个集合类都有一个接受相同类型元素集合的构造函数。例如，这是如何使用`ArrayList(Collection collection)`构造函数创建`ArrayList`类的对象，以及如何使用`HashSet(Collection collection)`构造函数创建`HashSet`类的对象：

```java
List<String> list1 = new ArrayList<>();
list1.add("s1");
list1.add("s1");

List<String> list2 = new ArrayList<>(list1);
System.out.println(list2);      //prints: [s1, s1]

Set<String> set = new HashSet<>(list1);
System.out.println(set);        //prints: [s1]

List<String> list3 = new ArrayList<>(set);
System.out.println(list3);      //prints: [s1]

```

我们将在*使用其他对象和流*子部分中展示更多使用这些构造函数的示例。

# 实例初始化程序（双括号）

可以使用双括号初始化器进行集合初始化。当集合是实例字段的值时，它特别适用，因此在对象创建期间会自动初始化。这是一个例子：

```java
public class ManageCollections {
  private List<String> list = new ArrayList<>() {
        {
            add(null);
            add("s2");
            add("s3");
        }
  };
  public List<String> getThatList(){
      return this.list;
  }
  public static void main(String... args){
    ManageCollections mc = new ManageCollections();
    System.out.println(mc.getThatList());    //prints: [null, s2, s3]
  }
}
```

我们添加了一个 getter，并在`main()`方法运行时使用它。不幸的是，双括号初始化器与构造函数中的传统集合初始化相比并没有节省任何输入时间：

```java
public class ManageCollections {
  private List<String> list = new ArrayList<>();
  public ManageCollections(){
        list.add(null);
        list.add("s2");
        list.add("s3");
  }
  public List<String> getThatList(){
      return this.list;
  }
  public static void main(String... args){
    ManageCollections mc = new ManageCollections();
    System.out.println(mc.getThatList());    //prints: [null, s2, s3]
  }
}
```

唯一的区别是每次调用`add()`方法时都需要为`list`变量输入。此外，双括号初始化器有一个额外的开销，它创建了一个只有实例初始化程序和对封闭类的引用的匿名类。它也可能有更多的问题，因此应该避免使用。

好消息是，有一种更短、更方便的初始化集合的方法，作为字段值或局部变量值：

```java
private List<String> list = Arrays.asList(null, "s2", "s3");

```

`java.util.Arrays`的`asList()`静态方法非常受欢迎（我们将很快更详细地讨论`Arrays`类）。唯一的潜在缺点是这样的列表不允许添加元素：

```java
List<String> list = Arrays.asList(null, "s2", "s3");
list.add("s4");    // throws UnsupportedOperationException
```

但是，我们总是可以通过将初始化的列表传递给构造函数来创建一个新的集合：

```java
List<String> list = new ArrayList(Arrays.asList(null, "s2", "s3"));
list.add("s4");   //works just fine

Set<String> set = new HashSet<>(Arrays.asList(null, "s2", "s3"));
set.add("s4");   //works just fine as well
```

请注意，集合类的构造函数接受实现`Collection`接口的任何对象。它允许从集合创建列表，反之亦然。但是，`Map`接口不扩展`Collection`，因此`Map`实现只允许从另一个映射创建映射：

```java
Map<Integer, String> map = new HashMap<>();
map.put(1, null);
map.put(2, "s2");
map.put(3, "s3");

Map<Integer, String> anotherMap = new HashMap<>(map);

```

新映射的键和值的类型必须与提供的映射中的类型相同，或者必须是提供的映射类型的父类型：

```java
class A{}
class B extends A{}
Map<Integer, B> mb = new HashMap<>();
Map<Integer, A> ma = new HashMap<>(mb);

```

例如，这是一个可以接受的赋值：

```java
Map<Integer, String> map1 = new HashMap<>();
Map<Integer, Object> map2 = new HashMap<>(map1);

```

这是因为`HashMap`构造函数将类型限制在映射元素的子类型之间：

```java
HashMap(Map<? extends K,? extends V> map)
```

还有以下代码也有类似的问题：

```java
class A {}
class B extends A {}
List<A> l1 = Arrays.asList(new B());
List<B> l2 = Arrays.asList(new B());
//List<B> l3 = Arrays.asList(new A()); //compiler error

```

前面的代码是有意义的，不是吗？`class B`有（继承）`class A`的所有非私有方法和字段，但可以有其他非私有方法和字段，这些方法和字段在`class A`中不可用。即使今天两个类都是空的，就像我们的例子一样，明天我们可能决定向`class B`中添加一些方法。因此，编译器保护我们免受这种情况的影响，并且不允许将具有父类型元素的集合分配给子类型的集合。这就是泛型在以下构造函数定义中的含义，正如您在 Java 标准库 API 的`java.util`包中看到的那样：

`ArrayList(Collection<? extends E> collection)`

`HashSet(Collection<? extends E> collection)`

`HashMap(Map<? extends K,? extends V> map)`

我们希望到目前为止，您对这样的泛型更加熟悉。如果有疑问，请阅读上一章关于泛型的部分。

# 静态初始化块

静态字段初始化也有类似的解决方案。静态块可以包含必要的代码，用于生成必须用于静态字段初始化的值：

```java
class SomeClass{
   public String getThatString(){
      return "that string";
   }
}
public class ManageCollections {
  private static Set<String> set = new HashSet<>();
   static {
        SomeClass someClass = new SomeClass();
        set.add(someClass.getThatString());
        set.add("another string");
  }
  public static void main(String... args){
    System.out.println(set); //prints: [that string, another string]
  }
}
```

由于`set`是一个静态字段，它不能在构造函数中初始化，因为构造函数只有在创建实例时才会被调用，而静态字段可以在不创建实例的情况下被访问。我们也可以将前面的代码重写如下：

```java
private static Set<String> set = 
    new HashSet<>(Arrays.asList(new SomeClass().getThatString(), 
                                                "another string"));
```

但是，您可以说它看起来有些笨拙和难以阅读。因此，如果它允许编写更易读的代码，静态初始化块可能是更好的选择。

# of()的工厂方法

自 Java 9 以来，每个接口中都有另一种创建和初始化集合的选项，包括`Map`——`of()`工厂方法。它们被称为*工厂*，因为它们生成对象。有 11 种这样的方法，它们接受 0 到 10 个参数，每个参数都是要添加到集合中的元素，例如：

```java
List<String> iList0 = List.of();
List<String> iList1 = List.of("s1");
List<String> iList2 = List.of("s1", "s2");
List<String> iList3 = List.of("s1", "s2", "s3");

Set<String> iSet1 = Set.of("s1", "s2", "s3", "s4");
Set<String> iSet2 = Set.of("s1", "s2", "s3", "s4", "s5");
Set<String> iSet3 = Set.of("s1", "s2", "s3", "s4", "s5", "s6", 
                                              "s7", "s8", "s9", "s10");

Map<Integer, String> iMap = Map.of(1, "s1", 2, "s2", 3, "s3", 4, "s4");

```

请注意地图是如何构建的：从一对值到 10 对这样的值。

我们决定从上面的变量开始使用"`i`"作为标识符，以表明这些集合是不可变的。我们将在下一节中讨论这一点。

这些工厂方法的另一个特点是它们不允许`null`作为元素值。如果添加，`null`元素将导致运行时错误（`NullPointerException`）。之所以不允许`null`是因为很久以前就不得不禁止它出现在大多数集合中。这个问题对`Set`尤为重要，因为集合为`Map`提供键，而`null`键没有太多意义，对吧？例如，看下面的代码：

```java
Map<Integer, String> map = new HashMap<>();
map.put(null, "s1");
map.put(2, "s2");
System.out.println(map.get(null));     //prints: s1

```

您可能还记得`Map`接口的`put()`方法，如果提供的键没有关联的值，或者旧值为`null`，则返回`null`。这种模棱两可很烦人，不是吗？

这就是为什么 Java 9 的作者决定开始从集合中排除`null`。可能总会有允许`null`的特殊集合实现，但是最常用的集合最终将不允许`null`，我们现在描述的工厂方法是朝着这个方向迈出的第一步。

这些工厂方法添加的另一个期待已久的特性是集合元素顺序的随机化。这意味着每次执行相同的集合创建时顺序都不同。例如，如果我们运行这些行：

```java
Set<String> iSet3 = Set.of("s1", "s2", "s3", "s4", "s5", "s6", 
                                       "s7", "s8", "s9", "s10");
System.out.println(iSet3);

```

输出可能如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/7fad692b-4ec9-4098-af18-134dcffba2ce.png)

但是，如果我们再次运行相同的两行，输出将不同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/2824cd6d-1f51-407f-8ae6-7739de2b3619.png)

每次执行集合创建都会导致元素的不同顺序。这就是随机化的作用。它有助于及早发现程序员对顺序的某种依赖在不保证顺序的地方。

# 使用其他对象和流

在*构造函数*子部分中，我们演示了`List<T> Arrays.asList(T...a)`方法如何用于生成值列表，然后可以将其传递给实现`Collection`接口的任何类的构造函数（或者扩展`Collection`的任何接口，例如`List`和`Set`）。作为提醒，我们想提一下`(T...a)`表示法称为可变参数，意味着可以以以下两种方式之一传递参数：

+   作为 T 类型的无限逗号分隔值序列

+   作为任何大小的 T 类型数组

因此，以下两个语句都创建了相等的列表：

```java
List<String> x1 = Arrays.asList(null, "s2", "s3");
String[] array = {null, "s2", "s3"};
List<String> x2 = Arrays.asList(array);
System.out.println(x1.equals(x2));       //prints: true

```

Java 8 增加了另一种创建集合的方法，引入了流。这是一个可能的列表和集合对象生成的例子（我们将在第十八章中更多地讨论流和管道）：

```java
List<String> list2 = Stream.of(null, "s2", "s3")
                           .collect(Collectors.toList());
System.out.println(list2);               //prints: [null, s2, s3]

Set<String> set2 = Stream.of(null, "s2", "s3")
                         .collect(Collectors.toSet());
System.out.println(set2);               //prints: [null, s2, s3]
```

如果你阅读关于`Collectors.toList()`或`Collectors.toSet()`方法的文档，你会发现它说“返回的列表的类型、可变性、可序列化性或线程安全性没有保证；如果需要对返回的列表有更多的控制，使用 toCollection(Supplier)。”它们指的是`Collectors`类的`toCollection(Supplier<C> collectionFactory)`方法。

`Supplier<C>`表示一个不带参数并产生类型为`C`的值的函数，因此得名。

在许多情况下（如果不是大多数情况），我们不关心返回的是哪个类（`List`或`Set`的实现）。这正是面向接口编程的美妙之处。但如果我们关心，这里是如何使用`toCollection()`方法的一个例子，根据之前的建议，这是比`toList()`或`toSet()`更好的选择：

```java
List<String> list3 = Stream.of(null, "s2", "s3")
               .collect(Collectors.toCollection(ArrayList::new));
System.out.println(list3);               //prints: [null, s2, s3]

Set<String> set3 = Stream.of(null, "s2", "s3")
                 .collect(Collectors.toCollection(HashSet::new));
System.out.println(set3);               //prints: [null, s2, s3]

```

如果你觉得我们创建一个集合，然后流它，再次生成相同的集合看起来很奇怪，但请记住，在实际编程中，你可能只会得到`Stream`对象，而我们创建一个流是为了让示例工作，并向你展示期望得到的值。

在`Map`的情况下，文档中还提到了以下代码，没有关于类型的保证：

```java
Map<Integer, String> m = new HashMap<>();
m.put(1, null);
m.put(2, "s2");
Map<Integer, String> map2 = m.entrySet().stream()
  .map(e -> e.getValue() == null ? Map.entry(e.getKey(), "") : e)
  .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
System.out.println(map2);    //prints: {1=, 2=s2} 
```

请注意我们如何处理`null`，通过用空的`String`文字""替换它，以避免可怕的`NullPointerException`。这里是类似于之前的`toCollection()`方法的代码，使用我们选择的实现，这里是`HashMap`类：

```java
Map<Integer, String> map3 = m.entrySet().stream()
   .map(e -> e.getValue() == null ? Map.entry(e.getKey(), "") : e)
   .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue(),
                                         (k,v) -> v, HashMap::new));
System.out.println(map3);    //prints: {1=, 2=s2}
```

如果提供的示例对你来说看起来太复杂，你是对的；即使对有经验的程序员来说，它们也很复杂。原因有两个：

+   函数式编程是一种与 Java 存在的头二十年中使用的编码方式不同的编码方式

+   它是最近才在 Java 中引入的，没有太多围绕它构建的实用方法，使代码看起来更简单

好消息是，过一段时间，你会习惯它，流和函数式编程会开始变得简单。甚至有很大的机会你会更喜欢它，因为使用函数和流使代码更紧凑，更强大，更清晰，特别是在需要高效处理大量数据（大数据）的情况下，这似乎是当前的趋势，延伸到未来。

我们将在第十七章、*Lambda 表达式和函数式编程*；第十八章、*流和管道*；以及第十九章、*响应式系统*中更多地讨论这个问题。

# 不可变集合

在日常语言中，形容词*不可变*和*不可修改*是可以互换使用的。但是在 Java 集合的情况下，不可修改的集合是可以更改的。好吧，这也取决于你对*更改*这个词的理解。这就是我们的意思。

# 不可变与不可修改

`Collections`类中有八个静态方法可以使集合*不可修改*：

+   `Set<T>  unmodifiableSet(Set<? extends T> set)`

+   `List<T>  unmodifiableList(List<? extends T> list)`

+   `Map<K,V>  unmodifiableMap(Map<? extends K, ? extends V> map)`

+   `Collection<T> unmodifiableCollection (Collection<? extends T> collection)`

+   `SortedSet<T>  unmodifiableSortedSet(SortedSet<T> sortdedSet)`

+   `SortedMap<K,V>  unmodifiableSortedMap(SortedMap<K,? extends V> sortedMap)`,

+   `NavigableSet<T>  unmodifiableNavigableSet(NavigableSet<T> navigableSet)`

+   `NavigableMap<K,V> unmodifiableNavigableMap(NavigableMap<K,? extends V> navigableMap)`

以下是创建不可修改列表的代码示例：

```java
List<String> list = Arrays.asList("s1", "s1");
System.out.println(list);          //prints: [s1, s1]

List<String> unmodfifiableList = Collections.unmodifiableList(list);
//unmodfifiableList.set(0, "s1"); //UnsupportedOperationException
//unmodfifiableList.add("s2");    //UnsupportedOperationException
```

正如你可能期望的那样，我们既不能更改元素的值，也不能向不可修改的列表中添加新元素。尽管如此，我们仍然可以更改底层列表，因为我们仍然持有对它的引用。之前创建的不可修改列表将捕获到这种更改：

```java
System.out.println(unmodfifiableList);      //prints: [s1, s1]
list.set(0, "s0");
//list.add("s2");       //UnsupportedOperationException
System.out.println(unmodfifiableList);      //prints: [s0, s1] 
```

通过改变原始列表，我们成功地改变了之前创建的不可修改列表中元素的值。这就是创建不可修改集合的这种方式的弱点，因为它们基本上只是常规集合的包装器。

`of()`工厂方法的集合没有这个弱点，因为它们没有像不可修改集合那样的两步集合创建。这就是为什么无法更改`of`工厂方法创建的集合的原因。无法更改集合的组成部分或任何元素。以这种方式创建的集合称为"不可变"。这就是 Java 集合世界中*不可修改*和*不可变*之间的区别。

# 不使用 of()方法的不可变

公平地说，即使不使用`of()`工厂方法，也有办法创建不可变集合。以下是一种方法：

```java
List<String> iList =
        Collections.unmodifiableList(new ArrayList<>() {{
            add("s1");
            add("s1");
        }});
//iList.set(0, "s0");       //UnsupportedOperationException
//iList.add("s2");          //UnsupportedOperationException
System.out.println(iList);  //prints: [s1, s1]
```

关键是不要引用用于创建不可修改集合的原始集合（值的来源），因此不能用于更改底层来源。

这是另一种创建不可变集合的方法，而不使用`of()`工厂方法：

```java
String[] source = {"s1", "s2"};
List<String> iList2 =
        Arrays.stream(source).collect(Collectors.toList());
System.out.println(iList2);      //prints: [s1, s2]

source[0]="s0";
System.out.println(iList2);      //prints: [s1, s2] 
```

看起来好像我们在这里有对原始值的`source`引用。但是，流不会保持值与其源之间的引用。它在处理之前会复制每个值，从而打破值与其源的连接。这就是为什么我们尝试通过更改`source`数组的元素来更改`iList2`的元素并没有成功。我们将在第十八章中更多地讨论流，*流和管道*。

需要不可变集合是为了在将其作为参数传递到方法中时保护集合对象免受修改。正如我们已经提到的，这样的修改将是一个可能引入意外和难以追踪的副作用。

请注意，`of()`工厂方法不带参数时会创建空的不可变集合。当您需要调用一个需要集合作为参数的方法，但又没有数据，并且也不想给方法修改传入的集合的机会时，它们也可能是需要的。

`Collections`类中还有三个常量，提供了不可变的空集合：

```java
List<String> list1 = Collections.EMPTY_LIST;
//list1.add("s1");       //UnsupportedOperationException
Set<String> set1 = Collections.EMPTY_SET;
Map<Integer, String> map1 = Collections.EMPTY_MAP;

```

此外，`Collections`类中还有七种方法可以创建不可变的空集合：

```java
List<String> list2 = Collections.emptyList();
//list2.add("s1");       //UnsupportedOperationException
Set<String> set2 = Collections.emptySet();
Map<Integer, String> map2 = Collections.emptyMap();

SortedSet<String> set3 = Collections.emptySortedSet();
Map<Integer, String> map3 = Collections.emptySortedMap();
NavigableSet<String> set4 = Collections.emptyNavigableSet();
NavigableMap<Integer, String> map4 = Collections.emptyNavigableMap();

```

`Collections`类的以下方法创建只有一个元素的不可变集合：

+   `Set<T> singleton(T object)`

+   `List<T> singletonList(T object)`

+   `Map<K,V> singletonMap(K key, V value)`

您可以在以下代码片段中看到它是如何工作的：

```java
List<String> singletonS1 = Collections.singletonList("s1");
System.out.println(singletonS1);
//singletonS1.add("s1");        //UnsupportedOperationException

```

所有这些都可以使用`of()`工厂方法来完成。我们已经为您描述了这一点，以便您对不可变集合创建的可用选项有一个完整的了解。

但是`Collections`类的`List<T> nCopies(int n, T object)`方法以比`of()`方法更紧凑的方式创建了`n`个相同对象的不可变列表：

```java
List<String> nList = Collections.nCopies(3, "s1");
System.out.println(nList);
//nList.add("s1");        //UnsupportedOperationException

```

使用`of()`方法的类似代码更冗长：

```java
List<String> nList = List.of("s1", "s1", "s1");
```

如果这对你来说不是太糟糕，想象一下你需要创建一个包含 100 个相同对象的列表。

# add()和 put()方法的混淆

不可变集合使用的一个方面是偶尔会引起混淆的源。从我们的例子中可以看出，不可变集合，就像任何 Java 集合一样，都有`add()`或`put()`方法。编译器不会生成错误，只有运行时的 JVM 才会这样做。因此，使用不可变集合的代码应该经过充分测试，以避免在生产中出现这种错误。

# java.util.Collections 类

`java.util.Collections`类的所有方法都是静态且无状态的。后者意味着它们不会在任何地方维护任何状态，它们的结果不依赖于调用历史，而只依赖于作为参数传递的值。

`Collections`类中有许多方法，您已经在上一节中看到了其中一些。我们鼓励您查阅此类的在线文档。在这里，我们为您整理了其中一些方法，以便您更好地了解`Collections`类的方法。

# 复制

`void copy(List<T> dest, List<T> src)`方法将`src`列表的元素复制到`dest`列表并保留元素顺序。如果需要将一个列表作为另一个列表的子列表，这个方法非常有用：

```java
List<String> list1 = Arrays.asList("s1","s2");
List<String> list2 = Arrays.asList("s3", "s4", "s5");
Collections.copy(list2, list1);
System.out.println(list2);    //prints: [s1, s2, "s5"]

```

在执行此操作时，`copy()`方法不会消耗额外的内存 - 它只是将值复制到已分配的内存上。这使得这个方法对于传统的复制相同大小的列表的情况非常有帮助：

```java
List<String> list1 = Arrays.asList("s1","s2");
List<String> list2 = Arrays.asList("s3", "s4");
list2 = new ArrayList(list1);
System.out.println(list2);    //prints: [s1, s2]
```

这段代码放弃了最初分配给`list2`的值，并分配了新的内存来保存`list1`的值的副本。被放弃的值会一直留在内存中，直到垃圾收集器将它们移除并允许重用内存。想象一下，这些列表的大小是可观的，您就会明白在这种情况下使用`Collections.copy()`会减少很多开销。它还有助于避免`OutOfMemory`异常。

# 排序和相等()

`Collections`类的两个静态排序方法是：

+   `void sort(List<T> list)`

+   `void sort(List<T> list, Comparator<T> comparator)`

第一个`sort(List<T>)`方法只接受实现`Comparable`接口的元素的列表，这要求实现`compareTo(T)`方法。每个元素实现的`compareTo(T)`方法建立的顺序称为“自然排序”。

第二个`sort()`方法不需要列表元素实现任何特定的接口。它使用传入的`Comparator`类的对象来使用`Comparator.compare(T o1, T o2)`方法建立所需的顺序。如果列表的元素实现了`Comparable`，那么它们的方法`compareTo(T)`会被忽略，顺序只由`Comparator.compare(T o1, T o2)`方法建立。

`Comparator`对象定义的顺序（`compare(T o1, T o2)`方法）会覆盖`Comparable`接口定义的自然顺序（`compareTo(T)`方法）。

例如，这是类`String`如何实现接口`Comparable`：

```java
List<String> no = Arrays.asList("a","b", "Z", "10", "20", "1", "2");
Collections.sort(no);
System.out.println(no);     //prints: [1, 10, 2, 20, Z, a, b]

```

对于许多人来说，`10`排在`2`前面，大写`Z`排在小写`a`前面可能看起来并不“自然”，但这个术语并不是基于人类的感知。它是基于对象在没有提供比较器时将如何排序的。在这种情况下，它们是基于实现的方法`compareTo(T)`排序的。这个实现的方法可以被认为是内置在元素中的。这就是为什么这样的排序被称为“自然”的原因。

自然排序是由接口`Comparable`的实现定义的（方法`compareTo(T)`）。

虽然对人类来说看起来有些意外，但`String`对`compareTo(T)`方法的实现在许多排序情况下非常有帮助。例如，我们可以用它来实现`Person`类中`Comparable`接口的实现：

```java
class Person implements Comparable<Person>{
    private String firstName = "", lastName = "";
    public Person(String firstName, String lastName) {
        this.firstName = firstName;
        this.lastName = lastName;
    }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    @Override
    public int compareTo(Person person){
        int result = this.firstName.compareTo(person.firstName);
        if(result == 0) {
            return this.lastName.compareTo(person.lastName);
        }
        return result;
    }
}
```

我们首先比较名字，如果它们相等，再比较姓。这意味着我们希望`Person`对象按名字顺序排列，然后按姓氏排列。

`String`的`compareTo(T)`方法的实现返回第一个（或 this）和第二个对象的排序位置之间的差异。例如，`a`和`c`的排序位置之间的差异是`2`，这是它们比较的结果：

```java
System.out.println("a".compareTo("c"));   //prints: -2
System.out.println("c".compareTo("a"));   //prints: 2

```

这是有道理的：`a`在`c`之前，所以它的位置在我们从左到右计算时更小。

请注意，`Integer`的`compareTo(T)`实现并不返回排序位置的差异。相反，当对象相等时，它返回`0`，当此对象小于方法参数时，它返回`-1`，否则返回`1`：

```java
System.out.println(Integer.valueOf(3)
                          .compareTo(Integer.valueOf(3))); //prints: 0
System.out.println(Integer.valueOf(3)
                          .compareTo(Integer.valueOf(4))); //prints: -1
System.out.println(Integer.valueOf(3)
                          .compareTo(Integer.valueOf(5))); //prints: -1
System.out.println(Integer.valueOf(5)
                          .compareTo(Integer.valueOf(4))); //prints: 1
System.out.println(Integer.valueOf(5)
                          .compareTo(Integer.valueOf(3))); //prints: 1

```

我们使用`Comparator`及其方法`compare(T o1, T o2)`得到相同的结果：

```java
Comparator<String> compStr = Comparator.naturalOrder();
System.out.println(compStr.compare("a", "c"));  //prints: -2

Comparator<Integer> compInt = Comparator.naturalOrder();
System.out.println(compInt.compare(3, 5));     //prints: -1

```

但是，请注意，方法`Comparable.compareTo(T)`和`Compartor.compare(T o1, T o2)`的文档只定义了以下返回：

+   `0`表示对象相等

+   `-1`表示第一个对象小于第二个对象

+   `1`表示第一个对象大于第二个对象

在`String`的情况下，`smaller`和`bigger`根据它们的排序位置进行定义——在有序列表中，`smaller`放在`bigger`前面。正如您所看到的，API 文档并不保证对所有类型的对象都返回排序位置的差异。

重要的是要确保方法`equals()`与方法`Comparable.compareTo(T)`对齐，以便对于相等的对象，方法`Comparable.compareTo(T)`返回 0。否则，可能会得到不可预测的排序结果。

这就是为什么我们在我们的类`Person`中添加了以下方法`equals()`：

```java
@Override
public boolean equals(Object other) {
    if (other == null) return false;
    if (this == other) return true;
    if (!(other instanceof Person)) return false;
    final Person that = (Person) other;
    return this.firstName.equals(that.getFirstName()) &&
            this.lastName.equals(that.getLastName());
}
```

现在方法`equals()`与方法`compareTo(T)`对齐，因此对于相等的`Person`对象，`compareTo(T)`返回 0：

```java
Person joe1 = new Person("Joe", "Smith");
Person joe2 = new Person("Joe", "Smith");
Person bob = new Person("Bob", "Smith");

System.out.println(joe1.equals(joe2));    //prints: true
System.out.println(joe1.compareTo(joe2)); //prints: 0

System.out.println(joe1.equals(bob));     //prints: false
System.out.println(joe1.compareTo(bob));  //prints: 8
System.out.println(joe2.compareTo(bob));  //prints: 8

```

返回值`8`是因为这是`B`和`J`在字母顺序中的位置之间的差异。

我们还在我们的类`Person`中添加了以下`toString()`方法：

```java
@Override
public String toString(){
    return this.firstName + " " + this.lastName;
}
```

它将允许我们更好地展示排序结果，这正是我们现在要做的。以下是演示代码：

```java
Person p1 = new Person("Zoe", "Arnold");
Person p2 = new Person("Alex", "Green");
Person p3 = new Person("Maria", "Brown");
List<Person> list7 = Arrays.asList(p1, p2, p3);
System.out.println(list7);  //[Zoe Arnold, Alex Green, Maria Brown]
Collections.sort(list7);
System.out.println(list7);  //[Alex Green, Maria Brown, Zoe Arnold]

```

如您所见，在排序后元素的顺序（前一个示例的最后一行）与`compareTo(T)`方法中定义的顺序相匹配。

现在，让我们创建一个以不同方式对`Person`类的对象进行排序的比较器：

```java
class OrderByLastThenFirstName implements Comparator<Person> {
    @Override
    public int compare(Person p1, Person p2){
        return (p1.getLastName() + p1.getFirstName())
                .compareTo(p2.getLastName() + p2.getFirstName());
    }
}
```

如您所见，前面的比较器首先根据姓氏的自然顺序，然后根据名字的自然顺序建立了一个顺序。如果我们使用相同的列表和对象与此比较器，我们将得到以下结果：

```java
Collections.sort(list7, new OrderByLastThenFirstName());
System.out.println(list7);  //[Zoe Arnold, Maria Brown, Alex Green]

```

正如预期的那样，`compareTo(T)`方法被忽略，传入的`Comparator`对象的顺序被强制执行。

# 反转和旋转

类`Collections`中有三个静态的与反转相关的方法，以及一个与旋转相关的方法：

+   `void reverse(List<?> list)`: 反转元素的当前顺序

+   `void rotate(List<?> list, int distance) `: 将元素的顺序旋转，将每个元素向右移动指定数量的位置（距离）

+   `Comparator<T> reverseOrder()`: 返回一个创建与自然顺序相反的顺序的比较器；仅适用于实现了`Comparable`接口的元素

+   `Comparator<T> reverseOrder(Comparator<T> comparator)`: 返回一个反转传入比较器定义的顺序的比较器

以下是演示列出的方法的代码：

```java
Person p1 = new Person("Zoe", "Arnold");
Person p2 = new Person("Alex", "Green");
Person p3 = new Person("Maria", "Brown");
List<Person> list7 = Arrays.asList(p1,p2,p3);
System.out.println(list7);  //[Zoe Arnold, Alex Green, Maria Brown]

Collections.reverse(list7);
System.out.println(list7);  //[Maria Brown, Alex Green, Zoe Arnold]

Collections.rotate(list7, 1);
System.out.println(list7);  //[Zoe Arnold, Maria Brown, Alex Green]

Collections.sort(list7, Collections.reverseOrder());
System.out.println(list7);  //[Zoe Arnold, Maria Brown, Alex Green]

Collections.sort(list7, new OrderByLastThenFirstName());
System.out.println(list7);  //[Zoe Arnold, Maria Brown, Alex Green]

Collections.sort(list7, 
         Collections.reverseOrder(new OrderByLastThenFirstName()));
System.out.println(list7);  //[Alex Green, Maria Brown, Zoe Arnold]
```

# 搜索和 equals()

类`Collections`中有五个静态的与搜索相关的方法：

+   `int binarySearch(List<Comparable<T>> list, T key)`

+   `int binarySearch(List<T> list, T key, Comparator<T> comparator)`

+   `int indexOfSubList(List<?> source, List<?> target) `

+   `int lastIndexOfSubList(List<?> source, List<?> target)`

+   `int frequency(Collection<?> collection, Object object)`

`binarySearch()`方法在提供的列表中搜索`key`值。需要注意的重要一点是，由于二分搜索的性质，提供的列表必须*按升序*排列。算法将`key`与列表的中间元素进行比较；如果它们不相等，就会忽略掉`key`不可能存在的那一半，并且算法将`key`与列表另一半的中间元素进行比较。搜索将继续，直到找到与`key`相等的元素，或者只剩一个元素需要搜索而且它不等于`key`。

`indexOfSubList()`和`lastIndexOfSubList()`方法返回提供列表中提供子列表的位置：

```java
List<String> list1 = List.of("s3","s5","s4","s1");
List<String> list2 = List.of("s4","s5");
int index = Collections.indexOfSubList(list1, list2);
System.out.println(index);  //prints: -1

List<String> list3 = List.of("s5","s4");
index = Collections.indexOfSubList(list1, list3);
System.out.println(index);   //prints: 1
```

请注意，子列表应该按照完全相同的顺序。否则，它是无法被找到的。

最后一个方法，`frequency(Collection, Object)`，返回提供的对象在提供的集合中出现的次数：

```java
List<String> list4 = List.of("s3","s4","s4","s1");
int count = Collections.frequency(list4, "s4");
System.out.println(count);         //prints: 2
```

如果你打算使用这些方法（或者任何其他搜索集合的方法），如果集合中包含自定义类的对象，那么你必须要实现方法`equals()`。典型的搜索算法使用方法`equals()`来识别对象。如果你没有在自定义类中实现方法`equals()`，那么基类`Object`中的方法`equals()`会被使用，它只比较对象的引用，而不是它们的状态（字段的值）。以下是这种行为的演示：

```java
class A{}
class B extends A{}

List<A> list5 = List.of(new A(), new B());
int c = Collections.frequency(list5, new A());
System.out.println(c);         //prints: 0

A a = new A();
List<A> list6 = List.of(a, new B());
c = Collections.frequency(list6, a);
System.out.println(c);         //prints: 1

```

如你所见，只有当类`A`的对象确实是同一个对象时才能找到。但是如果我们实现了方法`equals()`，那么根据我们在方法`equals()`实现中的标准，类`A`的对象就能被找到：

```java
class A{
    @Override
    public boolean equals(Object o){
        if (o == null) return false;
        return (o instanceof A);
    }
}
class B extends A{}

List<A> list5 = List.of(new A(), new B());
int c = Collections.frequency(list5, new A());
System.out.println(c);         //prints: 2

A a = new A();
List<A> list6 = List.of(a, new B());
c = Collections.frequency(list6, a);
System.out.println(c);         //prints: 2
```

现在，每种情况下对象`A`的计数都是`2`，因为`B`扩展了`A`，因此具有`B`和`A`两种类型。

如果我们更喜欢仅以当前类名来标识对象而不考虑其父类，我们应该以不同的方式实现方法`equals()`：

```java
class A{
    @Override
    public boolean equals(Object o){
        if (o == null) return false;
        return o.getClass().equals(this.getClass());
    }
}
class B extends A{}

List<A> list5 = List.of(new A(), new B());
int c = Collections.frequency(list5, new A());
System.out.println(c);         //prints: 1

A a = new A();
List<A> list6 = List.of(a, new B());
c = Collections.frequency(list6, a);
System.out.println(c);         //prints: 1
```

方法`getClass()`返回对象通过`new`运算符创建时使用的类名。这就是为什么现在两种情况下计数都是`1`的原因。

在本章的其余部分，我们将假设集合和数组的元素实现了`equals()`方法。大多数情况下，我们将在示例中使用`String`类的对象。正如我们在第九章中提到的那样，*运算符、表达式和语句*，`String`类具有基于字符串字面值的`equals()`方法实现，而不仅仅是基于对象引用。并且，正如我们在前一小节中解释的那样，`String`类还实现了`Comparable`接口，因此它提供了自然排序。

# 比较两个集合

`Collections`类中有一个简单的静态方法用于比较两个集合：

`boolean disjoint(Collection<?> c1, Collection<?> c2)`: 如果一个集合的元素都不等于另一个集合的任何元素，则返回`true`

你可能已经猜到，这个方法使用`equals()`方法来识别相等的元素。

# 最小和最大元素

以下`Collections`类的方法可用于选择提供的集合中的*最大*和*最小*元素：

+   `T min(Collection<? extends T> collection)`

+   `T max(Collection<? extends T>collection)`

+   `T min(Collection<? extends T>collection, Comparator<T> comparator)`

+   `T max(Collection<? extends T>collection, Comparator<T> comparator)`

前两个方法要求集合元素实现`Comparable`（方法`compareTo(T)`），而另外两个方法使用`Comparator`类的对象来比较元素。

最小的元素是在排序后的列表中首先出现的元素；最大的元素在排序后的列表的另一端。以下是演示代码：

```java
Person p1 = new Person("Zoe", "Arnold");
Person p2 = new Person("Alex", "Green");
Person p3 = new Person("Maria", "Brown");
List<Person> list7 = Arrays.asList(p1,p2,p3);
System.out.println(list7);  //[Zoe Arnold, Alex Green, Maria Brown]

System.out.println(Collections.min(list7)); //prints: Alex Green
System.out.println(Collections.max(list7)); //prints: Zoe Arnold

Person min = Collections.min(list7, new OrderByLastThenFirstName());
System.out.println(min);                    //[Zoe Arnold]

Person max = Collections.max(list7, new OrderByLastThenFirstName());
System.out.println(max);                    //[Alex Green]

```

前两个方法使用自然排序来建立顺序，而后两个方法使用作为参数传递的比较器。

# 添加和替换元素

以下是`Collections`类的三个静态方法，用于向集合中添加或替换元素：

+   `boolean addAll(Collection<T> c, T... elements)`: 将所有提供的元素添加到提供的集合中；如果提供的元素是`Set`，则只添加唯一的元素。它的执行速度比相应集合类型的`addAll()`方法要快得多。

+   `boolean replaceAll(List<T> list, T oldVal, T newVal)`: 用`newValue`替换提供的列表中等于`oldValue`的每个元素；当`oldValue`为`null`时，该方法将提供的列表中的每个`null`值替换为`newValue`。如果至少替换了一个元素，则返回`true`。

+   `void fill(List<T> list, T object)`: 用提供的对象替换提供的列表中的每个元素。

# 洗牌和交换元素

`Collections`类的以下三个静态方法可以对提供的列表进行洗牌和交换元素：

+   `void shuffle(List<?> list)`: 使用默认的随机源来打乱提供的列表中元素的位置

+   `void shuffle(List<?> list, Random random)`: 使用提供的随机源（我们将在后面的相应部分讨论这样的源）来打乱提供的列表中元素的位置

+   `void swap(List<?> list, int i, int j`): 将提供的列表中位置`i`的元素与位置`j`的元素交换

# 转换为已检查的集合

类`Collections`的以下九个静态方法将提供的集合从原始类型（没有泛型）转换为某种元素类型。名称*checked*意味着转换后，每个新添加的元素的类型都将被检查：

+   `Set<E> checkedSet(Set<E> s, Class<E> type)`

+   `List<E> checkedList(List<E> list, Class<E> type)`

+   `Queue<E> checkedQueue(Queue<E> queue, Class<E> type)`

+   `Collection<E> checkedCollection(Collection<E> collection, Class<E> type)`

+   `Map<K,V> checkedMap(Map<K,V> map, Class<K> keyType, Class<V> valueType)`

+   `SortedSet<E> checkedSortedSet(SortedSet<E> set, Class<E> type)`

+   `NavigableSet<E> checkedNavigableSet(NavigableSet<E> set, Class<E> type)`

+   `SortedMap<K,V> checkedSortedMap(SortedMap<K,V> map, Class<K> keyType, Class<V> valueType)`

+   `NavigableMap<K,V> checkedNavigableMap(NavigableMap<K,V> map, Class<K> keyType, Class<V> valueType)`

以下是演示代码：

```java
List list = new ArrayList();
list.add("s1");
list.add("s2");
list.add(42);
System.out.println(list);    //prints: [s1, s2, 42]

List cList = Collections.checkedList(list, String.class);
System.out.println(list);   //prints: [s1, s2, 42]

list.add(42);
System.out.println(list);   //prints: [s1, s2, 42, 42]

//cList.add(42);           //throws ClassCastException
```

您可以观察到转换不会影响集合的当前元素。我们已经向同一个列表添加了`String`类的对象和`Integer`类的对象，并且能够将其转换为一个检查过的列表`cList`，没有任何问题。我们可以继续向原始列表添加不同类型的对象，但是尝试向检查过的列表添加非 String 对象会在运行时生成`ClassCastException`。

# 转换为线程安全的集合

类`Collections`中有八个静态方法，可以将常规集合转换为线程安全的集合：

+   `Set<T> synchronizedSet(Set<T> set)`

+   `List<T> synchronizedList(List<T> list)`

+   `Map<K,V> synchronizedMap(Map<K,V> map)`

+   `Collection<T> synchronizedCollection(Collection<T> collection)`

+   `SortedSet<T> synchronizedSortedSet(SortedSet<T> set)`

+   `SortedMap<K,V> synchronizedSortedMap(SortedMap<K,V> map)`

+   `NavigableSet<T> synchronizedNavigableSet(NavigableSet<T> set)`

+   `NavigableMap<K,V> synchronizedNavigableMap(NavigableMap<K,V> map)`

线程安全的集合是这样构造的，以便两个应用程序线程只能顺序地修改它，而不会互相干扰。但是，多线程处理超出了本书的范围，所以我们就此打住。

# 转换为另一种集合类型

将一种类型的集合转换为另一种类型的四个静态方法包括：

+   `ArrayList<T> list(Enumeration<T> e)`

+   `Enumeration<T> enumeration(Collection<T> c)`

+   `Queue<T> asLifoQueue(Deque<T> deque)`

+   `Set<E> newSetFromMap(Map<E,Boolean> map)`

接口`java.util.Enumeration`是一个遗留接口，它是在 Java 1 中引入的，与使用它的遗留类`java.util.Hashtable`和`java.util.Vector`一起。它与`Iterator`接口非常相似。实际上，可以使用`Enumeration.asIterator()`方法将`Enumeration`类型对象转换为`Iterator`类型。

所有这些方法在主流编程中很少使用，所以我们只是为了完整性而在这里列出它们。

# 创建枚举和迭代器

以下也是不经常使用的静态方法，允许创建一个空的`Enumeration`，`Iterator`和`ListIterator` - 都是`java.util`包的接口：

+   `Iterator<T> empty iterator``()`

+   `ListIterator<T> emptyListIterator()`

+   `Enumeration<T> emptyEnumeration()`

# Class collections4.CollectionUtils

Apache Commons 项目中的`org.apache.commons.collections4.CollectionUtils`类包含了与`java.util.Collections`类的方法相辅相成的静态无状态方法。它们有助于搜索、处理和比较 Java 集合。要使用这个类，您需要将以下依赖项添加到 Maven 配置文件`pom.xml`中：

```java
<dependency>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-collections4</artifactId>
  <version>4.1</version>
</dependency>
```

这个类中有很多方法，而且随着时间的推移，可能会添加更多的方法。刚刚审查的`Collections`类可能会涵盖大部分您的需求，特别是当您刚刚进入 Java 编程领域时。因此，我们不会花时间解释每个方法的目的，就像我们为`Collections`类所做的那样。此外，`CollectionUtils`的方法是作为`Collections`方法的补充而创建的，因此它们更加复杂和微妙，不适合本书的范围。

为了让您了解`CollectionUtils`类中可用的方法，我们将它们按相关功能进行了分组：

+   检索元素的方法：

+   `Object get(Object object, int index)`

+   `Map.Entry<K,V> get(Map<K,V> map, int index)`

+   `Map<O,Integer> getCardinalityMap(Iterable<O> collection)`

+   添加元素或一组元素到集合的方法：

+   `boolean addAll(Collection<C> collection, C[] elements)`

+   `boolean addIgnoreNull(Collection<T> collection, T object)`

+   `boolean addAll(Collection<C> collection, Iterable<C> iterable)`

+   `boolean addAll(Collection<C> collection, Iterator<C> iterator)`

+   `boolean addAll(Collection<C> collection, Enumeration<C> enumeration)`

+   合并`Iterable`元素的方法：

+   `List<O> collate(Iterable<O> a, Iterable<O> b)`

+   `List<O> collate(Iterable<O> a, Iterable<O> b, Comparator<O> c)`

+   `List<O> collate(Iterable<O> a, Iterable<O> b, boolean includeDuplicates)`

+   `List<O> collate(Iterable<O> a, Iterable<O> b, Comparator<O> c, boolean includeDuplicates)`

+   删除或保留具有或不具有标准的元素的方法：

+   `Collection<O> subtract(Iterable<O> a, Iterable<O> b)`

+   ``Collection<O> subtract(Iterable<O> a, Iterable<O> b, Predicate<O> p)``

+   `Collection<E> removeAll(Collection<E> collection, Collection<?> remove)`

+   `Collection<E> removeAll(Iterable<E> collection, Iterable<E> remove, Equator<E> equator)`

+   `Collection<C> retainAll(Collection<C> collection, Collection<?> retain)`

+   `Collection<E> retainAll(Iterable<E> collection, Iterable<E> retain, Equator<E> equator)`

+   比较两个集合的方法：

+   `boolean containsAll(Collection<?> coll1, Collection<?> coll2)`

+   `boolean containsAny(Collection<?> coll1, Collection<?> coll2)`

+   `boolean isEqualCollection(Collection<?> a, Collection<?> b)`

+   `boolean isEqualCollection(Collection<E> a, Collection<E> b, Equator<E> equator)`

+   `boolean isProperSubCollection(Collection<?> a, Collection<?> b)`

+   转换集合的方法：

+   `Collection<List<E>> permutations(Collection<E> collection)`

+   `void transform(Collection<C> collection, Transformer<C,C> transformer)`

+   `Collection<E> transformingCollection(Collection<E> collection, Transformer<E,E> transformer)`

+   `Collection<O> collect(Iterator<I> inputIterator, Transformer<I,O> transformer)`

+   `Collection<O> collect(Iterable<I> inputCollection, Transformer<I,O> transformer)`

+   `Collection<O> R collect(Iterator<I> inputIterator, Transformer<I,O> transformer, R outputCollection)`

+   `Collection<O> R collect(Iterable<I> inputCollection, Transformer<I,O> transformer, R outputCollection)`

+   选择和过滤集合的方法：

+   ``Collection<O> select(Iterable<O> inputCollection, Predicate<O> predicate)``

+   `Collection<O> R select(Iterable<O> inputCollection, Predicate<O> predicate, R outputCollection)`

+   `Collection<O> R select(Iterable<O> inputCollection, Predicate<O> predicate, R outputCollection, R rejectedCollection)`

+   `Collection<O> selectRejected(Iterable<O> inputCollection, Predicate<O> predicate)`

+   `Collection<O> R selectRejected(Iterable<O> inputCollection, Predicate<O> predicate, R outputCollection)`

+   `E extractSingleton(Collection<E> collection)`

+   `boolean filter(Iterable<T> collection, Predicate<T> predicate)`

+   `boolean filterInverse(Iterable<T> collection, Predicate<T> predicate)`

+   `Collection<C> predicatedCollection(Collection<C> collection, Predicate<C> predicate)`

+   生成两个集合的并集、交集或差集的方法：

+   `Collection<O> union(Iterable<O> a, Iterable<O> b)`

+   `Collection<O> disjunction(Iterable<O> a, Iterable<O> b)`

+   `Collection<O> intersection(Iterable<O> a, Iterable<O> b)`

+   创建不可变空集合的方法：

+   `<T> Collection<T> emptyCollection()`

+   `Collection<T> emptyIfNull(Collection<T> collection)`

+   检查集合大小和是否为空的方法：

+   `int size(Object object)`

+   `boolean sizeIsEmpty(Object object)`

+   `int maxSize(Collection<Object> coll)`

+   `boolean isEmpty(Collection<?> coll)`

+   `boolean isNotEmpty(Collection<?> coll)`

+   `boolean isFull(Collection<Object> coll)`

+   反转数组的方法：

+   `void reverseArray(Object[] array)`

这个最后的方法可能应该属于处理数组的实用类，这就是我们现在要讨论的内容。

# 管理数组

在本节中，我们将回顾如何创建和初始化数组对象，以及在哪里可以找到允许我们对数组执行一些操作的方法——例如复制、排序和比较。

尽管数组在一些算法和旧代码中有它们的用武之地，但在实践中，`ArrayList()`可以做任何数组可以做的事情，并且不需要提前设置大小。事实上，`ArrayList`也使用数组来存储其元素。因此，数组和`ArrayList`的性能也是可比较的。

因此，我们不打算过多地讨论数组管理，只是基本的创建和初始化。我们将提供一个简短的概述和参考资料，告诉您在哪里可以找到数组实用方法，以防您需要它们。

# 初始化数组

我们已经看到了一些数组构造的例子。现在，我们将回顾它们并介绍创建和初始化数组对象的其他方法。

# 创建表达式

数组创建表达式包括：

+   数组元素类型

+   嵌套数组的级数

+   至少在第一级上的数组长度

以下是一级数组创建示例：

```java
int[] ints = new int[10];
System.out.println(ints[0]);     //prints: 0

Integer[] intW = new Integer[10];
System.out.println(intW[0]);     //prints: null

boolean[] bs = new boolean[10];
System.out.println(bs[0]);       //prints: false

Boolean[] bW = new Boolean[10];
System.out.println(bW[0]);       //prints: 0

String[] strings = new String[10];
System.out.println(strings[0]);  //prints: null

A[] as = new A[10];
System.out.println(as[0]);       //prints: null 
System.out.println(as.length);   //prints: 10

```

正如我们在第五章中所展示的，*Java 语言元素和类型*，每种 Java 类型都有一个默认的初始化值，在对象创建时使用，当没有明确分配值时。因为数组是一个类，它的元素被初始化——就像任何类的实例字段一样——即使程序员没有明确地为它们分配值。数字原始类型的默认值为 0，布尔原始类型为 false，而所有引用类型的默认值为 null。在前面的示例中使用的类 A 被定义为`class A {}`。数组的长度被捕获在最终的公共属性`length`中。

多级嵌套初始化如下所示：

```java
    //A[][] as2 = new A[][10];             //compilation error
    A[][] as2 = new A[10][];
    System.out.println(as2.length);        //prints: 10
    System.out.println(as2[0]);            //prints: null
    //System.out.println(as2[0].length);   //NullPointerException
    //System.out.println(as2[0][0]);       //NullPointerException

    as2 = new A[2][3];
    System.out.println(as2[0]); //prints: ManageArrays$A;@282ba1e
    System.out.println(as2[0].length); //prints: 3
    System.out.println(as2[0][0]);     //prints: null
```

首先要注意的是，尝试创建一个没有定义第一级数组长度的数组会生成编译错误。第二个观察是多级数组的`length`属性捕获了第一（顶级）级数组的长度。第三个是顶级数组的每个元素都是一个数组。如果不是最后一级，下一级数组的元素也是数组。

在我们之前的示例中，我们没有设置第二级数组的长度，因此顶级数组的每个元素都被初始化为`null`，因为这是任何引用类型的默认值（数组也是引用类型）。这就是为什么尝试获取第二级数组的长度或任何值会生成`NullPointerException`。

一旦我们将第二级数组的长度设置为三，我们就能够得到它的长度和第一个元素的值（`null`，因为这是默认值）。奇怪的打印`ManageArrays$A;@282ba1e`是数组二进制引用，因为对象数组没有实现`toString()`方法。您可以得到的最接近的是实用类`java.util.Arrays`的静态方法`toString()`（请参见下一节）。它返回所有数组元素的`String`表示：

```java
System.out.println(Arrays.toString(as2));   
        //prints: [[ManageArrays$A;@282ba1e, [ManageArrays$A;@13b6d03]
System.out.println(Arrays.toString(as2[0])); //[null, null, null]

```

对于最后（最深层）嵌套的数组，它可以正常工作，但对于更高级别的数组仍然打印二进制引用。如果要打印所有嵌套数组的所有元素，请使用`Arrays.deepToString(Object[])`方法：

```java
System.out.println(Arrays.deepToString(as2)); 
           //the above prints: [[null, null, null], [null, null, null]]

```

请注意，如果数组元素没有实现`toString()`方法，则对于那些不是`null`的元素，将打印二进制引用。

# 数组初始化程序

数组初始化程序由逗号分隔的表达式列表组成，括在大括号`{}`中。允许并忽略最后一个表达式后面的逗号：

```java
String[] arr = {"s0", "s1", };
System.out.println(Arrays.toString(arr)); //prints: [s0, s1]

```

我们经常在示例中使用这种初始化数组的方式，因为这是最紧凑的方式。

# 静态初始化块

与集合一样，当需要执行一些代码时，可以使用静态块来初始化数组静态属性：

```java
class ManageArrays {
private static A[] AS_STATIC;
  static {
    AS_STATIC = new A[2];
    for(int i = 0; i< AS_STATIC.length; i++){
        AS_STATIC[i] = new A();
    }
    AS_STATIC[0] = new A();
    AS_STATIC[1] = new A();
  }
  //... the rest of class code goes here
}
```

静态块中的代码在每次加载类时都会执行，甚至在调用构造函数之前。但是，如果字段不是静态的，则可以将相同的初始化代码放在构造函数中：

```java
class ManageArrays {
  private A[] as;
  public ManageArrays(){
    as = new A[2];
    for(int i = 0; i< as.length; i++){
        as[i] = new A();
    }
    as[0] = new A();
    as[1] = new A();
  }
  //the reat of class code goes here
}
```

# 从收集

如果有一个可以用作数组值源的集合，它有一个`toArray()`方法，可以按如下方式调用：

```java
List<Integer> list = List.of(0, 1, 2, 3);
Integer[] arr1 = list.toArray(new Integer[list.size()]);
System.out.println(Arrays.toString(arr1)); //prints: [0, 1, 2, 3]
```

# 其他可能的方法

在不同的上下文中，可能会使用一些其他方法来创建和初始化数组。这也是你喜欢的风格问题。以下是您可以选择的各种数组创建和初始化方法的示例：

```java
String[] arr2 = new String[3];
Arrays.fill(arr2, "s");
System.out.println(Arrays.toString(arr2));      //prints: [s, s, s]

String[] arr3 = new String[5];
Arrays.fill(arr3, 2, 3, "s");
System.out.println(Arrays.toString(arr3)); 
                              //prints: [null, null, s, null, null]
String[] arr4 = {"s0", "s1", };
String[] arr4Copy = Arrays.copyOf(arr4, 5);
System.out.println(Arrays.toString(arr4Copy)); 
                                //prints: [s0, s1, null, null, null]
String[] arr5 = {"s0", "s1", "s2", "s3", "s4" };
String[] arr5Copy = Arrays.copyOfRange(arr5, 1, 3);
System.out.println(Arrays.toString(arr5Copy));    //prints: [s1, s2]

Integer[] arr6 = {0, 1, 2, 3, 4 };
Object[] arr6Copy = Arrays.copyOfRange(arr6,1, 3, Object[].class);
System.out.println(Arrays.toString(arr6Copy));      //prints: [1, 2]

String[] arr7 = Stream.of("s0", "s1", "s2").toArray(String[]::new);
System.out.println(Arrays.toString(arr7));    //prints: [s0, s1, s2] 
```

在上面的六个例子中，有五个使用了`java.util.Arrays`类（见下一节）来填充或复制数组。所有这些例子都使用了`Arrays.toString()`方法来打印结果数组的元素。

第一个例子为数组`arr2`的所有元素分配了值`s`。

第二个例子仅为索引 2 到索引 3 的元素分配了值`s`。请注意，第二个索引不包括在内。这就是为什么数组`arr3`的一个元素被赋予了值。

第三个例子复制了`arr4`数组，并使新数组的大小更长。这就是为什么新数组的其余元素被初始化为`String`的默认值，即`null`。请注意，我们在`arr4`数组初始化器中放置了一个尾随逗号，以演示它是允许的并被忽略的。这看起来不像是一个非常重要的特性。我们只是提出来，以防你在其他人的代码中看到它并想知道它是如何工作的。

第四个例子使用其元素从索引 1 到 3 创建了一个数组的副本。再次强调，第二个索引不包括在内，因此只复制了两个元素。

第五个例子不仅创建了元素范围的副本，还将它们转换为`Object`类型，这是可能的，因为源数组是引用类型。

最后一个例子使用了`Stream`类，我们将在第十八章中讨论*流和管道*。

# 类 java.util.Arrays

我们已经多次使用了`java.util.Arrays`类。它是数组管理的主要工具。但是，它曾经非常受到那些使用集合的人的欢迎，因为`asList(T...a)`方法是创建和初始化集合的最紧凑的方法：

```java
List<String> list = Arrays.asList("s0", "s1");
Set<String> set = new HashSet<>(Arrays.asList("s0", "s1");
```

但是在每个集合中引入了`of()`工厂方法之后，`Arrays`类的流行度大大下降。以下是创建集合的更自然的方法：

```java
List<String> list = List.of("s0", "s1");
Set<String> set = Set.of("s0", "s1");
```

这个集合的对象是不可变的。但是，如果需要一个可变的集合，可以按照以下方式创建：

```java
List<String> list = new ArrayList<>(List.of("s0", "s1"));
Set<String> set1 = new HashSet<>(list);
Set<String> set2 = new HashSet<>(Set.of("s0", "s1"));
```

我们之前在*管理集合*部分详细讨论过这个问题。

但是如果您的代码管理数组，那么您肯定需要使用`Arrays`类。它包含了 160 多种方法。其中大多数都是使用不同参数和数组类型进行重载。如果我们按方法名称对它们进行分组，将会有 21 组。如果我们进一步按功能对它们进行分组，只有以下 10 组将涵盖所有`Arrays`类的功能：

+   `asList()`: 基于提供的数组创建一个`ArrayList`对象（请参见上一节中的示例）

+   `binarySearch()`: 允许搜索数组或其部分（由索引范围指定）

+   `compare()`, `mismatch()`, `equals()`, and `deepEquals()`: 比较两个数组或它们的部分（由索引范围）

+   `copyOf()` and `copyOfRange()`: 复制所有数组或其中的一部分（由索引范围）

+   `hashcode()` and `deepHashCode()`: 根据提供的数组内容生成哈希码值

+   `toString()` and `deepToString()`: 创建数组的`String`表示（请参见上一节中的示例）

+   `fill()`, `setAll()`, `parallelPrefix()`, and `parallelSetAll()`: 设置数组的每个元素的值（由提供的函数生成的固定值或值）或由索引范围指定的元素的值

+   `sort()` and `parallelSort()`: 对数组的元素进行排序或仅对部分元素进行排序（由索引范围指定）

+   `splititerator()`: 返回用于并行处理数组或其部分（由索引范围指定）的`Splititerator`对象

+   `stream()`: 生成数组元素或其中一些元素的流（由索引范围指定）；请参见第十八章，*流和管道*

所有这些方法都很有用，但我们想要吸引您注意的是`equals(a1, a2)`和`deepEquals(a1, a2)`方法。它们对于数组比较特别有帮助，因为数组对象不允许实现自定义方法`equals(a)`，因此总是使用类`Object`的实现来比较只有引用。

相比之下，`equals(a1, a2)`和`deepEquals(a1, a2)`方法不仅比较引用`a1`和`a2`，而且在数组的情况下使用`equals(a)`方法来比较元素。这意味着非嵌套数组是通过它们的元素的值进行比较的，并且当两个数组都为`null`或它们的长度相等且方法`a1[i].equals(a2[i])`对于每个索引返回`true`时被认为是相等的：

```java
Integer[] as1 = {1,2,3};
Integer[] as2 = {1,2,3};
System.out.println(as1.equals(as2));               //prints: false
System.out.println(Arrays.equals(as1, as2));       //prints: true
System.out.println(Arrays.deepEquals(as1, as2));   //prints: true

```

对于嵌套数组，`equals(a1, a2)`方法使用`equals(a)`方法来比较下一级的元素。但是嵌套数组的元素是数组，因此它们仅通过引用而不是它们的元素的值进行比较。如果需要比较所有嵌套级别上的元素的值，请使用方法`deepEquals(a1, a2)`：

```java
Integer[][] aas1 = {{1,2,3}, {4,5,6}};
Integer[][] aas2 = {{1,2,3}, {4,5,6}};
System.out.println(Arrays.equals(aas1, aas2));       //prints: false
System.out.println(Arrays.deepEquals(aas1, aas2));   //prints: true

Integer[][][] aaas1 = {{{1,2,3}, {4,5,6}}, {{7,8,9}, {10,11,12}}};
Integer[][][] aaas2 = {{{1,2,3}, {4,5,6}}, {{7,8,9}, {10,11,12}}};
System.out.println(Arrays.deepEquals(aaas1, aaas2)); //prints: true

```

# Class lang3.ArrayUtils

类`org.apache.commons.lang3.ArrayUtils`是类`java.util.Arrays`的补充。它为数组管理工具包添加了新的方法，并能够在否则会抛出`NullPointerException`的情况下处理`null`。

与`Arrays`类类似，`ArrayUtils`类有许多（大约 300 个）重载方法，可以分为 12 组：

+   `add()`, `addAll()`, and `insert()`: 向数组添加元素

+   `clone()`: 克隆数组，类似于`java.util.Arrays`中的`copyOf()`方法和`java.lang.System`的`arraycopy()`方法

+   `getLength()`: 返回数组长度并处理`null`（当数组为`null`时，尝试读取属性`length`会抛出`NullPointerException`）

+   `hashCode()`：计算数组的哈希值，包括嵌套数组

+   `contains()`、`indexOf()`和`lastIndexOf()`：搜索数组

+   `isSorted()`、`isEmpty`和`isNotEmpty()`：检查数组并处理`null`

+   `isSameLength()`和`isSameType()`：比较数组

+   `nullToEmpty()`: 将`null`数组转换为空数组

+   `remove()`、`removeAll()`、`removeElement()`、`removeElements()`和`removeAllOccurances()`：移除元素

+   `reverse()`、`shift()`、`shuffle()`和`swap()`：改变数组元素的顺序

+   `subarray()`: 通过索引范围提取数组的一部分

+   `toMap()`、`toObject()`、`toPrimitive()`、`toString()`和`toStringArray()`：将数组转换为另一种类型并处理`null`值

# 练习- 对对象列表进行排序

列出两种允许对对象列表进行排序的方法，以及它们的使用先决条件。

# 答案

`java.util.Collections`类的两个静态方法：

+   `void sort(List<T> list)`: 对实现了`Comparable`接口的对象列表进行排序（使用`compareTo(T)`方法）

+   `void sort(List<T> list, Comparator<T> comparator)`: 根据提供的`Comparator`对对象进行排序（使用`compare(T o1, T o2)`方法）

# 总结

在本章中，我们向读者介绍了 Java 标准库和 Apache Commons 中的类，这些类允许操作集合和数组。每个 Java 程序员都必须了解`java.util.Collections`、`java.util.Arrays`、`org.acpache.commons.collections4.CollectionUtils`和`org.acpache.commons.lang3.ArrayUtils`类的功能。

在下一章中，我们将讨论与本章讨论的类一起属于最受欢迎的实用程序组的类，每个程序员都必须掌握这些类，以成为有效的编码人员。


# 第十五章：管理对象、字符串、时间和随机数

在本章中我们将讨论的类，与前几章讨论的 Java 集合和数组一起属于每个程序员都必须掌握的一类（主要是来自 Java 标准库和 Apache Commons 的工具类），以成为一名高效的编码人员。它们也展示了各种软件设计和解决方案，具有指导意义，并可作为最佳编码实践的模式。

我们将涵盖以下功能领域：

+   管理对象

+   管理字符串

+   管理时间

+   管理随机数

概述的类列表包括：

+   `java.util.Objects`

+   `org.apache.commons.lang3.ObjectUtils`

+   `java.lang.String`

+   `org.apache.commons.lang3.StringUtils`

+   `java.time.LocalDate`

+   `java.time.LocalTime`

+   `java.time.LocalDateTime`

+   `java.lang.Math`

+   `java.util.Random`

# 管理对象

你可能不需要管理数组，甚至可能一段时间内不需要管理集合，但你无法避免管理对象，这意味着本节描述的类你可能每天都会使用。

尽管`java.util.Objects`类是在 2011 年（Java 7 发布时）添加到 Java 标准库中的，而`ObjectUtils`类自 2002 年以来就存在于 Apache Commons 库中，但它们的使用增长缓慢。这可能部分地可以解释它们最初的方法数量很少-2003 年`ObjectUtils`只有 6 个方法，2011 年`Objects`只有 9 个方法。然而，它们是非常有用的方法，可以使代码更易读、更健壮，减少错误的可能性。因此，为什么这些类从一开始就没有被更频繁地使用至今仍然是个谜。我们希望你能立即在你的第一个项目中开始使用它们。

# 类 java.util.Objects

类`Objects`只有 17 个方法-全部是静态的。在前一章中，当我们实现了类`Person`时，我们已经使用了其中的一些方法：

```java
class Person implements Comparable<Person> {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name == null ? "" : name;
    }
    public int getAge(){ return this.age; }
    public String getName(){ return this.name; }
    @Override
    public int compareTo(Person p){
        int result = this.name.compareTo(p.getName());
        if (result != 0) {
            return result;
        }
        return this.age - p.getAge();
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if(!(o instanceof Person)) return false;
        Person person = (Person)o;
        return age == person.getAge() &&
               Objects.equals(name, person.getName()); //line 25
    }
    @Override
    public int hashCode(){
        return Objects.hash(age, name);
    }
    @Override
    public String toString() {
        return "Person{age=" + age + ", name=" + name + "}";
    }
}
```

我们以前在`equals()`和`hashCode()`方法中使用了`Objects`类。一切都运行良好。但是，请注意我们如何检查前一个构造函数中的参数`name`。如果参数是`null`，我们将空的`String`值赋给字段`name`。我们这样做是为了避免第 25 行的`NullPointerException`。另一种方法是使用 Apache Commons 库中的`ObjectUtils`类。我们将在下一节中进行演示。`ObjectUtils`类的方法处理`null`值，并使将`null`参数转换为空的`String`变得不必要。

但首先，让我们回顾一下`Objects`类的方法。

# equals()和 deepEquals()

我们详细讨论了`equals()`方法的实现，但一直假设它是在一个非`null`的对象`obj`上调用的，`obj.equals(anotherObject)`的调用不会产生`NullPointerException`。

然而，有时我们需要比较两个对象`a`和`b`，当它们中的一个或两个可以是`null`时。以下是这种情况的典型代码：

```java
boolean equals(Object a, Object b) {
    return (a == b) || (a != null && a.equals(b));
}
```

这是`boolean Objects.equals(Object a, Object b)`方法的实际源代码。它允许使用方法`equals(Object)`比较两个对象，并处理其中一个或两个为`null`的情况。

`Objects`类的另一个相关方法是`boolean deepEquals(Object a, Object b)`。以下是其源代码：

```java
boolean deepEquals(Object a, Object b) {
    if (a == b)
        return true;
    else if (a == null || b == null)
        return false;
    else
        return Arrays.deepEquals0(a, b);
}
```

正如您所见，它是基于我们在前一节中讨论的`Arrays.deepEquals()`。这些方法的演示代码有助于理解它们之间的区别：

```java
Integer[] as1 = {1,2,3};
Integer[] as2 = {1,2,3};
System.out.println(Arrays.equals(as1, as2));        //prints: true
System.out.println(Arrays.deepEquals(as1, as2));    //prints: true

System.out.println(Objects.equals(as1, as2));        //prints: false
System.out.println(Objects.deepEquals(as1, as2));    //prints: true

Integer[][] aas1 = {{1,2,3},{1,2,3}};
Integer[][] aas2 = {{1,2,3},{1,2,3}};
System.out.println(Arrays.equals(aas1, aas2));       //prints: false
System.out.println(Arrays.deepEquals(aas1, aas2));   //prints: true

System.out.println(Objects.equals(aas1, aas2));       //prints: false
System.out.println(Objects.deepEquals(aas1, aas2));   //prints: true

```

在上述代码中，`Objects.equals(as1, as2)`和`Objects.equals(aas1, aas2)`返回`false`，因为数组无法覆盖`Object`类的`equals()`方法，而是通过引用而不是值进行比较。

方法`Arrays.equals(aas1, aas2)`返回`false`的原因相同：因为嵌套数组的元素是数组，通过引用进行比较。

总而言之，如果您想比较两个对象`a`和`b`的字段值，则：

+   如果它们不是数组且`a`不是`null`，请使用`a.equals(b)`

+   如果它们不是数组且两个对象都可以是`null`，请使用`Objects.equals(a, b)`

+   如果两者都可以是数组且都可以是`null`，请使用`Objects.deepEquals(a, b)`

也就是说，我们可以看到方法`Objects.deepEquals()`是最安全的方法，但这并不意味着您必须总是使用它。大多数情况下，您将知道要比较的对象是否可以为`null`或可以是数组，因此您也可以安全地使用其他`equals()`方法。

# hash()和 hashCode()

方法`hash()`或`hashCode()`返回的哈希值通常用作将对象存储在使用哈希的集合中的键，例如`HashSet()`。在`Object`超类中的默认实现基于内存中的对象引用。对于具有相同类的两个对象且具有相同实例字段值的情况，它返回不同的哈希值。因此，如果需要两个类实例具有相同状态的相同哈希值，则重写默认的`hashCode()`实现使用以下方法至关重要：

+   `int hashCode(Object value)`: 计算单个对象的哈希值

+   `int hash(Object... values)`: 计算对象数组的哈希值（请看我们在前面示例中的`Person`类中如何使用它）

请注意，当将同一对象用作方法`Objects.hash()`的单个输入数组时，这两种方法返回不同的哈希值：

```java
System.out.println(Objects.hash("s1"));           //prints: 3645
System.out.println(Objects.hashCode("s1"));       //prints: 3614

```

仅一个值会从两种方法中返回相同的哈希值：`null`

```java
System.out.println(Objects.hash(null));      //prints: 0
System.out.println(Objects.hashCode(null));  //prints: 0

```

当作为单个非空参数使用时，相同的值从方法`Objects.hashCode(Object value)`和`Objects.hash(Object... values)`返回的哈希值不同。值`null`从这些方法中返回相同的哈希值`0`。

使用类`Objects`进行哈希值计算的另一个优点是它能容忍`null`值，而在尝试对`null`引用调用实例方法`hashCode()`时会生成`NullPointerException`。

# isNull() 和 nonNull()

这两个方法只是对布尔表达式`obj == null`和`obj != null`的简单包装：

+   `boolean isNull(Object obj)`: 返回与`obj == null`相同的值。

+   `boolean nonNull(Object obj)`: 返回与`obj != null`相同的值。

这是演示代码：

```java
String object = null;

System.out.println(object == null);           //prints: true
System.out.println(Objects.isNull(object));   //prints: true

System.out.println(object != null);           //prints: false
System.out.println(Objects.nonNull(object));  //prints: false
```

# requireNonNull()

类`Objects`的以下方法检查第一个参数的值，如果值为`null`，则抛出`NullPointerException`或返回提供的默认值：

+   `T requireNonNull(T obj)`: 如果参数为`null`，则抛出没有消息的`NullPointerException`：

```java
      String object = null;
      try {
          Objects.requireNonNull(object);
      } catch (NullPointerException ex){
          System.out.println(ex.getMessage());  //prints: null
      }
```

+   `T requireNonNull(T obj, String message)`: 如果第一个参数为`null`，则抛出带有提供消息的`NullPointerException`：

```java
      String object = null;
      try {
          Objects.requireNonNull(object, "Parameter 'object' is null");
      } catch (NullPointerException ex){
          System.out.println(ex.getMessage());  
          //Parameter 'object' is null
      }
```

+   `T requireNonNull(T obj, Supplier<String> messageSupplier)`: 如果第一个参数为`null`，则返回由提供的函数生成的消息，如果生成的消息或函数本身为`null`，则抛出`NullPointerException`：

```java
      String object = null;
      Supplier<String> msg1 = () -> {
          String msg = "Msg from db";
          //get the corresponding message from database
          return msg;
      };
      try {
          Objects.requireNonNull(object, msg1);
      } catch (NullPointerException ex){
          System.out.println(ex.getMessage());  //prints: Msg from db
      }
      Supplier<String> msg2 = () -> null;
      try {
          Objects.requireNonNull(object, msg2);
      } catch (NullPointerException ex){
          System.out.println(ex.getMessage());  //prints: null
      }
      Supplier<String> msg3 = null;
      try {
          Objects.requireNonNull(object, msg3);
      } catch (NullPointerException ex){
          System.out.println(ex.getMessage());  //prints: null
      }
```

+   `T requireNonNullElse(T obj, T defaultObj)`: 如果第一个参数非空，则返回第一个参数的值，如果第二个参数非空，则返回第二个参数的值，如果都为空，则抛出带有消息`defaultObj`的`NullPointerException`：

```java
      String object = null;
      System.out.println(Objects.requireNonNullElse(object, 
                              "Default value"));   
                              //prints: Default value
      try {
          Objects.requireNonNullElse(object, null);
      } catch (NullPointerException ex){
          System.out.println(ex.getMessage());     //prints: defaultObj
      }
```

+   `T requireNonNullElseGet(T obj, Supplier<? extends T> supplier)`: 如果第一个参数非空，则返回第一个参数的值，否则返回由提供的函数生成的对象，如果都为空，则抛出带有消息`defaultObj`的`NullPointerException`：

```java
      String object = null;
      Supplier<String> msg1 = () -> {
          String msg = "Msg from db";
          //get the corresponding message from database
          return msg;
      };
      String s = Objects.requireNonNullElseGet(object, msg1);
      System.out.println(s);                //prints: Msg from db

      Supplier<String> msg2 = () -> null;
      try {
       System.out.println(Objects.requireNonNullElseGet(object, msg2));
      } catch (NullPointerException ex){
       System.out.println(ex.getMessage()); //prints: supplier.get()
      }
      try {
       System.out.println(Objects.requireNonNullElseGet(object, null));
      } catch (NullPointerException ex){
       System.out.println(ex.getMessage()); //prints: supplier
      }
```

# checkIndex()

以下一组方法检查集合或数组的索引和长度是否兼容：

+   `int checkIndex(int index, int length)`: 如果提供的`index`大于`length - 1`，则抛出`IndexOutOfBoundsException`。

+   `int checkFromIndexSize(int fromIndex, int size, int length)`: 如果提供的`index + size`大于`length - 1`，则抛出`IndexOutOfBoundsException`。

+   `int checkFromToIndex(int fromIndex, int toIndex, int length)`: 如果提供的`fromIndex`大于`toIndex`，或`toIndex`大于`length - 1`，则抛出`IndexOutOfBoundsException`。

这是演示代码：

```java
List<String> list = List.of("s0", "s1");
try {
    Objects.checkIndex(3, list.size());
} catch (IndexOutOfBoundsException ex){
    System.out.println(ex.getMessage());  
                         //prints: Index 3 out-of-bounds for length 2
}
try {
    Objects.checkFromIndexSize(1, 3, list.size());
} catch (IndexOutOfBoundsException ex){
    System.out.println(ex.getMessage());  
                //prints: Range [1, 1 + 3) out-of-bounds for length 2
}

try {
    Objects.checkFromToIndex(1, 3, list.size());
} catch (IndexOutOfBoundsException ex){
    System.out.println(ex.getMessage());  
                    //prints: Range [1, 3) out-of-bounds for length 2
}
```

# compare()

类`Objects`的方法`int compare(T a, T b, Comparator<T> c)`使用提供的比较器的方法`compare(T o1, T o2)`来比较两个对象。我们已经在谈论排序集合时描述了`compare(T o1, T o2)`方法的行为，因此应该期望以下结果：

```java
int diff = Objects.compare("a", "c", Comparator.naturalOrder());
System.out.println(diff);  //prints: -2
diff = Objects.compare("a", "c", Comparator.reverseOrder());
System.out.println(diff);  //prints: 2
diff = Objects.compare(3, 5, Comparator.naturalOrder());
System.out.println(diff);  //prints: -1
diff = Objects.compare(3, 5, Comparator.reverseOrder());
System.out.println(diff);  //prints: 1

```

如前所述，方法`compare(T o1, T o2)`返回`String`对象中对象`o1`和`o2`在排序列表中的位置之间的差异，而对于`Integer`对象，则返回`-1`、`0`或`1`。API 描述它返回`0`当对象相等时，返回负数当第一个对象小于第二个对象时；否则，它返回正数。

为了演示方法`compare(T a, T b, Comparator<T> c)`的工作原理，假设我们要按照`Person`类对象的名称和年龄以分别按照`String`和`Integer`类的自然排序方式进行排序：

```java
@Override
public int compareTo(Person p){
    int result = Objects.compare(this.name, p.getName(),
                                         Comparator.naturalOrder());
    if (result != 0) {
        return result;
    }
    return Objects.compare(this.age, p.getAge(), 
                                         Comparator.naturalOrder());
}
```

下面是`Person`类中`compareTo(Object)`方法的新实现的结果：

```java
Person p1 = new Person(15, "Zoe");
Person p2 = new Person(45, "Adam");
Person p3 = new Person(37, "Bob");
Person p4 = new Person(30, "Bob");
List<Person> list = new ArrayList<>(List.of(p1, p2, p3, p4));
System.out.println(list);//[{15, Zoe}, {45, Adam}, {37, Bob}, {30, Bob}]
Collections.sort(list);
System.out.println(list);//[{45, Adam}, {30, Bob}, {37, Bob}, {15, Zoe}] 
```

正如您所看到的，`Person`对象首先按照它们的名称的自然顺序排序，然后按照它们的年龄的自然顺序排序。如果我们需要反转名称的顺序，例如，我们将`compareTo(Object)`方法更改为以下内容：

```java
@Override
public int compareTo(Person p){
    int result = Objects.compare(this.name, p.getName(),
                                         Comparator.reverseOrder());
    if (result != 0) {
        return result;
    }
    return Objects.compare(this.age, p.getAge(), 
                                         Comparator.naturalOrder());
}
```

结果的样子就像我们期望的一样：

```java
Person p1 = new Person(15, "Zoe");
Person p2 = new Person(45, "Adam");
Person p3 = new Person(37, "Bob");
Person p4 = new Person(30, "Bob");
List<Person> list = new ArrayList<>(List.of(p1, p2, p3, p4));
System.out.println(list);//[{15, Zoe}, {45, Adam}, {37, Bob}, {30, Bob}]
Collections.sort(list);
System.out.println(list);//[{15, Zoe}, {30, Bob}, {37, Bob}, {45, Adam}] 
```

方法`compare(T a, T b, Comparator<T> c)`的弱点在于它不能处理`null`值。将`new Person(25, null)`对象添加到列表中，在排序时会触发`NullPointerException`异常。在这种情况下，最好使用`org.apache.commons.lang3.ObjectUtils.compare(T o1, T o2)`方法，我们将在下一节中演示。

# toString()

有时需要将一个`Object`对象（它是对某个类类型的引用）转换为它的`String`表示。当引用`obj`被赋予`null`值（对象还未创建）时，编写`obj.toString()`会生成`NullPointerException`异常。对于这种情况，使用`Objects`类的以下方法是更好的选择：

+   `String toString(Object o)`: 当第一个参数值不为`null`时，返回调用第一个参数的`toString()`的结果，否则返回`null`

+   `String toString(Object o, String nullDefault)`: 当第一个参数值不为`null`时，返回调用第一个参数的`toString()`的结果，否则返回第二个参数值`nullDefault`

这是演示如何使用这些方法的代码：

```java
List<String> list = new ArrayList<>(List.of("s0 "));
list.add(null);
for(String e: list){
    System.out.print(e);                   //prints: s0 null
}
System.out.println();
for(String e: list){
    System.out.print(Objects.toString(e)); //prints: s0 null
}
System.out.println();
for(String e: list){
    System.out.print(Objects.toString(e, "element was null")); 
                                        //prints: s0 element was null
}
```

顺便提一下，与当前讨论无关的是，请注意我们如何使用`print()`方法而不是`println()`方法来显示所有结果在一行中，因为`print()`方法不会添加行结束符。

# `ObjectUtils`类

Apache Commons 库的`org.apache.commons.lang3.ObjectUtils`类补充了先前描述的`java.util.Objects`类的方法。本书的范围和分配的大小不允许详细审查`ObjectUtils`类的所有方法，因此我们将根据相关功能进行简要描述，并仅演示那些与我们已经提供的示例相关的方法。

`ObjectUtils`类的所有方法可以分为七个组：

+   对象克隆方法：

    +   `T clone(T obj)`: 如果提供的对象实现了`Cloneable`接口，则返回提供的对象的副本；否则返回`null`。

    +   `T cloneIfPossible(T obj)`: 如果提供的对象实现了`Cloneable`接口，则返回提供的对象的副本；否则返回原始提供的对象。

+   支持对象比较的方法：

    +   `int compare(T c1, T c2)`: 比较实现`Comparable`接口的两个对象的新排序位置；允许任意参数或两个参数都为`null`；将一个`null`值放在非空值的前面。

    +   `int compare(T c1, T c2, boolean nullGreater)`: 如果参数`nullGreater`的值为`false`，则行为与前一个方法完全相同；否则，将一个`null`值放在非空值的后面。我们可以通过在我们的`Person`类中使用最后两个方法来演示这两个方法：

```java
@Override
public int compareTo(Person p){
    int result = ObjectUtils.compare(this.name, p.getName());
    if (result != 0) {
        return result;
    }
    return ObjectUtils.compare(this.age, p.getAge());
}
```

这种改变的结果使我们可以为`name`字段使用`null`值。

```java
Person p1 = new Person(15, "Zoe");
Person p2 = new Person(45, "Adam");
Person p3 = new Person(37, "Bob");
Person p4 = new Person(30, "Bob");
Person p5 = new Person(25, null);
List<Person> list = new ArrayList<>(List.of(p1, p2, p3, p4, p5));
System.out.println(list);  //[{15, Zoe}, {45, Adam}, {37, Bob}, {30, Bob}, {25, }]
Collections.sort(list);
System.out.println(list);  //[{25, }, {45, Adam}, {30, Bob}, {37, Bob}, {15, Zoe}]

```

由于我们使用了`Objects.compare(T c1, T c2)`方法，`null`值被放在非空值的前面。顺便问一下，你是否注意到我们不再显示`null`了？那是因为我们已经按照以下方式更改了类`Person`的方法`toString()`：

```java
@Override
public String toString() {
    //return "{" + age + ", " + name + "}";
    return "{" + age + ", " + Objects.toString(name, "") + "}";
}
```

不仅仅显示字段`name`的值，我们还使用了方法`Objects.toString(Object o, String nullDefault)`，当对象为`null`时，用提供的`nullDefault`值替换对象。在这种情况下，是否使用此方法是一种风格问题。许多程序员可能会认为我们必须显示实际值，而不是将其替换为其他内容。但是，我们这样做只是为了展示方法`Objects.toString(Object o, String nullDefault)`的用法。

如果我们现在使用第二个`compare(T c1, T c2, boolean nullGreater)`方法，那么类`Person`的`compareTo()`方法将如下所示：

```java
@Override
public int compareTo(Person p){
    int result = ObjectUtils.compare(this.name, p.getName(), true);
    if (result != 0) {
        return result;
    }
    return ObjectUtils.compare(this.age, p.getAge());
}
```

接着，具有其`name`设置为`null`的`Person`对象将显示在排序列表的末尾：

```java
Person p1 = new Person(15, "Zoe");
Person p2 = new Person(45, "Adam");
Person p3 = new Person(37, "Bob");
Person p4 = new Person(30, "Bob");
Person p5 = new Person(25, null);
List<Person> list = new ArrayList<>(List.of(p1, p2, p3, p4, p5));
System.out.println(list);  
               //[{15, Zoe}, {45, Adam}, {37, Bob}, {30, Bob}, {25, }]
Collections.sort(list);
System.out.println(list);  
               //[{45, Adam}, {30, Bob}, {37, Bob}, {15, Zoe}, {25, }]

```

为了完成关于`null`值的讨论，当将`null`对象添加到列表中时，上述代码将抛出`NullPointerException`异常：`list.add(null)`。为了避免异常，可以使用一个特殊的`Comparator`对象来处理列表的`null`元素：

```java
Person p1 = new Person(15, "Zoe");
Person p2 = new Person(45, "Adam");
Person p3 = new Person(37, "Bob");
Person p4 = new Person(30, "Bob");
Person p5 = new Person(25, null);
List<Person> list = new ArrayList<>(List.of(p1, p2, p3, p4, p5));
list.add(null);
System.out.println(list);  
        //[{15, Zoe}, {45, Adam}, {37, Bob}, {30, Bob}, {25, }, null]
Collections.sort(list, 
 Comparator.nullsLast(Comparator.naturalOrder()));
System.out.println(list);  
        //[{45, Adam}, {30, Bob}, {37, Bob}, {15, Zoe}, {25, }, null]
```

在这段代码中，你可以看到我们已经表明希望在列表的末尾看到`null`对象。相反，我们可以使用另一个将空对象放在排序列表开头的`Comparator`：

```java
Collections.sort(list, 
                   Comparator.nullsFirst(Comparator.naturalOrder()));
System.out.println(list);  
        //[null, {45, Adam}, {30, Bob}, {37, Bob}, {15, Zoe}, {25, }]

```

+   `notEqual`：

    +   `boolean notEqual(Object object1, Object object2)`: 比较两个对象是否不相等，其中一个或两个对象都可以是`null`。

+   `identityToString`：

    +   `String identityToString(Object object)`: 返回提供的对象的`String`表示，就好像是由基类`Object`的默认方法`toString()`生成的一样。

    +   `void identityToString(StringBuffer buffer, Object object)`: 将所提供对象的`String`表示追加到提供的`StringBuffer`对象上，就好像由基类`Object`的默认方法`toString()`生成一样。

    +   `void identityToString(StringBuilder builder, Object object)`: 将所提供对象的`String`表示追加到提供的`StringBuilder`对象上，就好像由基类`Object`的默认方法`toString()`生成一样。

    +   `void identityToString(Appendable appendable, Object object)`: 将所提供对象的`String`表示追加到提供的`Appendable`对象上，就好像由基类`Object`的默认方法`toString()`生成一样。

以下代码演示了其中的两种方法：

```java
String s = "s0 " + ObjectUtils.identityToString("s1");
System.out.println(s);  //prints: s0 java.lang.String@5474c6c

StringBuffer sb = new StringBuffer();
sb.append("s0");
ObjectUtils.identityToString(sb, "s1");
System.out.println(s);  //prints: s0 java.lang.String@5474c6c

```

+   `allNotNull`和`anyNotNull`：

    +   `boolean allNotNull(Object... values)`: 当所提供数组中所有值都不为`null`时返回`true`。

    +   `boolean anyNotNull(Object... values)`: 当所提供数组中至少有一个值不为`null`时返回`true`。

+   `firstNonNull`和`defaultIfNull`：

    +   `T firstNonNull(T... values)`: 返回所提供数组中第一个不为`null`的值。

    +   `T defaultIfNull(T object, T defaultValue)`: 如果第一个参数为`null`，则返回提供的默认值。

+   `max`、`min`、`median`和`mode`：

    +   `T max(T... values)`: 返回所提供值列表中实现了`Comparable`接口的最后一个值；仅当所有值都为`null`时返回`null`。

    +   `T min(T... values)`: 返回所提供值列表中实现了`Comparable`接口的第一个值；仅当所有值都为`null`时返回`null`。

    +   `T median(T... items)`: 返回所提供值列表中实现了`Comparable`接口的有序列表中位于中间的值；如果值的计数是偶数，则返回中间两个中较小的一个。

    +   `T median(Comparator<T> comparator, T... items)`: 返回根据提供的`Comparator`对象对提供的值列表排序后位于中间的值；如果值的计数是偶数，则返回中间两个中较小的一个。

    +   `T mode(T... items)`: 返回提供的项目中出现频率最高的项目；当没有出现最频繁的项目或没有一个项目最频繁地出现时返回`null`；下面是演示此最后一个方法的代码：

```java
String s = ObjectUtils.mode("s0", "s1", "s1");
System.out.println(s);     //prints: s1

s = ObjectUtils.mode("s0", "s1", "s2");
System.out.println(s);     //prints: null

s = ObjectUtils.mode("s0", "s1", "s2", "s1", "s2");
System.out.println(s);     //prints: null

s = ObjectUtils.mode(null);
System.out.println(s);     //prints: null

s = ObjectUtils.mode("s0", null, null);
System.out.println(s);     //prints: null

```

# 管理字符串

类`String`经常被使用。因此，您必须对其功能有很好的掌握。我们已经在第五章中讨论了`String`值的不可变性，*Java 语言元素和类型*。我们已经表明，每次“修改”`String`值时，都会创建一个新副本，这意味着在多次“修改”的情况下，会创建许多`String`对象，消耗内存并给 JVM 带来负担。

在这种情况下，建议使用类`java.lang.StringBuilder`或`java.lang.StringBuffer`，因为它们是可修改的对象，不需要创建`String`值的副本。我们将展示如何使用它们，并在本节的第一部分解释这两个类之间的区别。

之后，我们会回顾类`String`的方法，然后提供一个对`org.apache.commons.lang3.StringUtils`类的概述，该类补充了类`String`的功能。

# `StringBuilder`和`StringBuffer`

类`StringBuilder`和`StringBuffer`具有完全相同的方法列表。不同之处在于类`StringBuilder`的方法执行速度比类`StringBuffer`的相同方法更快。这是因为类`StringBuffer`不允许不同应用程序线程同时访问其值，所以如果你不是为多线程处理编码，就使用`StringBuilder`。

类`StringBuilder`和`StringBuffer`中有许多方法。但是，我们将展示如何只使用方法`append()`，这显然是最受欢迎的方法，用于需要多次修改`String`值的情况。它的主要功能是将一个值追加到已存储在`StringBuilder`（或`StringBuffer`）对象中的值的末尾。

方法`append()`被重载为所有原始类型和类`String`、`Object`、`CharSequence`和`StringBuffer`，这意味着传入任何这些类的对象的`String`表示都可以追加到现有值中。为了演示，我们将只使用`append(String s)`版本，因为这可能是你大部分时间都会使用的。这里是一个例子：

```java
List<String> list = 
  List.of("That", "is", "the", "way", "to", "build", "a", "sentence");
StringBuilder sb = new StringBuilder();
for(String s: list){
    sb.append(s).append(" ");
}
String s = sb.toString();
System.out.println(s);  //prints: That is the way to build a sentence

```

类`StringBuilder`（和`StringBuffer`）中还有`replace()`、`substring()`和`insert()`方法，允许进一步修改值。虽然它们不像方法`append()`那样经常使用，但我们不打算讨论它们，因为它们超出了本书的范围。

# 类 java.lang.String

类`String`有 15 个构造函数和近 80 个方法。在这本书中详细讨论和演示每一个方法对来说有点过分，所以我们只会评论最受欢迎的方法，其他的只会提到。当你掌握了基础知识后，你可以阅读在线文档，看看类`String`的其他方法还可以做什么。

# 构造函数

如果您担心应用程序创建的字符串消耗过多的内存，则`String`类的构造函数很有用。问题在于，`String`字面值（例如`abc`）存储在内存的特殊区域中，称为“字符串常量池”，并且永远不会被垃圾回收。这样设计的理念是，`String`字面值消耗的内存远远超过数字。此外，处理这样的大型实体会产生开销，可能会使 JVM 负担过重。这就是设计者认为将它们存储并在所有应用程序线程之间共享比分配新内存然后多次清理相同值更便宜的原因。

但是，如果`String`值的重用率较低，而存储的`String`值消耗过多内存，则使用构造函数创建`String`对象可能是解决问题的方法。这里是一个例子：

```java
String veryLongText = new String("asdakjfakjn akdb aakjn... akdjcnak");
```

以这种方式创建的`String`对象位于堆区（存储所有对象的地方），并且在不再使用时进行垃圾回收。这就是`String`构造函数发挥作用的时候。

如有必要，您可以使用`String`类的`intern()`方法，在字符串常量池中创建堆`String`对象的副本。它不仅允许我们与其他应用程序线程共享值（在多线程处理中），还允许我们通过引用（使用运算符`==`）将其与另一个字面值进行比较。如果引用相等，则意味着它们指向池中的相同`String`值。

但是，主流程序员很少以这种方式管理内存，因此我们将不再进一步讨论这个话题。

# `format()`

方法`String format(String format, Object... args)`允许将提供的对象插入字符串的指定位置，并根据需要进行格式化。在`java.util.Formatter`类中有许多格式说明符。我们这里只演示`%s`，它通过调用对象的`toString()`方法将传入的对象转换为其`String`表示形式：

```java
String format = "There is a %s in the %s";
String s = String.format(format, "bear", "woods");
System.out.println(s); //prints: There is a bear in the woods

format = "Class %s is very useful";
s = String.format(format, new A());
System.out.println(s);  //prints: Class A is very useful

```

# `replace()`

`String` 类中的方法`String replace(CharSequence target, CharSequence replacement)`，该方法会用第二个参数的值替换第一个参数的值：

```java
String s1 = "There is a bear in the woods";
String s2 = s1.replace("bear", "horse").replace("woods", "field");
System.out.println(s2);     //prints: There is a horse in the field

```

还有一些方法，比如`String replaceAll(String regex, String replacement)`和`String replaceFirst(String regex, String replacement)`，它们具有类似的功能。

# `compareTo()`

我们已经在示例中使用了`int compareTo(String anotherString)`方法。它返回此`String`值和`anotherString`值在有序列表中的位置差异。它用于字符串的自然排序，因为它是`Comparable`接口的实现。

方法`int compareToIgnoreCase(String str)`执行相同的功能，但会忽略比较字符串的大小写，并且不用于自然排序，因为它不是`Comparable`接口的实现。

# `valueOf(Object j)`

静态方法 `String valueOf(Object obj)` 如果提供的对象为 `null`，则返回 `null`，否则调用提供对象的 `toString()` 方法。

# valueOf(基本类型或字符数组)

任何基本类型的值都可以作为参数传递给静态方法 `String valueOf(primitive value)`，该方法返回所提供值的字符串表示形式。例如，`String.valueOf(42)` 返回`42`。该组方法包括以下静态方法：

+   `String valueOf(boolean b)`

+   `String valueOf(char c)`

+   `String valueOf(double d)`

+   `String valueOf(float f)`

+   `String valueOf(int i)`

+   `String valueOf(long l)`

+   `String valueOf(char[] data)`

+   `String valueOf(char[] data, int offset, int count)`

# copyValueOf(char[])

方法 `String copyValueOf(char[] data)` 等效于 `valueOf(char[])`，而方法 `String copyValueOf(char[] data, int offset, int count)` 等效于 `valueOf(char[], int, int)`。它们返回字符数组或其子数组的 `String` 表示形式。

而方法 `void getChars(int srcBegin, int srcEnd, char[] dest, int dstBegin)` 将此 `String` 值中的字符复制到目标字符数组中。

# indexOf() 和 substring()

各种 `int indexOf(String str)` 和 `int lastIndexOf(String str)` 方法返回字符串中子字符串的位置：

```java
String s = "Introduction";
System.out.println(s.indexOf("I"));      //prints: 0
System.out.println(s.lastIndexOf("I"));  //prints: 0
System.out.println(s.lastIndexOf("i"));  //prints: 9
System.out.println(s.indexOf("o"));      //prints: 4
System.out.println(s.lastIndexOf("o"));  //prints: 10
System.out.println(s.indexOf("tro"));    //prints: 2
```

注意位置计数从零开始。

方法 `String substring(int beginIndex)` 返回从作为参数传递的位置（索引）开始的字符串的剩余部分：

```java
String s = "Introduction";
System.out.println(s.substring(1));        //prints: ntroduction
System.out.println(s.substring(2));        //prints: troduction

```

位置为 `beginIndex` 的字符是前一个子字符串中存在的第一个字符。

方法 `String substring(int beginIndex, int endIndex)` 返回从作为第一个参数传递的位置开始到作为第二个参数传递的位置的子字符串：

```java
String s = "Introduction";
System.out.println(s.substring(1, 2));        //prints: n
System.out.println(s.substring(1, 3));        //prints: nt

```

与方法 `substring(beginIndex)` 一样，位置为 `beginIndex` 的字符是前一个子字符串中存在的第一个字符，而位置为 `endIndex` 的字符不包括在内。 `endIndex - beginIndex` 的差等于子字符串的长度。

这意味着以下两个子字符串相等：

```java
System.out.println(s.substring(1));              //prints: ntroduction
System.out.println(s.substring(1, s.length()));  //prints: ntroduction

```

# contains() 和 matches()

方法 `boolean contains(CharSequence s)` 在提供的字符序列（子字符串）存在时返回 `true`：

```java
String s = "Introduction";
System.out.println(s.contains("x"));          //prints: false
System.out.println(s.contains("o"));          //prints: true
System.out.println(s.contains("tro"));        //prints: true
System.out.println(s.contains("trx"));        //prints: false

```

其他类似的方法有：

+   `boolean matches(String regex)`: 使用正则表达式（本书不讨论此内容）

+   `boolean regionMatches(int tOffset, String other, int oOffset, int length)`: 比较两个字符串的区域

+   `boolean regionMatches(boolean ignoreCase, int tOffset, String other, int oOffset, int length)`: 与上述相同，但使用标志 `ignoreCase` 指示是否忽略大小写

# split(), concat() 和 join()

方法`String[] split(String regex)`和`String[] split(String regex, int limit)`使用传入的正则表达式将字符串拆分成子字符串。我们在本书中不解释正则表达式。但是，有一个非常简单的正则表达式，即使您对正则表达式一无所知也很容易使用：如果您只是将字符串中存在的任何符号或子字符串传递到此方法中，该字符串将被拆分为以传入的值分隔的部分，例如：

```java
String[] substrings = "Introduction".split("o");
System.out.println(Arrays.toString(substrings)); 
                                       //prints: [Intr, ducti, n]
substrings = "Introduction".split("duct");
System.out.println(Arrays.toString(substrings)); 
                                      //prints: [Intro, ion] 

```

此代码仅说明了功能。但是以下代码片段更实用：

```java
String s = "There is a bear in the woods";
String[] arr = s.split(" ");
System.out.println(Arrays.toString(arr));  
                       //prints: [There, is, a, bear, in, the, woods]
arr = s.split(" ", 3);
System.out.println(Arrays.toString(arr));  
                          //prints: [There, is, a bear in the woods]

```

正如您所见，`split()`方法中的第二个参数限制了生成的子字符串的数量。

方法`String concat(String str)`将传入的值添加到字符串的末尾：

```java
String s1 =  "There is a bear";
String s2 =  " in the woods";
String s = s1.concat(s2);
System.out.println(s);  //prints: There is a bear in the woods

```

`concat()`方法创建一个新的`String`值，其中包含连接的结果，因此非常经济。但是，如果您需要添加（连接）许多值，则使用`StringBuilder`（或`StringBuffer`，如果需要保护免受并发访问）将是更好的选择。我们在前一节中讨论过这个问题。另一个选择是使用运算符`+`：

```java
String s =  s1 + s2;
System.out.println(s);  //prints: There is a bear in the woods
```

当与`String`值一起使用时，运算符`+`是基于`StringBuilder`实现的，因此允许通过修改现有的值来添加`String`值。使用 StringBuilder 和仅使用运算符`+`添加`String`值之间没有性能差异。

方法`String join(CharSequence delimiter, CharSequence... elements)`和`String join(CharSequence delimiter, Iterable<? extends CharSequence> elements)`也基于`StringBuilder`。它们使用传入的`delimiter`将提供的值组装成一个`String`值，以在创建的`String`结果中分隔组装的值。以下是一个示例：

```java
s = String.join(" ", "There", "is", "a", "bear", "in", "the", "woods");
System.out.println(s);  //prints: There is a bear in the woods

List<String> list = 
             List.of("There", "is", "a", "bear", "in", "the", "woods");
s = String.join(" ", list);
System.out.println(s);  //prints: There is a bear in the woods
```

# startsWith() 和 endsWith()

以下方法在字符串值以提供的子字符串`prefix`开始（或结束）时返回`true`：

+   `boolean startsWith(String prefix)`

+   `boolean startsWith(String prefix, int toffset)`

+   `boolean endsWith(String suffix)`

这是演示代码：

```java
boolean b = "Introduction".startsWith("Intro");
System.out.println(b);             //prints: true

b = "Introduction".startsWith("tro", 2);
System.out.println(b);             //prints: true

b = "Introduction".endsWith("ion");
System.out.println(b);             //prints: true

```

# equals() 和 equalsIgnoreCase()

我们已经多次使用了`String`类的`boolean equals(Object anObject)`方法，并指出它将此`String`值与其他对象进行比较。此方法仅在传入的对象是具有相同值的`String`时返回`true`。

方法`boolean equalsIgnoreCase(String anotherString)`也执行相同的操作，但还忽略大小写，因此字符串`AbC`和`ABC`被视为相等。

# contentEquals() 和 copyValueOf()

方法`boolean contentEquals(CharSequence cs)`将此`String`值与实现接口`CharSequence`的对象的`String`表示进行比较。流行的`CharSequence`实现包括`CharBuffer`、`Segment`、`String`、`StringBuffer`和`StringBuilder`。

方法 `boolean contentEquals(StringBuffer sb)` 仅对 `StringBuffer` 有效。它的实现略有不同于 `contentEquals(CharSequence cs)`，在某些情况下可能具有一些性能优势，但我们不打算讨论这些细节。此外，当你在 `String` 值上调用 `contentEquals()` 时，你可能甚至不会注意到使用了哪种方法，除非你努力利用差异。

# length()、isEmpty() 和 hashCode()

方法 `int length()` 返回 `String` 值中字符的数量。

方法 `boolean isEmpty()` 在 `String` 值中没有字符且方法 `length()` 返回零时返回 `true`。

方法 `int hashCode()` 返回 `String` 对象的哈希值。

# trim()、toLowerCase() 和 toUpperCase()

方法 `String trim()` 从 `String` 值中删除前导和尾随空格。

以下方法更改 `String` 值中字符的大小写：

+   `String toLowerCase()`

+   `String toUpperCase()`

+   `String toLowerCase(Locale locale)`

+   `String toUpperCase(Locale locale)`

# getBytes()、getChars() 和 toCharArray()

以下方法将 `String` 值转换为字节数组，可选择使用给定的字符集进行编码：

+   `byte[] getBytes()`

+   `byte[] getBytes(Charset charset)`

+   `byte[] getBytes(String charsetName)`

这些方法将所有或部分 `String` 值转换为其他类型：

+   `IntStream chars()`

+   `char[] toCharArray()`

+   `char charAt(int index)`

+   `CharSequence subSequence(int beginIndex, int endIndex)`

# 按索引或流获取代码点

以下一组方法将 `String` 值的全部或部分转换为其字符的 Unicode 代码点：

+   `IntStream codePoints()`

+   `int codePointAt(int index)`

+   `int codePointBefore(int index)`

+   `int codePointCount(int beginIndex, int endIndex)`

+   `int offsetByCodePoints(int index, int codePointOffset)`

我们在第五章 *Java 语言元素和类型*中解释了 Unicode 代码点。当你需要表示*不能适应* `char` 类型的两个字节时，这些方法特别有用。这样的字符具有大于 `Character.MAX_VALUE` 的代码点，即  `65535`。

# 类 lang3.StringUtils

Apache Commons 库的 `org.apache.commons.lang3.StringUtils` 类具有 120 多个静态实用方法，这些方法补充了我们在前一节中描述的 `String` 类的方法。

最受欢迎的是以下静态方法：

+   `boolean isBlank(CharSequence cs)`: 当传入的参数为空字符串""、`null` 或空格时返回 `true`

+   `boolean isNotBlank(CharSequence cs)`: 当传入的参数不为空字符串""、`null` 或空格时返回 `true`

+   `boolean isAlpha(CharSequence cs)`: 当传入的参数只包含 Unicode 字母时返回 `true`

+   `boolean isAlphaSpace(CharSequence cs)`: 当传入的参数仅包含 Unicode 字母和空格（' '）时返回`true`

+   `boolean isNumeric(CharSequence cs)`: 当传入的参数仅包含数字时返回`true`

+   `boolean isNumericSpace(CharSequence cs)`: 当传入的参数仅包含数字和空格（' '）时返回`true`

+   `boolean isAlphaNumeric(CharSequence cs)`: 当传入的参数仅包含 Unicode 字母和数字时返回`true`

+   `boolean isAlphaNumericSpace(CharSequence cs)`: 当传入的参数仅包含 Unicode 字母、数字和空格（' '）时返回`true`

我们强烈建议您查看该类的 API 并了解您可以在其中找到什么。

# 管理时间

`java.time`包及其子包中有许多类。它们被引入作为处理日期和时间的其他旧包的替代品。新类是线程安全的（因此更适合多线程处理），而且同样重要的是，设计更一致，更容易理解。此外，新实现遵循国际标准组织（ISO）的日期和时间格式，但也允许使用任何其他自定义格式。

我们将描述主要的五个类，并演示如何使用它们：

+   `java.util.LocalDate`

+   `java.util.LocalTime`

+   `java.util.LocalDateTime`

+   `java.util.Period`

+   `java.util.Duration`

所有这些以及`java.time`包及其子包中的其他类都具有丰富的各种功能，涵盖了所有实际情况和任何想象得到的情况。但我们不打算覆盖所有内容，只是介绍基础知识和最常见的用例。

# `java.time.LocalDate`

`LocalDate`类不包含时间。它表示 ISO 8601 格式的日期，即 yyyy-MM-DD：

```java
System.out.println(LocalDate.now());   //prints: 2018-04-14
```

正如您所见，方法`now()`返回当前日期，即它设置在您计算机上的日期：`April 14, 2018`是撰写本节时的日期。

类似地，您可以使用静态方法`now(ZoneId zone)`获取任何其他时区的当前日期。`ZoneId`对象可以使用静态方法`ZoneId.of(String zoneId)`构造，其中`String zoneId`是方法`ZonId.getAvailableZoneIds()`返回的任何`String`值之一：

```java
Set<String> zoneIds = ZoneId.getAvailableZoneIds();
for(String zoneId: zoneIds){
    System.out.println(zoneId);     
}
```

该代码打印了许多时区 ID，其中之一是`Asia/Tokyo`。现在，我们可以找出当前日期在该时区的日期：

```java
ZoneId zoneId = ZoneId.of("Asia/Tokyo");
System.out.println(LocalDate.now(zoneId));   //prints: 2018-04-15

```

`LocalDate`的对象也可以表示过去或未来的任何日期，使用以下方法：

+   `LocalDate parse(CharSequence text)`: 从 ISO 8601 格式的字符串 yyyy-MM-DD 构造对象

+   `LocalDate parse(CharSequence text, DateTimeFormatter formatter) `: 根据对象`DateTimeFormatter`指定的格式从字符串构造对象，该对象有许多预定义格式

+   `LocalDate of(int year, int month, int dayOfMonth)`: 从年、月和日构造对象

+   `LocalDate of(int year, Month month, int dayOfMonth)`：根据年份、月份（作为`enum`常量）和日期构造对象

+   `LocalDate ofYearDay(int year, int dayOfYear)`：根据年份和年份中的日数构造对象

以下代码演示了这些方法：

```java
LocalDate lc1 =  LocalDate.parse("2020-02-23");
System.out.println(lc1);                     //prints: 2020-02-23

DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy");
LocalDate lc2 =  LocalDate.parse("23/02/2020", formatter);
System.out.println(lc2);                     //prints: 2020-02-23

LocalDate lc3 =  LocalDate.of(2020, 2, 23);
System.out.println(lc3);                     //prints: 2020-02-23

LocalDate lc4 =  LocalDate.of(2020, Month.FEBRUARY, 23);
System.out.println(lc4);                     //prints: 2020-02-23

LocalDate lc5 = LocalDate.ofYearDay(2020, 54);
System.out.println(lc5);                     //prints: 2020-02-23

```

使用`LocalDate`对象，可以获取各种值：

```java
System.out.println(lc5.getYear());          //prints: 2020
System.out.println(lc5.getMonth());         //prints: FEBRUARY
System.out.println(lc5.getMonthValue());    //prints: 2
System.out.println(lc5.getDayOfMonth());    //prints: 23

System.out.println(lc5.getDayOfWeek());     //prints: SUNDAY
System.out.println(lc5.isLeapYear());       //prints: true
System.out.println(lc5.lengthOfMonth());    //prints: 29
System.out.println(lc5.lengthOfYear());     //prints: 366

```

`LocalDate`对象可以被修改：

```java
System.out.println(lc5.withYear(2021));     //prints: 2021-02-23
System.out.println(lc5.withMonth(5));       //prints: 2020-05-23
System.out.println(lc5.withDayOfMonth(5));  //prints: 2020-02-05
System.out.println(lc5.withDayOfYear(53));  //prints: 2020-02-22

System.out.println(lc5.plusDays(10));       //prints: 2020-03-04
System.out.println(lc5.plusMonths(2));      //prints: 2020-04-23
System.out.println(lc5.plusYears(2));       //prints: 2022-02-23

System.out.println(lc5.minusDays(10));      //prints: 2020-02-13
System.out.println(lc5.minusMonths(2));     //prints: 2019-12-23
System.out.println(lc5.minusYears(2));      //prints: 2018-02-23 
```

`LocalDate`对象也可以进行比较：

```java
LocalDate lc6 =  LocalDate.parse("2020-02-22");
LocalDate lc7 =  LocalDate.parse("2020-02-23");
System.out.println(lc6.isAfter(lc7));       //prints: false
System.out.println(lc6.isBefore(lc7));      //prints: true

```

`LocalDate`类中还有许多其他有用的方法。如果您需要处理日期，我们建议您阅读该类及其他`java.time`包及其子包的 API。

# java.time.LocalTime

`LocalTime`类包含没有日期的时间。它具有类似于`LocalDate`类的方法。

以下是如何创建`LocalTime`类的对象的方法：

```java
System.out.println(LocalTime.now());         //prints: 21:15:46.360904

ZoneId zoneId = ZoneId.of("Asia/Tokyo");
System.out.println(LocalTime.now(zoneId));   //prints: 12:15:46.364378

LocalTime lt1 =  LocalTime.parse("20:23:12");
System.out.println(lt1);                     //prints: 20:23:12

LocalTime lt2 =  LocalTime.of(20, 23, 12);
System.out.println(lt2);                     //prints: 20:23:12

```

`LocalTime`对象的每个时间值组件可以按以下方式提取：

```java
System.out.println(lt2.getHour());          //prints: 20
System.out.println(lt2.getMinute());        //prints: 23
System.out.println(lt2.getSecond());        //prints: 12
System.out.println(lt2.getNano());          //prints: 0

```

该对象可以被修改：

```java
System.out.println(lt2.withHour(3));        //prints: 03:23:12
System.out.println(lt2.withMinute(10));     //prints: 20:10:12
System.out.println(lt2.withSecond(15));     //prints: 20:23:15
System.out.println(lt2.withNano(300));      //prints: 20:23:12:000000300

System.out.println(lt2.plusHours(10));      //prints: 06:23:12
System.out.println(lt2.plusMinutes(2));     //prints: 20:25:12
System.out.println(lt2.plusSeconds(2));     //prints: 20:23:14
System.out.println(lt2.plusNanos(200));     //prints: 20:23:14:000000200

System.out.println(lt2.minusHours(10));      //prints: 10:23:12
System.out.println(lt2.minusMinutes(2));     //prints: 20:21:12
System.out.println(lt2.minusSeconds(2));     //prints: 20:23:10
System.out.println(lt2.minusNanos(200));     //prints: 20:23:11.999999800

```

`LocalTime`类的两个对象也可以进行比较：

```java
LocalTime lt3 =  LocalTime.parse("20:23:12");
LocalTime lt4 =  LocalTime.parse("20:25:12");
System.out.println(lt3.isAfter(lt4));       //prints: false
System.out.println(lt3.isBefore(lt4));      //prints: true

```

`LocalTime`类中还有许多其他有用的方法。如果您需要处理时间，请阅读该类及其他`java.time`包及其子包的 API。

# java.time.LocalDateTime

`LocalDateTime`类同时包含日期和时间，并且具有`LocalDate`类和`LocalTime`类拥有的所有方法，因此我们不会在此重复。我们只会展示如何创建`LocalDateTime`对象：

```java
System.out.println(LocalDateTime.now());  //2018-04-14T21:59:00.142804
ZoneId zoneId = ZoneId.of("Asia/Tokyo");
System.out.println(LocalDateTime.now(zoneId));  
                                   //prints: 2018-04-15T12:59:00.146038
LocalDateTime ldt1 =  LocalDateTime.parse("2020-02-23T20:23:12");
System.out.println(ldt1);                 //prints: 2020-02-23T20:23:12
DateTimeFormatter formatter = 
          DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
LocalDateTime ldt2 =  
       LocalDateTime.parse("23/02/2020 20:23:12", formatter);
System.out.println(ldt2);                 //prints: 2020-02-23T20:23:12
LocalDateTime ldt3 = LocalDateTime.of(2020, 2, 23, 20, 23, 12);
System.out.println(ldt3);                 //prints: 2020-02-23T20:23:12
LocalDateTime ldt4 =  
        LocalDateTime.of(2020, Month.FEBRUARY, 23, 20, 23, 12);
System.out.println(ldt4);                     //prints: 2020-02-23T20:23:12
LocalDate ld = LocalDate.of(2020, 2, 23);
LocalTime lt =  LocalTime.of(20, 23, 12);
LocalDateTime ldt5 = LocalDateTime.of(ld, lt);
System.out.println(ldt5);                     //prints: 2020-02-23T20:23:12

```

`LocalDateTime`类中还有许多其他有用的方法。如果你需要处理日期和时间，我们建议你阅读该类及其他`java.time`包及其子包的 API。

# `Period`和`Duration`

`java.time.Period`和`java.time.Duration`类的设计目的是包含一定的时间量：

+   `Period`对象包含以年、月和日为单位的时间量

+   `Duration`对象包含以小时、分、秒和纳秒为单位的时间量

以下代码演示了它们如何在`LocalDateTime`类中创建和使用，但是对于`Period`来说，相同的方法也存在于`LocalDate`类中，而对于`Duration`来说，相同的方法也存在于`LocalTime`类中：

```java
LocalDateTime ldt1 = LocalDateTime.parse("2020-02-23T20:23:12");
LocalDateTime ldt2 = ldt1.plus(Period.ofYears(2));
System.out.println(ldt2); //prints: 2022-02-23T20:23:12

//The following methods work the same way:
ldt.minus(Period.ofYears(2));
ldt.plus(Period.ofMonths(2));
ldt.minus(Period.ofMonths(2));
ldt.plus(Period.ofWeeks(2));
ldt.minus(Period.ofWeeks(2));
ldt.plus(Period.ofDays(2));
ldt.minus(Period.ofDays(2));

ldt.plus(Duration.ofHours(2));
ldt.minus(Duration.ofHours(2));
ldt.plus(Duration.ofMinutes(2));
ldt.minus(Duration.ofMinutes(2));
ldt.plus(Duration.ofMillis(2));
ldt.minus(Duration.ofMillis(2));
```

在以下代码中还演示了创建和使用`Period`对象的其他方法：

```java
LocalDate ld1 =  LocalDate.parse("2020-02-23");
LocalDate ld2 =  LocalDate.parse("2020-03-25");

Period period = Period.between(ld1, ld2);
System.out.println(period.getDays());       //prints: 2
System.out.println(period.getMonths());     //prints: 1
System.out.println(period.getYears());      //prints: 0
System.out.println(period.toTotalMonths()); //prints: 1

period = Period.between(ld2, ld1);
System.out.println(period.getDays());       //prints: -2
```

`Duration`对象可以类似地创建和使用：

```java
LocalTime lt1 =  LocalTime.parse("10:23:12");
LocalTime lt2 =  LocalTime.parse("20:23:14");
Duration duration = Duration.between(lt1, lt2);
System.out.println(duration.toDays());     //prints: 0
System.out.println(duration.toHours());    //prints: 10
System.out.println(duration.toMinutes());  //prints: 600
System.out.println(duration.toSeconds());  //prints: 36002
System.out.println(duration.getSeconds()); //prints: 36002
System.out.println(duration.toNanos());    //prints: 36002000000000
System.out.println(duration.getNano());    //prints: 0

```

`Period`和`Duration`类中还有许多其他有用的方法。如果您需要处理时间量，请阅读这些类及其他`java.time`包及其子包的 API。

# 管理随机数

生成一个真正的随机数是一个大问题，不属于本书。但是对于绝大多数实际目的来说，Java 提供的伪随机数生成器已经足够好了，这就是我们将在本节中讨论的内容。

在 Java 标准库中生成随机数有两种主要方式：

+   `java.lang.Math.random()`方法

+   `java.util.Random`类

还有 `java.security.SecureRandom` 类，它提供了一个加密强度很高的随机数生成器，但超出了入门课程的范围。

# 方法 `java.lang.Math.random()`

类 `Math` 的静态方法 `double random()` 返回一个大于或等于 `0.0` 且小于 `1.0` 的 `double` 类型值：

```java
for(int i =0; i < 3; i++){
    System.out.println(Math.random());
    //0.9350483840148613
    //0.0477353019234189
    //0.25784245516898985
}
```

在前面的注释中我们已经捕获了结果。但在实践中，更多时候需要的是某个范围内的随机整数。为了满足这样的需求，我们可以编写一个方法，例如，生成一个从 0（包含）到 10（不包含）的随机整数：

```java
int getInteger(int max){
    return (int)(Math.random() * max);
}
```

以下是前述代码的一次运行结果：

```java
for(int i =0; i < 3; i++){
    System.out.print(getInteger(10) + " "); //prints: 2 5 6
}
```

如你所见，它生成一个随机整数值，可以是以下 10 个数字之一：0、1、...、9。以下是使用相同方法的代码，并生成从 0（包含）到 100（不包含）的随机整数：

```java
for(int i =0; i < 3; i++){
    System.out.print(getInteger(100) + " "); //prints: 48 11 97
}
```

当你需要一个介于 100（包含）和 200（不包含）之间的随机数时，你可以直接将前述结果加上 100：

```java
for(int i =0; i < 3; i++){
    System.out.print(100 + getInteger(100) + " "); //prints: 114 101 127
}
```

将范围的两个端点包括在结果中可以通过四舍五入生成的 `double` 值来实现：

```java
int getIntegerRound(int max){
    return (int)Math.round(Math.random() * max);
}
```

当我们使用前述方法时，结果为：

```java
for(int i =0; i < 3; i++){
    System.out.print(100 + getIntegerRound(100) + " "); //179 147 200
}
```

如你所见，范围的上限（数字 200）包含在可能的结果集中。可以通过将所请求的上限范围加 1 来达到同样的效果：

```java
int getInteger2(int max){
    return (int)(Math.random() * (max + 1));
}
```

如果我们使用前述方法，我们可以得到以下结果：

```java
for(int i =0; i < 3; i++){
    System.out.print(100 + getInteger2(100) + " "); //167 200 132
}
```

但是，如果你查看 `Math.random()` 方法的源代码，你会看到它使用了 `java.util.Random` 类及其 `nextDouble()` 方法来生成一个随机的 double 值。因此，让我们看看如何直接使用 `java.util.Random` 类。

# 类 `java.util.Random`

类 `Random` 的方法 `doubles()` 生成一个大于或等于 `0.0` 且小于 `1.0` 的 `double` 类型值：

```java
Random random = new Random();
for(int i =0; i < 3; i++){
    System.out.print(random.nextDouble() + " "); 
    //prints: 0.8774928230544553 0.7822070124559267 0.09401796000707807 
}
```

我们可以像在上一节中使用 `Math.random()` 一样使用方法 `nextDouble()`。但是在需要某个范围内的随机整数值时，类还有其他方法可用，而无需创建自定义的 `getInteger()` 方法。例如，`nextInt()` 方法返回介于 `Integer.MIN_VALUE`（包含）和 `Integer.MAX_VALUE`（包含）之间的整数值：

```java
for(int i =0; i < 3; i++){
    System.out.print(random.nextInt() + " "); 
                        //prints: -2001537190 -1148252160 1999653777
}
```

并且带有参数的相同方法允许我们通过上限（不包含）限制返回值的范围：

```java
for(int i =0; i < 3; i++){
    System.out.print(random.nextInt(11) + " "); //prints: 4 6 2
}
```

该代码生成一个介于 0（包含）和 10（包含）之间的随机整数值。以下代码返回介于 11（包含）和 20（包含）之间的随机整数值：

```java
for(int i =0; i < 3; i++){
    System.out.print(11 + random.nextInt(10) + " "); //prints: 13 20 15
}
```

从范围中生成随机整数的另一种方法是使用方法 `ints(int count, int min, int max)` 返回的 `IntStream` 对象，其中 `count` 是所请求的值的数量，`min` 是最小值（包含），`max` 是最大值（不包含）：

```java
String result = random.ints(3, 0, 101)
        .mapToObj(String::valueOf)
        .collect(Collectors.joining(" ")); //prints: 30 48 52

```

此代码从 0（包含）到 100（包含）返回三个整数值。我们将在第十八章中更多地讨论流，*流和管道*。

# 练习 - Objects.equals() 结果

有三个类：

```java
public class A{}
public class B{}
public class Exercise {
    private A a;
    private B b;
    public Exercise(){
        System.out.println(java.util.Objects.equals(a, b));
    }
    public static void main(String... args){
        new Exercise();
    }
}
```

当我们运行`Exercise`类的`main()`方法时，会显示什么？ `错误`？ `假`？ `真`？

# 答案

显示将只显示一个值：`真`。原因是两个私有字段——`a`和`b`——都初始化为`null`。

# 总结

在本章中，我们向读者介绍了 Java 标准库和 Apache Commons 库中最受欢迎的实用程序和一些其他类。每个 Java 程序员都必须对它们的功能有很好的理解，才能成为有效的编码者。研究它们还有助于了解各种软件设计模式和解决方案，这些模式和解决方案具有指导意义，并且可以用作任何应用程序中最佳编码实践的模式。

在下一章中，我们将向读者演示如何编写能够操作数据库中数据的 Java 代码——插入、读取、更新和删除。它还将提供 SQL 和基本数据库操作的简要介绍。
