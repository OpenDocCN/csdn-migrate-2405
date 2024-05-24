# Java 12 编程学习手册（三）

> 原文：[Learn Java 12 Programming ](https://libgen.rs/book/index.php?md5=2D05FE7A99FD37AE2178F1DD99C27887)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 六、数据结构、泛型和流行工具

本章介绍了 Java 集合框架及其三个主要接口：`List`、`Set`和`Map`，包括泛型的讨论和演示。`equals()`和`hashCode()`方法也在 Java 集合的上下文中讨论。用于管理数组、对象和时间/日期值的工具类也有相应的专用部分。

本章将讨论以下主题：

*   `List`、`Set`、`Map`接口
*   集合工具
*   数组工具
*   对象工具
*   `java.time`包

# 列表、集合和映射接口

**Java 集合框架**由实现集合数据结构的类和接口组成。集合在这方面类似于数组，因为它们可以保存对对象的引用，并且可以作为一个组进行管理。不同之处在于，数组需要先定义它们的容量，然后才能使用，而集合可以根据需要自动增减大小。一种是添加或删除对集合的对象引用，集合相应地改变其大小，另一个区别是集合的元素不能是原始类型，如`short`、`int`或`double`。如果需要存储这样的类型值，那么元素必须是相应的包装器类型，例如`Short`、`Integer`或`Double`。

Java 集合支持存储和访问集合元素的各种算法：有序列表、唯一集、Java 中称为**映射**的字典、栈、**队列**，Java 集合框架的所有类和接口都属于 Java 类库的`java.util`包。`java.util`包包含以下内容：

*   对`Collection`接口进行扩展的接口有：`List`、`Set`、`Queue`等
*   实现前面列出的接口的类：`ArrayList`、`HashSet`、`Stack`、`LinkedList`和其他一些类
*   `Map`接口及其子接口：`ConcurrentMap`、`SortedMap`，以一对夫妇的名字命名
*   实现与`Map`相关的接口的类：`HashMap`、`HashTable`、`TreeMap`，这三个类是最常用的

要查看`java.util`包的所有类和接口，需要一本专门的书。因此，在本节中，我们将简要介绍三个主要接口：`List`、`Set`和`Map`——以及它们各自的一个实现类：`ArrayList`、`HashSet`和`HashMap`。我们从`List`和`Set`接口共享的方法开始。`List`和`Set`的主要区别在于`Set`不允许元素重复。另一个区别是`List`保留了元素的顺序，也允许对它们进行排序。

要标识集合中的元素，请使用`equals()`方法。为了提高性能，实现`Set`接口的类也经常使用`hashCode()`方法。它允许快速计算一个整数（称为**散列值**或**哈希码**），该整数在大多数时间（但并非总是）对每个元素都是唯一的。具有相同哈希值的元素被放置在相同的*桶*中。在确定集合中是否已经存在某个值时，检查内部哈希表并查看是否已经使用了这样的值就足够了。否则，新元素是唯一的。如果是，则可以将新元素与具有相同哈希值的每个元素进行比较（使用`equals()`方法）。这样的过程比逐个比较新元素和集合中的每个元素要快

这就是为什么我们经常看到类的名称有`Hash`前缀，表示类使用了哈希值，所以元素必须实现`hashCode()`方法，在实现时一定要确保`equals()`方法每次为两个对象返回`true`时，`hashCode()`方法返回的这两个对象的散列值也是相等的。否则，所有刚才描述的使用哈希值的算法都将不起作用。

最后，在讨论`java.util`接口之前，先谈一下泛型。

# 泛型

您最常在以下声明中看到它们：

```java
List<String> list = new ArrayList<String>();
Set<Integer> set = new HashSet<Integer>();
```

在前面的例子中，**泛型**是被尖括号包围的元素类型声明。如您所见，它们是多余的，因为它们在赋值语句的左侧和右侧重复。这就是为什么 Java 允许用空括号（`<>`）替换右侧的泛型，称为**菱形**：

```java
List<String> list = new ArrayList<>();
Set<Integer> set = new HashSet<>();
```

泛型通知编译器集合元素的预期类型。这样编译器就可以检查程序员试图添加到声明集合中的元素是否是兼容类型。例如：

```java
List<String> list = new ArrayList<>();
list.add("abc");
list.add(42);   //compilation error

```

它有助于避免运行时错误。它还向程序员提示可能对集合元素进行的操作（因为程序员编写代码时 IDE 会编译代码）。

我们还将看到其他类型的泛型：

*   `<? extends T>`表示`T`或`T`的子类型，其中`T`是用作集合泛型的类型
*   `<? super T>`表示`T`或其任何基（父）类，其中`T`是用作集合泛型的类型

那么，让我们从实现`List`或`Set`接口的类的对象的创建方式开始，或者换句话说，可以初始化`List`或`Set`类型的变量。为了演示这两个接口的方法，我们将使用两个类：`ArrayList`（实现`List`）和`HashSet`（实现`Set`）。

# 如何初始化列表和集合

由于 Java9，`List`或`Set`接口具有静态工厂方法`of()`，可用于初始化集合：

*   `of()`：返回空集合。
*   `of(E... e)`：返回一个集合，其中包含调用期间传入的元素数。它们可以以逗号分隔的列表或数组形式传递。

以下是几个例子：

```java
//Collection<String> coll = List.of("s1", null); //does not allow null
Collection<String> coll = List.of("s1", "s1", "s2");
//coll.add("s3");                        //does not allow add element
//coll.remove("s1");                     //does not allow remove element
((List<String>) coll).set(1, "s3");      //does not allow modify element
System.out.println(coll);                //prints: [s1, s1, s2]

//coll = Set.of("s3", "s3", "s4");       //does not allow duplicate
//coll = Set.of("s2", "s3", null);       //does not allow null
coll = Set.of("s3", "s4");
System.out.println(coll);                //prints: [s3, s4]

//coll.add("s5");                        //does not allow add element
//coll.remove("s2");                     //does not allow remove

```

正如人们所料，`Set`的工厂方法不允许重复，因此我们已经注释掉了该行（否则，前面的示例将停止在该行运行）。不太令人期待的是，不能有一个`null`元素，也不能在使用`of()`方法之一初始化集合之后添加/删除/修改集合的元素。这就是为什么我们注释掉了前面示例中的一些行。如果需要在集合初始化后添加元素，则必须使用构造器或其他创建可修改集合的工具对其进行初始化（稍后我们将看到一个`Arrays.asList()`的示例）。

接口`Collection`提供了两种向实现了`Collection`（`List`和`Set`的父接口）的对象添加元素的方法，如下所示：

*   `boolean add(E e)`：尝试将提供的元素`e`添加到集合中，成功返回`true`，无法完成返回`false`（例如`Set`中已经存在该元素）

*   `boolean addAll(Collection<? extends E> c)`：尝试将所提供集合中的所有元素添加到集合中；如果至少添加了一个元素，则返回`true`；如果无法将元素添加到集合中，则返回`false`（例如，当所提供集合`c`中的所有元素都已存在于`Set`中时）

以下是使用`add()`方法的示例：

```java
List<String> list1 = new ArrayList<>();
list1.add("s1");
list1.add("s1");
System.out.println(list1);     //prints: [s1, s1]

Set<String> set1 = new HashSet<>();
set1.add("s1");
set1.add("s1");
System.out.println(set1);      //prints: [s1]

```

下面是一个使用`addAll()`方法的例子：

```java
List<String> list1 = new ArrayList<>();
list1.add("s1");
list1.add("s1");
System.out.println(list1);      //prints: [s1, s1]

List<String> list2 = new ArrayList<>();
list2.addAll(list1);
System.out.println(list2);      //prints: [s1, s1]

Set<String> set = new HashSet<>();
set.addAll(list1);
System.out.println(set);        //prints: [s1]

```

以下是`add()`和`addAll()`方法的功能示例：

```java
List<String> list1 = new ArrayList<>();
list1.add("s1");
list1.add("s1");
System.out.println(list1);     //prints: [s1, s1]

List<String> list2 = new ArrayList<>();
list2.addAll(list1);
System.out.println(list2);      //prints: [s1, s1]

Set<String> set = new HashSet<>();
set.addAll(list1);
System.out.println(set);      //prints: [s1]

Set<String> set1 = new HashSet<>();
set1.add("s1");

Set<String> set2 = new HashSet<>();
set2.add("s1");
set2.add("s2");

System.out.println(set1.addAll(set2)); //prints: true
System.out.println(set1);              //prints: [s1, s2]

```

注意，在前面代码片段的最后一个示例中，`set1.addAll(set2)`方法返回`true`，尽管没有添加所有元素。要查看`add()`和`addAll()`方法返回`false`的情况，请看以下示例：

```java
Set<String> set = new HashSet<>();
System.out.println(set.add("s1"));   //prints: true
System.out.println(set.add("s1"));   //prints: false
System.out.println(set);             //prints: [s1]

Set<String> set1 = new HashSet<>();
set1.add("s1");
set1.add("s2");

Set<String> set2 = new HashSet<>();
set2.add("s1");
set2.add("s2");

System.out.println(set1.addAll(set2)); //prints: false
System.out.println(set1);              //prints: [s1, s2]

```

`ArrayList`和`HashSet`类还有接受集合的构造器：

```java
Collection<String> list1 = List.of("s1", "s1", "s2");
System.out.println(list1);      //prints: [s1, s1, s2]

List<String> list2 = new ArrayList<>(list1);
System.out.println(list2);      //prints: [s1, s1, s2]

Set<String> set = new HashSet<>(list1);
System.out.println(set);        //prints: [s1, s2]

List<String> list3 = new ArrayList<>(set);
System.out.println(list3);      //prints: [s1, s2]
```

现在，在我们了解了如何初始化集合之后，我们可以转向接口`List`和`Set`中的其他方法。

# `java.lang.Iterable`接口

`Collection`接口扩展了`java.lang.Iterable`接口，这意味着那些直接或不直接实现`Collection`接口的类也实现了`java.lang.Iterable`接口。`Iterable`接口只有三种方式：

*   `Iterator<T> iterator()`：返回实现接口`java.util.Iterator`的类的对象，允许集合在`FOR`语句中使用，例如：

```java
Iterable<String> list = List.of("s1", "s2", "s3");
System.out.println(list);       //prints: [s1, s2, s3]

for(String e: list){
    System.out.print(e + " ");  //prints: s1 s2 s3
}
```

*   `default void forEach (Consumer<? super T> function)`：将提供的`Consumer`类型的函数应用于集合的每个元素，直到所有元素都处理完毕或函数抛出异常为止。什么是函数，我们将在第 13 章、“函数编程”中讨论；现在我们只提供一个例子：

```java
Iterable<String> list = List.of("s1", "s2", "s3");
System.out.println(list);                     //prints: [s1, s2, s3]
list.forEach(e -> System.out.print(e + " ")); //prints: s1 s2 s3
```

*   `default Spliterator<T> splititerator()`：返回实现`java.util.Spliterator`接口的类的对象，主要用于实现允许并行处理的方法，不在本书范围内

# 集合接口

如前所述，`List`和`Set`接口扩展了`Collection`接口，这意味着`Collection`接口的所有方法都被`List`和`Set`继承。这些方法如下：

*   `boolean add(E e)`：尝试向集合添加元素
*   `boolean addAll(Collection<? extends E> c)`：尝试添加所提供集合中的所有元素
*   `boolean equals(Object o)`：将集合与提供的对象`o`进行比较；如果提供的对象不是集合，则返回`false`；否则将集合的组成与提供的集合的组成进行比较（作为对象`o`）；如果是`List`，它还比较了元素的顺序；让我们用几个例子来说明：

```java
Collection<String> list1 = List.of("s1", "s2", "s3");
System.out.println(list1);       //prints: [s1, s2, s3]

Collection<String> list2 = List.of("s1", "s2", "s3");
System.out.println(list2);       //prints: [s1, s2, s3]

System.out.println(list1.equals(list2));  //prints: true

Collection<String> list3 = List.of("s2", "s1", "s3");
System.out.println(list3);       //prints: [s2, s1, s3]

System.out.println(list1.equals(list3));  //prints: false

Collection<String> set1 = Set.of("s1", "s2", "s3");
System.out.println(set1);   //prints: [s2, s3, s1] or different order

Collection<String> set2 = Set.of("s2", "s1", "s3");
System.out.println(set2);   //prints: [s2, s1, s3] or different order

System.out.println(set1.equals(set2));  //prints: true

Collection<String> set3 = Set.of("s4", "s1", "s3");
System.out.println(set3);   //prints: [s4, s1, s3] or different order

System.out.println(set1.equals(set3));  //prints: false

```

*   `int hashCode()`：返回集合的哈希值，用于集合是需要`hashCode()`方法实现的集合元素的情况
*   `boolean isEmpty()`：如果集合中没有任何元素，则返回`true`
*   `int size()`：返回集合中元素的计数；当`isEmpty()`方法返回`true`时，此方法返回`0`
*   ` void clear()`：删除集合中的所有元素；调用此方法后，`isEmpty()`方法返回`true`，`size()`方法返回`0`
*   `boolean contains(Object o)`：如果集合包含提供的对象`o`，则返回`true`；要使此方法正常工作，集合中的每个元素和提供的对象必须实现`equals()`方法，如果是`Set`，则需要实现`hashCode()`方法
*   `boolean containsAll(Collection<?> c)`：如果集合包含所提供集合中的所有元素，则返回`true`，要使此方法正常工作，集合中的每个元素和所提供集合中的每个元素必须实现`equals()`方法，如果是`Set`，则应实现`hashCode()`方法
*   `boolean remove(Object o)`：尝试从此集合中移除指定元素，如果存在则返回`true`；要使此方法正常工作，集合的每个元素和提供的对象必须实现方法`equals()`，如果是`Set`，则应实现`hashCode()`方法
*   `boolean removeAll(Collection<?> c)`：尝试从集合中移除所提供集合的所有元素；与`addAll()`方法类似，如果至少移除了一个元素，则返回`true`，否则返回`false`，以便该方法正常工作，集合的每个元素和所提供集合的每个元素必须实现`equals()`方法，在`Set`的情况下，应该实现`hashCode()`方法
*   `default boolean removeIf(Predicate<? super E> filter)`：尝试从集合中移除满足给定谓词的所有元素；我们将在第 13 章、“函数式编程”中描述的函数；如果至少移除了一个元素，则返回`true`

*   `boolean retainAll(Collection<?> c)`：试图在集合中只保留所提供集合中包含的元素；与`addAll()`方法类似，如果至少保留了一个元素，则返回`true`，否则返回`false`，以便该方法正常工作，集合的每个元素和所提供集合的每个元素必须实现`equals()`方法，在`Set`的情况下，应该实现`hashCode()`方法
*   `Object[] toArray()`、`T[] toArray(T[] a)`：将集合转换成数组
*   `default T[] toArray(IntFunction<T[]> generator)`：使用提供的函数将集合转换为数组；我们将在第 13 章、“函数式编程”中解释函数
*   `default Stream<E> stream()`：返回`Stream`对象（我们在第 14 章、“Java 标准流”中谈到流）
*   `default Stream<E> parallelStream()`：返回一个可能并行的`Stream`对象（我们在第 14 章“Java 标准流”中讨论流）。

# 列表接口

`List`接口有几个不属于其父接口的其他方法：

*   静态工厂`of()`方法“如何初始化列表和集合”小节中描述的方法
*   `void add(int index, E element)`：在列表中提供的位置插入提供的元素
*   `static List<E> copyOf(Collection<E> coll)`：返回一个不可修改的`List`，其中包含给定`Collection`的元素并保留它们的顺序；下面是演示此方法功能的代码：

```java
Collection<String> list = List.of("s1", "s2", "s3");
System.out.println(list);         //prints: [s1, s2, s3]

List<String> list1 = List.copyOf(list);
//list1.add("s4");                //run-time error
//list1.set(1, "s5");             //run-time error
//list1.remove("s1");             //run-time error

Set<String> set = new HashSet<>();
System.out.println(set.add("s1"));
System.out.println(set);          //prints: [s1]

Set<String> set1 = Set.copyOf(set);
//set1.add("s2");                 //run-time error
//set1.remove("s1");              //run-time error

Set<String> set2 = Set.copyOf(list);
System.out.println(set2);         //prints: [s1, s2, s3] 

```

*   `E get(int index)`：返回列表中指定位置的元素
*   `List<E> subList(int fromIndex, int toIndex)`：在`fromIndex`（包含）和`toIndex`（排除）之间提取子列表
*   `int indexOf(Object o)`：返回列表中指定元素的第一个索引（位置）；列表中的第一个元素有一个索引（位置）`0`
*   `int lastIndexOf(Object o)`：返回列表中指定元素的最后一个索引（位置）；列表中最后一个元素的索引（位置）等于`list.size() - 1`
*   `E remove(int index)`：删除列表中指定位置的元素；返回删除的元素
*   `E set(int index, E element)`：替换列表中指定位置的元素，返回被替换的元素
*   `default void replaceAll(UnaryOperator<E> operator)`：通过将提供的函数应用于每个元素来转换列表，`UnaryOperator`函数将在第 13 章、“函数式编程”中描述
*   `ListIterator<E> listIterator()`：返回允许向后遍历列表的`ListIterator`对象
*   `ListIterator<E> listIterator(int index)`：返回一个`ListIterator`对象，该对象允许向后遍历子列表（从提供的位置开始）；例如：

```java
List<String> list = List.of("s1", "s2", "s3");
ListIterator<String> li = list.listIterator();
while(li.hasNext()){
    System.out.print(li.next() + " ");         //prints: s1 s2 s3
}
while(li.hasPrevious()){
    System.out.print(li.previous() + " ");     //prints: s3 s2 s1
}
ListIterator<String> li1 = list.listIterator(1);
while(li1.hasNext()){
    System.out.print(li1.next() + " ");        //prints: s2 s3
}
ListIterator<String> li2 = list.listIterator(1);
while(li2.hasPrevious()){
    System.out.print(li2.previous() + " ");    //prints: s1
}

```

*   `default void sort(Comparator<? super E> c)`：根据提供的`Comparator`生成的顺序对列表进行排序，例如：

```java
List<String> list = new ArrayList<>();
list.add("S2");
list.add("s3");
list.add("s1");
System.out.println(list);                //prints: [S2, s3, s1]

list.sort(String.CASE_INSENSITIVE_ORDER);
System.out.println(list);                //prints: [s1, S2, s3]

//list.add(null);                 //causes NullPointerException
list.sort(Comparator.naturalOrder());
System.out.println(list);               //prints: [S2, s1, s3]

list.sort(Comparator.reverseOrder());
System.out.println(list);               //prints: [s3, s1, S2]

list.add(null);
list.sort(Comparator.nullsFirst(Comparator.naturalOrder()));
System.out.println(list);              //prints: [null, S2, s1, s3]

list.sort(Comparator.nullsLast(Comparator.naturalOrder()));
System.out.println(list);              //prints: [S2, s1, s3, null]

Comparator<String> comparator = (s1, s2) -> 
 s1 == null ? -1 : s1.compareTo(s2);
list.sort(comparator);
System.out.println(list);              //prints: [null, S2, s1, s3]

```

对列表排序主要有两种方法：

*   使用`Comparable`接口实现（称为**自然顺序**）
*   使用`Comparator`接口实现

`Comparable`接口只有`compareTo()`方法。在前面的例子中，我们已经在`String`类中的`Comparable`接口实现的基础上实现了`Comparator`接口。如您所见，此实现提供了与`Comparator.nullsFirst(Comparator.naturalOrder())`相同的排序顺序，这种实现方式称为**函数式编程**，我们将在第 13 章“函数式编程”中详细讨论。

 *# 接口集

`Set`接口有以下不属于其父接口的方法：

*   静态`of()`工厂方法，在“如何初始化列表和集合”小节中描述
*   `static Set<E> copyOf(Collection<E> coll)`方法：返回一个包含给定`Collection`元素的不可修改的`Set`，其工作方式与“接口列表”部分描述的`static <E> List<E> copyOf(Collection<E> coll)`方法相同

# 映射接口

`Map`接口有很多类似`List`、`Set`的方法：

*   `int size()`
*   `void clear()`
*   `int hashCode()`
*   `boolean isEmpty()`
*   `boolean equals(Object o)`
*   `default void forEach(BiConsumer<K,V> action)`
*   静态工厂方法：`of()`、`of(K k, V v)`、`of(K k1, V v1, K k2, V v2)`等多种方法

然而，`Map`接口并不扩展`Iterable`、`Collection`或任何其他接口。通过**键***可以存储**值**。*每个键都是唯一的，而同一个映射上不同的键可以存储几个相等的值。键和值的组合构成了一个`Entry`，是`Map`的内部接口。值和关键对象都必须实现`equals()`方法，关键对象也必须实现`hashCode()`方法

`Map`接口的很多方法与`List`和`Set`接口的签名和功能完全相同，这里不再赘述，我们只介绍`Map`的具体方法：

*   `V get(Object key)`：按提供的键取值，如果没有该键返回`null`
*   `Set<K> keySet()`：从映射中检索所有键
*   `Collection<V> values()`：从映射中检索所有值
*   `boolean containsKey(Object key)`：如果映射中存在提供的键，则返回`true`
*   `boolean containsValue(Object value)`：如果提供的值存在于映射中，则返回`true`
*   `V put(K key, V value)`：将值及其键添加到映射中；返回使用相同键存储的上一个值
*   `void putAll(Map<K,V> m)`：从提供的映射中复制所有键值对
*   `default V putIfAbsent(K key, V value)`：存储所提供的值，如果映射尚未使用该键，则映射到所提供的键；将映射到所提供键的值返回到现有或新的值
*   `V remove(Object key)`：从映射中删除键和值；如果没有键或值为`null`，则返回值或`null`
*   `default boolean remove(Object key, Object value)`：如果映射中存在键值对，则从映射中移除键值对
*   `default V replace(K key, V value)`：如果提供的键当前映射到提供的值，则替换该值；如果被替换，则返回旧值；否则返回`null`
*   `default boolean replace(K key, V oldValue, V newValue)`：如果提供的键当前映射到`oldValue`，则用提供的`newValue`替换值`oldValue`；如果替换了`oldValue`，则返回`true`，否则返回`false`
*   `default void replaceAll(BiFunction<K,V,V> function)`：将提供的函数应用于映射中的每个键值对，并用结果替换，如果不可能，则抛出异常
*   `Set<Map.Entry<K,V>> entrySet()`：返回一组所有键值对作为`Map.Entry`的对象
*   `default V getOrDefault(Object key, V defaultValue)`：返回映射到提供键的值，如果映射没有提供键，则返回`defaultValue`

*   `static Map.Entry<K,V> entry(K key, V value)`：返回一个不可修改的`Map.Entry`对象，其中包含提供的`key`和`value`
*   `static Map<K,V> copy(Map<K,V> map):`将提供的`Map`转换为不可修改的`Map`

以下`Map`方法对于本书的范围来说太复杂了，所以我们只是为了完整起见才提到它们。它们允许组合或计算多个值，并将它们聚集在`Map`中的单个现有值中，或创建一个新值：

*   `default V merge(K key, V value, BiFunction<V,V,V> remappingFunction)`：如果提供的键值对存在且值不是`null`，则提供的函数用于计算新值；如果新计算的值是`null`，则删除键值对；如果提供的键值对不存在或值是`null`，则提供的非空值替换当前值；此方法可用于聚合多个值；例如，可用于连接字符串值：`map.merge(key, value, String::concat)`；我们将在第 13 章、“函数式编程”中解释`String::concat`的含义
*   `default V compute(K key, BiFunction<K,V,V> remappingFunction)`：使用提供的函数计算新值
*   `default V computeIfAbsent(K key, Function<K,V> mappingFunction)`：仅当提供的键尚未与值关联或值为`null`时，才使用提供的函数计算新值
*   `default V computeIfPresent(K key, BiFunction<K,V,V> remappingFunction)`：仅当提供的键已经与值关联并且该值不是`null`时，才使用提供的函数计算新值

最后一组*计算*和*合并*方法很少使用。到目前为止最流行的是`V put(K key, V value)`和`V get(Object key)`方法，它们允许使用主要的`Map`功能来存储键值对并使用键检索值。`Set<K> keySet()`方法通常用于迭代映射的键值对，尽管`entrySet()`方法似乎是一种更自然的方法。举个例子：

```java
Map<Integer, String> map = Map.of(1, "s1", 2, "s2", 3, "s3");

for(Integer key: map.keySet()){
    System.out.print(key + ", " + map.get(key) + ", ");  
                                   //prints: 3, s3, 2, s2, 1, s1,
}
for(Map.Entry e: map.entrySet()){
    System.out.print(e.getKey() + ", " + e.getValue() + ", "); 
                                   //prints: 2, s2, 3, s3, 1, s1,
}
```

前面代码示例中的第一个`for`循环使用更广泛的方法通过迭代键来访问映射的键对值。第二个`for`循环遍历条目集，我们认为这是一种更自然的方法。请注意，打印出来的值的顺序与我们在映射中的顺序不同。这是因为，自 Java9 以来，不可修改的集合（即`of()`工厂方法产生的集合）增加了`Set`元素顺序的随机化。它改变了不同代码执行之间元素的顺序。这样的设计是为了确保程序员不依赖于`Set`元素的特定顺序，而这对于一个集合是不保证的

# 不可修改的集合

请注意，`of()`工厂方法生成的集合在 Java9 中被称为**不可变**，在 Java10 中被称为**不可修改**。这是因为不可变意味着不能更改其中的任何内容，而实际上，如果集合元素是可修改的对象，则可以更改它们。例如，让我们构建一个`Person1`类的对象集合，如下所示：

```java
class Person1 {
    private int age;
    private String name;
    public Person1(int age, String name) {
        this.age = age;
        this.name = name == null ? "" : name;
    }
    public void setName(String name){ this.name = name; }
    @Override
    public String toString() {
        return "Person{age=" + age +
                ", name=" + name + "}";
    }
}
```

为简单起见，我们将创建一个只包含一个元素的列表，然后尝试修改该元素：

```java
Person1 p1 = new Person1(45, "Bill");
List<Person1> list = List.of(p1);
//list.add(new Person1(22, "Bob")); //UnsupportedOperationException
System.out.println(list);        //prints: [Person{age=45, name=Bill}]
p1.setName("Kelly");       
System.out.println(list);        //prints: [Person{age=45, name=Kelly}]

```

如您所见，尽管无法将元素添加到由`of()`工厂方法创建的列表中，但是如果对元素的引用存在于列表之外，则仍然可以修改其元素。

# 集合工具

有两个类具有处理集合的静态方法，它们非常流行并且非常有用：

*   `java.util.Collections`
*   `org.apache.commons.collections4.CollectionUtils`

这些方法是静态的，这意味着它们不依赖于对象状态，因此它们也被称为**无状态方法**或**工具方法**。

# `java.util.Collections`类

`Collections`类中有许多方法可以管理集合、分析、排序和比较它们。其中有 70 多个，所以我们没有机会谈论所有这些问题。相反，我们将研究主流应用开发人员最常使用的：

*   `static copy(List<T> dest, List<T> src)`：将`src`列表中的元素复制到`dest`列表中，并保留元素的顺序及其在列表中的位置；目的地`dest`列表大小必须等于或大于`src`列表大小，否则会引发运行时异常；此方法用法示例如下：

```java
List<String> list1 = Arrays.asList("s1","s2");
List<String> list2 = Arrays.asList("s3", "s4", "s5");
Collections.copy(list2, list1);
System.out.println(list2);    //prints: [s1, s2, s5]

```

*   `static void sort(List<T> list)`：根据每个元素实现的`compareTo(T)`方法对列表进行排序（称为**自然排序**）；只接受具有实现`Comparable`接口的元素的列表（需要实现`compareTo(T)`方法）；在下面的示例中，我们使用`List<String>`因为类`String`机具`Comparable`：

```java
//List<String> list = List.of("a", "X", "10", "20", "1", "2");
List<String> list = Arrays.asList("a", "X", "10", "20", "1", "2");
Collections.sort(list);
System.out.println(list);         //prints: [1, 10, 2, 20, X, a]

```

请注意，我们不能使用`List.of()`方法创建列表，因为该列表是不可修改的，并且其顺序不能更改。另外，看看结果的顺序：数字排在第一位，然后是大写字母，然后是小写字母。这是因为`String`类中的`compareTo()`方法使用字符的代码点来建立顺序。下面是演示它的代码：

```java
List<String> list = Arrays.asList("a", "X", "10", "20", "1", "2");
Collections.sort(list);
System.out.println(list);     //prints: [1, 10, 2, 20, X, a]
list.forEach(s -> {
    for(int i = 0; i < s.length(); i++){
        System.out.print(" " + Character.codePointAt(s, i));
    }
    if(!s.equals("a")) {
        System.out.print(",");   //prints: 49, 49 48, 50, 50 48, 88, 97
    }
});

```

如您所见，顺序是由组成字符串的字符的代码点的值定义的。

*   `static void sort(List<T> list, Comparator<T> comparator)`：根据提供的`Comparator`对象对列表进行排序，不管列表元素是否实现了`Comparable`接口；例如，让我们对一个由`Person`类的对象组成的列表进行排序：

```java
class Person  {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name == null ? "" : name;
    }
    public int getAge() { return this.age; }
    public String getName() { return this.name; }
    @Override
    public String toString() {
        return "Person{name=" + name + ", age=" + age + "}";
    }
}
```

这里有一个`Comparator`类对`Person`对象列表进行排序：

```java
class ComparePersons implements Comparator<Person> {
    public int compare(Person p1, Person p2){
        int result = p1.getName().compareTo(p2.getName());
        if (result != 0) { return result; }
        return p1.age - p2.getAge();
    }
}
```

现在我们可以使用`Person`和`ComparePersons`类，如下所示：

```java
List<Person> persons = Arrays.asList(new Person(23, "Jack"),
        new Person(30, "Bob"), new Person(15, "Bob"));
Collections.sort(persons, new ComparePersons());
System.out.println(persons);    //prints: [Person{name=Bob, age=15}, 
                                           Person{name=Bob, age=30}, 
                                           Person{name=Jack, age=23}]
```

正如我们已经提到的，`Collections`类中还有更多的工具，因此我们建议您至少查看一次它的文档并查看所有的功能。

# ApacheCommons `CollectionUtils`类 

ApacheCommons 项目中的`org.apache.commons.collections4.CollectionUtils`类包含静态无状态方法，这些方法是对`java.util.Collections`类方法的补充，它们有助于搜索、处理和比较 Java 集合。

要使用此类，您需要向 Maven`pom.xml`配置文件添加以下依赖项：

```java
 <dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.1</version>
 </dependency>
```

这个类中有很多方法，随着时间的推移，可能会添加更多的方法。这些工具是在`Collections`方法之外创建的，因此它们更复杂、更细致，不适合本书的范围。为了让您了解`CollectionUtils`类中可用的方法，以下是根据功能分组的方法的简短说明：

*   从集合中检索元素的方法
*   向集合中添加元素或元素组的方法
*   将`Iterable`元素合并到集合中的方法
*   带或不带条件移除或保留元素的方法
*   比较两个集合的方法
*   转换集合的方法
*   从集合中选择并过滤集合的方法
*   生成两个集合的并集、交集或差集的方法
*   创建不可变的空集合的方法
*   检查集合大小和空性的方法
*   反转数组的方法

最后一个方法可能属于处理数组的工具类。这就是我们现在要讨论的。

# 数组工具

有两个类具有处理集合的静态方法，它们非常流行并且非常有用：

*   `java.util.Arrays`
*   `org.apache.commons.lang3.ArrayUtils`

我们将简要回顾其中的每一项。

# `java.util.Arrays`类

我们已经用过几次了。它是数组管理的主要工具类。这个工具类过去非常流行，因为有`asList(T...a)`方法。它是创建和初始化集合的最简洁的方法：

```java
List<String> list = Arrays.asList("s0", "s1");
Set<String> set = new HashSet<>(Arrays.asList("s0", "s1");
```

它仍然是一种流行的创建可修改列表的方法。我们也使用它。但是，在引入了一个`List.of()`工厂方法之后，`Arrays`类的流行性大大下降。

不过，如果您需要管理数组，`Arrays`类可能会有很大帮助。它包含 160 多种方法。它们中的大多数都重载了不同的参数和数组类型。如果我们按方法名对它们进行分组，将有 21 个组。如果我们进一步按功能对它们进行分组，那么只有以下 10 组将涵盖所有的`Arrays`类功能：

*   `asList()`：根据提供的数组或逗号分隔的参数列表创建`ArrayList`对象
*   `binarySearch()`：搜索一个数组或只搜索它的指定部分（按索引的范围）
*   `compare()`、`mismatch()`、`equals()`和`deepEquals()`：比较两个数组或它们的部分（根据索引的范围）
*   `copyOf()`、`copyOfRange()`：复制所有数组或只复制其中指定的（按索引范围）部分
*   `hashcode()`、`deepHashCode()`：根据提供的数组生成哈希码值
*   `toString()`和`deepToString()`：创建数组的`String`表示
*   `fill()`、`setAll()`、`parallelPrefix()`、`parallelSetAll()`：数组中每个元素的设定值（固定的或由提供的函数生成的）或由索引范围指定的值
*   `sort()`和`parallelSort()`：对数组中的元素进行排序或只对数组的一部分进行排序（由索引的范围指定）
*   `splititerator()`：返回`Splititerator`对象，对数组或数组的一部分进行并行处理（由索引的范围指定）
*   `stream()`：生成数组元素流或其中的一部分（由索引的范围指定）；参见第 14 章、“Java 标准流”

所有这些方法都是有用的，但我们想提请您注意`equals(a1, a2)`方法和`deepEquals(a1, a2)`。它们对于数组比较特别有用，因为数组对象不能实现`equals()`自定义方法，而是使用`Object`类的实现（只比较引用）。`equals(a1, a2)`和`deepEquals(a1, a2)`方法不仅允许比较`a1`和`a2`引用，还可以使用`equals()`方法比较元素。以下是演示这些方法如何工作的代码示例：

```java
String[] arr1 = {"s1", "s2"};
String[] arr2 = {"s1", "s2"};
System.out.println(arr1.equals(arr2));             //prints: false
System.out.println(Arrays.equals(arr1, arr2));     //prints: true
System.out.println(Arrays.deepEquals(arr1, arr2)); //prints: true

String[][] arr3 = {{"s1", "s2"}};
String[][] arr4 = {{"s1", "s2"}};
System.out.println(arr3.equals(arr4));             //prints: false
System.out.println(Arrays.equals(arr3, arr4));     //prints: false
System.out.println(Arrays.deepEquals(arr3, arr4)); //prints: true

```

如您所见，`Arrays.deepEquals()`每次比较两个相等的数组时，当一个数组的每个元素等于另一个数组在同一位置的元素时，返回`true`，而`Arrays.equals()`方法返回相同的结果，但只对一维数组。

# ApacheCommons `ArrayUtils`类

`org.apache.commons.lang3.ArrayUtils`类是对`java.util.Arrays`类的补充，它向数组管理工具箱添加了新方法，并且在可能抛出`NullPointerException`的情况下能够处理`null`。要使用这个类，您需要向 Maven`pom.xml`配置文件添加以下依赖项：

```java
<dependency>
   <groupId>org.apache.commons</groupId>
   <artifactId>commons-lang3</artifactId>
   <version>3.8.1</version>
</dependency>
```

`ArrayUtils`类有大约 300 个重载方法，可以收集在以下 12 个组中：

*   `add()`、`addAll()`和`insert()`：向数组添加元素
*   `clone()`：克隆数组，类似`Arrays`类的`copyOf()`方法和`java.lang.System`的`arraycopy()`方法
*   `getLength()`：当数组本身为`null`时，返回数组长度或`0`
*   `hashCode()`：计算数组的哈希值，包括嵌套数组
*   `contains()`、`indexOf()`、`lastIndexOf()`：搜索数组
*   `isSorted()`、`isEmpty`、`isNotEmpty()`：检查数组并处理`null`
*   `isSameLength()`和`isSameType()`：比较数组
*   `nullToEmpty()`：将`null`数组转换为空数组
*   `remove()`、`removeAll()`、`removeElement()`、`removeElements()`、`removeAllOccurances()`：删除部分或全部元素
*   `reverse()`、`shift()`、`shuffle()`、`swap()`：改变数组元素的顺序
*   `subarray()`：根据索引的范围提取数组的一部分
*   `toMap()`、`toObject()`、`toPrimitive()`、`toString()`、`toStringArray()`：将数组转换为其他类型，并处理`null`值

# 对象工具

本节中描述的两个工具是：

*   `java.util.Objects`
*   `org.apache.commons.lang3.ObjectUtils`

它们在类创建期间特别有用，因此我们将主要关注与此任务相关的方法。

# `java.util.Objects`类

`Objects`类只有 17 个方法都是静态的。在将它们应用于`Person`类时，我们来看看其中的一些方法，假设这个类是集合的一个元素，这意味着它必须实现`equals()`和`hashCode()`方法：

```java
class Person {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge(){ return this.age; }
    public String getName(){ return this.name; }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if(!(o instanceof Person)) return false;
        Person person = (Person)o;
        return age == person.getAge() &&
                Objects.equals(name, person.getName()); 
    }
    @Override
    public int hashCode(){
        return Objects.hash(age, name);
    }
}
```

注意，我们没有检查`null`的属性`name`，因为当任何参数为`null`时`Object.equals()`不会中断。它只是做比较对象的工作。如果其中只有一个是`null`，则返回`false`。如果两者都为空，则返回`true`。

使用`Object.equals()`是实现`equals()`方法的一种安全方法，但是如果需要比较可能是数组的对象，最好使用`Objects.deepEquals()`方法，因为它不仅像`Object.equals()`方法那样处理`null`，而且还比较所有数组元素的值，即使数组是多维的：

```java
String[][] x1 = {{"a","b"},{"x","y"}};
String[][] x2 = {{"a","b"},{"x","y"}};
String[][] y =  {{"a","b"},{"y","y"}};

System.out.println(Objects.equals(x1, x2));      //prints: false
System.out.println(Objects.equals(x1, y));       //prints: false
System.out.println(Objects.deepEquals(x1, x2));  //prints: true
System.out.println(Objects.deepEquals(x1, y));   //prints: false

```

`Objects.hash()`方法也处理空值。需要记住的一点是，`equals()`方法中比较的属性列表必须与作为参数传入`Objects.hash()`的属性列表相匹配。否则，两个相等的`Person`对象将具有不同的哈希值，这使得基于哈希的集合无法正常工作。

另一件值得注意的事情是，还有另一个与哈希相关的`Objects.hashCode()`方法，它只接受一个参数。但是它产生的值并不等于只有一个参数的`Objects.hash()`产生的值。例如：

```java
System.out.println(Objects.hash(42) == Objects.hashCode(42));  
                                                        //prints: false
System.out.println(Objects.hash("abc") == Objects.hashCode("abc"));  
                                                        //prints: false

```

为避免此警告，请始终使用`Objects.hash()`。

另一个潜在的混淆表现在以下代码中：

```java
System.out.println(Objects.hash(null));      //prints: 0
System.out.println(Objects.hashCode(null));  //prints: 0
System.out.println(Objects.hash(0));         //prints: 31
System.out.println(Objects.hashCode(0));     //prints: 0

```

如您所见，`Objects.hashCode()`方法为`null`和`0`生成相同的散列值，这对于一些基于散列值的算法来说是有问题的。

`static <T> int compare (T a, T b, Comparator<T> c)`是另一种流行的方法，它返回`0`（如果参数相等）或`c.compare(a, b)`的结果。它对于实现`Comparable`接口（为自定义对象排序建立自然顺序）非常有用。例如：

```java
class Person implements Comparable<Person> {
    private int age;
    private String name;
    public Person(int age, String name) {
        this.age = age;
        this.name = name;
    }
    public int getAge(){ return this.age; }
    public String getName(){ return this.name; }
    @Override
    public int compareTo(Person p){
        int result = Objects.compare(name, p.getName(),
                                         Comparator.naturalOrder());
        if (result != 0) { 
           return result;
        }
        return Objects.compare(age, p.getAge(),
                                          Comparator.naturalOrder());
    }
}
```

这样，您可以通过设置`Comparator.reverseOrder()`值或添加`Comparator.nullFirst()`或`Comparator.nullLast()`来轻松更改排序算法。

此外，我们在上一节中使用的`Comparator`实现可以通过使用`Objects.compare()`变得更加灵活：

```java
class ComparePersons implements Comparator<Person> {
    public int compare(Person p1, Person p2){
        int result = Objects.compare(p1.getName(), p2.getName(),
                                         Comparator.naturalOrder());
        if (result != 0) { 
           return result;
        }
        return Objects.compare(p1.getAge(), p2.getAge(),
                                          Comparator.naturalOrder());
    }
}
```

最后，我们要讨论的`Objects`类的最后两个方法是生成对象的字符串表示的方法。当您需要对对象调用`toString()`方法，但不确定对象引用是否为`null`时，它们会很方便。例如：

```java
List<String> list = Arrays.asList("s1", null);
for(String e: list){
    //String s = e.toString();  //NullPointerException
}
```

在前面的例子中，我们知道每个元素的确切值。但是想象一下，列表作为参数传递到方法中。然后我们被迫写下如下内容：

```java
void someMethod(List<String> list){
    for(String e: list){
        String s = e == null ? "null" : e.toString();
    }
```

看来这没什么大不了的。但是在编写了十几次这样的代码之后，程序员自然会想到一种实用方法来完成所有这些，也就是说，当`Objects`类的以下两种方法有帮助时：

*   `static String toString(Object o)`：当参数不是`null`时返回调用`toString()`的结果，当参数值为`null`时返回`null`

*   `static String toString(Object o, String nullDefault)`：当第一个参数不是`null`时，返回调用第一个参数`toString()`的结果；当第一个参数值是`null`时，返回第二个参数值`nullDefault`

下面的代码演示了这两种方法：

```java
List<String> list = Arrays.asList("s1", null);
for(String e: list){
    String s = Objects.toString(e);
    System.out.print(s + " ");          //prints: s1 null
}
for(String e: list){
    String s = Objects.toString(e, "element was null");
    System.out.print(s + " ");          //prints: s1 element was null
}
```

在撰写本文时，`Objects`类有 17 种方法。我们建议您熟悉它们，以避免在已经存在相同工具的情况下编写自己的工具

# ApacheCommons `ObjectUtils`类

上一节的最后一条语句适用于 ApacheCommons 库的`org.apache.commons.lang3.ObjectUtils`类，它补充了上一节中描述的`java.util.Objects`类的方法。本书的范围和分配的大小不允许对`ObjectUtils`类的所有方法进行详细的回顾，因此我们将按相关功能分组对它们进行简要的描述。要使用这个类，您需要在 Maven`pom.xml`配置文件中添加以下依赖项：

```java
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-lang3</artifactId>
    <version>3.8.1</version>
</dependency>
```

`ObjectUtils`类的所有方法可分为七组：

*   对象克隆方法
*   比较两个对象的方法
*   比较两个对象是否相等的`notEqual()`方法，其中一个或两个对象可以是`null`

*   几个`identityToString()`方法生成所提供对象的`String`表示，就像由`toString()`生成一样，这是`Object`基类的默认方法，并且可选地将其附加到另一个对象
*   分析`null`的对象数组的`allNotNull()`和`anyNotNull()`方法
*   `firstNonNull()`和`defaultIfNull()`方法，它们分析一个对象数组并返回第一个非`null`对象或默认值
*   `max()`、`min()`、`median()`和`mode()`方法，它们分析一个对象数组并返回其中一个对应于方法名称的对象

# `java.time`包

`java.time`包及其子包中有许多类。它们是作为处理日期和时间的其他（旧的包）的替代品引入的。新类是线程安全的（因此，更适合多线程处理），同样重要的是，它们的设计更加一致，更易于理解。此外，新的实现在日期和时间格式上遵循了**国际标准组织**（**ISO**），但也允许使用任何其他自定义格式。

我们将描述主要的五个类，并演示如何使用它们：

*   `java.time.LocalDate`
*   `java.time.LocalTime`
*   `java.time.LocalDateTime`
*   `java.time.Period`
*   `java.time.Duration`

所有这些，以及`java.time`包的其他类，以及它的子包都有丰富的功能，涵盖了所有的实际案例。但我们不打算讨论所有这些问题；我们将只介绍基本知识和最流行的用例。

# `LocalDate`类 

`LocalDate`类不带时间。它表示 ISO 8601 格式的日期（YYYY-MM-DD）：

```java
System.out.println(LocalDate.now()); //prints: 2019-03-04

```

这是在这个地方写这篇文章时的当前日期。这个值是从计算机时钟中提取的。同样，您可以使用静态`now(ZoneId zone)`方法获取任何其他时区的当前日期。`ZoneId`对象可以使用静态`ZoneId.of(String zoneId)`方法构造，其中`String zoneId`是`ZonId.getAvailableZoneIds()`方法返回的任何字符串值：

```java
Set<String> zoneIds = ZoneId.getAvailableZoneIds();
for(String zoneId: zoneIds){
    System.out.println(zoneId);
}
```

前面的代码打印了近 600 个时区 ID。以下是其中一些：

```java
Asia/Aden
Etc/GMT+9
Africa/Nairobi
America/Marigot
Pacific/Honolulu
Australia/Hobart
Europe/London
America/Indiana/Petersburg
Asia/Yerevan
Europe/Brussels
GMT
Chile/Continental
Pacific/Yap
CET
Etc/GMT-1
Canada/Yukon
Atlantic/St_Helena
Libya
US/Pacific-New
Cuba
Israel
GB-Eire
GB
Mexico/General
Universal
Zulu
Iran
Navajo
Egypt
Etc/UTC
SystemV/AST4ADT
Asia/Tokyo
```

让我们尝试使用`"Asia/Tokyo"`，例如：

```java
ZoneId zoneId = ZoneId.of("Asia/Tokyo");
System.out.println(LocalDate.now(zoneId)); //prints: 2019-03-05

```

`LocalDate`的对象可以表示过去的任何日期，也可以表示将来的任何日期，方法如下：

*   `LocalDate parse(CharSequence text)`：从 ISO 8601 格式的字符串构造对象（YYYY-MM-DD）
*   `LocalDate parse(CharSequence text, DateTimeFormatter formatter)`：从字符串构造一个对象，格式由`DateTimeFormatter`对象指定，该对象具有丰富的模式系统和许多预定义的格式；下面是其中的一些：

*   `LocalDate of(int year, int month, int dayOfMonth)`：从年、月、日构造对象
*   `LocalDate of(int year, Month month, int dayOfMonth)`：从年、月（枚举常量）和日构造对象
*   `LocalDate ofYearDay(int year, int dayOfYear)`：从一年和一年中的某一天构造一个对象窗体

下面的代码演示了前面列出的方法：

```java
LocalDate lc1 = LocalDate.parse("2020-02-23");
System.out.println(lc1);                     //prints: 2020-02-23

LocalDate lc2 =  
          LocalDate.parse("20200223", DateTimeFormatter.BASIC_ISO_DATE);
System.out.println(lc2);                     //prints: 2020-02-23

DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy");
LocalDate lc3 =  LocalDate.parse("23/02/2020", formatter);
System.out.println(lc3);                     //prints: 2020-02-23

LocalDate lc4 =  LocalDate.of(2020, 2, 23);
System.out.println(lc4);                     //prints: 2020-02-23

LocalDate lc5 =  LocalDate.of(2020, Month.FEBRUARY, 23);
System.out.println(lc5);                     //prints: 2020-02-23

LocalDate lc6 = LocalDate.ofYearDay(2020, 54);
System.out.println(lc6);                     //prints: 2020-02-23

```

`LocalDate`对象可以提供各种值：

```java
LocalDate lc = LocalDate.parse("2020-02-23");
System.out.println(lc);                  //prints: 2020-02-23
System.out.println(lc.getYear());        //prints: 2020
System.out.println(lc.getMonth());       //prints: FEBRUARY
System.out.println(lc.getMonthValue());  //prints: 2
System.out.println(lc.getDayOfMonth());  //prints: 23
System.out.println(lc.getDayOfWeek());   //prints: SUNDAY
System.out.println(lc.isLeapYear());     //prints: true
System.out.println(lc.lengthOfMonth());  //prints: 29
System.out.println(lc.lengthOfYear());   //prints: 366

```

`LocalDate`对象可以修改如下：

```java
LocalDate lc = LocalDate.parse("2020-02-23");
System.out.println(lc.withYear(2021)); //prints: 2021-02-23
System.out.println(lc.withMonth(5));       //prints: 2020-05-23
System.out.println(lc.withDayOfMonth(5));  //prints: 2020-02-05
System.out.println(lc.withDayOfYear(53));  //prints: 2020-02-22
System.out.println(lc.plusDays(10));       //prints: 2020-03-04
System.out.println(lc.plusMonths(2));      //prints: 2020-04-23
System.out.println(lc.plusYears(2));       //prints: 2022-02-23
System.out.println(lc.minusDays(10));      //prints: 2020-02-13
System.out.println(lc.minusMonths(2));     //prints: 2019-12-23
System.out.println(lc.minusYears(2));      //prints: 2018-02-23

```

`LocalDate`对象可以比较如下：

```java
LocalDate lc1 = LocalDate.parse("2020-02-23");
LocalDate lc2 = LocalDate.parse("2020-02-22");
System.out.println(lc1.isAfter(lc2));       //prints: true
System.out.println(lc1.isBefore(lc2));      //prints: false

```

在`LocalDate`类中还有许多其他有用的方法。如果您要处理日期，我们建议您阅读这个类的 API 和其他类的`java.time`包及其子包。

# `LocalTime`类

`LocalTime`类包含没有日期的时间。它的方法与`LocalDate`类的方法类似，下面介绍如何创建`LocalTime`类的对象：

```java
System.out.println(LocalTime.now());         //prints: 21:15:46.360904

ZoneId zoneId = ZoneId.of("Asia/Tokyo");
System.out.println(LocalTime.now(zoneId));   //prints: 12:15:46.364378

LocalTime lt1 =  LocalTime.parse("20:23:12");
System.out.println(lt1);                     //prints: 20:23:12

LocalTime lt2 = LocalTime.of(20, 23, 12);
System.out.println(lt2);                     //prints: 20:23:12

```

时间值的每个分量可以从一个`LocalTime`对象中提取，如下所示：

```java
LocalTime lt2 =  LocalTime.of(20, 23, 12);
System.out.println(lt2);                     //prints: 20:23:12

System.out.println(lt2.getHour());           //prints: 20
System.out.println(lt2.getMinute());         //prints: 23
System.out.println(lt2.getSecond());         //prints: 12
System.out.println(lt2.getNano());           //prints: 0
```

`LocalTime`类的对象可以修改：

```java
LocalTime lt2 = LocalTime.of(20, 23, 12);
System.out.println(lt2.withHour(3)); //prints: 03:23:12
System.out.println(lt2.withMinute(10)); //prints: 20:10:12
System.out.println(lt2.withSecond(15)); //prints: 20:23:15
System.out.println(lt2.withNano(300)); //prints: 20:23:12.000000300
System.out.println(lt2.plusHours(10));       //prints: 06:23:12
System.out.println(lt2.plusMinutes(2));      //prints: 20:25:12
System.out.println(lt2.plusSeconds(2));      //prints: 20:23:14
System.out.println(lt2.plusNanos(200));      //prints: 20:23:12.000000200
System.out.println(lt2.minusHours(10));      //prints: 10:23:12
System.out.println(lt2.minusMinutes(2));     //prints: 20:21:12
System.out.println(lt2.minusSeconds(2));     //prints: 20:23:10
System.out.println(lt2.minusNanos(200));     //prints: 20:23:11.999999800
```

`LocalTime`类的两个对象也可以比较：

```java
LocalTime lt2 =  LocalTime.of(20, 23, 12);
LocalTime lt4 =  LocalTime.parse("20:25:12");
System.out.println(lt2.isAfter(lt4));       //prints: false
System.out.println(lt2.isBefore(lt4));      //prints: true
```

`LocalTime`类中还有很多其他有用的方法，如果您需要处理日期，我们建议您阅读这个类的 API 以及`java.time`包及其子包的其他类。

# `LocalDateTime`

`LocalDateTime`类包含日期和时间，并且具有`LocalDate`和`LocalTime`类所具有的所有方法，因此我们不在这里重复它们。我们只展示如何创建`LocalDateTime`类的对象：

```java
System.out.println(LocalDateTime.now());       
                                   //prints: 2019-03-04T21:59:00.142804
ZoneId zoneId = ZoneId.of("Asia/Tokyo");
System.out.println(LocalDateTime.now(zoneId)); 
                                   //prints: 2019-03-05T12:59:00.146038
LocalDateTime ldt1 = LocalDateTime.parse("2020-02-23T20:23:12");
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
System.out.println(ldt4);                 //prints: 2020-02-23T20:23:12

LocalDate ld = LocalDate.of(2020, 2, 23);
LocalTime lt = LocalTime.of(20, 23, 12);
LocalDateTime ldt5 = LocalDateTime.of(ld, lt);
System.out.println(ldt5);                 //prints: 2020-02-23T20:23:12

```

`LocalDateTime`类中还有很多其他有用的方法，如果您需要处理日期，我们建议您阅读这个类的 API 以及`java.time`包及其子包的其他类。

# `Period`和`Duration`类

`java.time.Period`和`java.time.Duration`类被设计为包含一定的时间量：

*   `Period`对象包含以年、月、日为单位的时间量
*   `Duration`对象包含以小时、分钟、秒和纳秒为单位的时间量

下面的代码演示了它们在`LocalDateTime`类中的创建和使用，但是`LocalDate`类（对于`Period`）和`LocalTime`（对于`Duration`中存在相同的方法：

```java
LocalDateTime ldt1 = LocalDateTime.parse("2020-02-23T20:23:12");
LocalDateTime ldt2 = ldt1.plus(Period.ofYears(2));
System.out.println(ldt2);      //prints: 2022-02-23T20:23:12

```

以下方法的工作方式相同：

```java
LocalDateTime ldt = LocalDateTime.parse("2020-02-23T20:23:12");
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

下面的代码演示了创建和使用`Period`对象的一些其他方法：

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

`Duration`的对象可以类似地创建和使用：

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

在`Period`和`Duration`类中还有很多其他有用的方法，如果您需要处理日期，我们建议您阅读这个类和`java.time`包及其子包的其他类的 API。

# 总结

本章向读者介绍了 Java 集合框架及其三个主要接口：`List`、`Set`和`Map`。讨论了每个接口，并用其中一个实现类演示了其方法。对泛型也进行了解释和演示。必须实现`equals()`和`hashCode()`方法，以便 Java 集合能够正确处理对象。

工具类`Collections`和`CollectionUtils`有许多有用的集合处理方法，并在示例中介绍了它们，以及`Arrays`、`ArrayUtils`、`Objects`和`ObjectUtils`。

`java.time`包的类的方法允许管理时间/日期值，这在特定的实际代码片段中得到了演示。

在下一章中，我们将概述 Java 类库和一些外部库，包括那些支持测试的库。具体来说，我们将探讨`org.junit`、`org.mockito`、`org.apache.log4j`、`org.slf4j`、`org.apache.commons`包及其子包。

# 测验

1.  什么是 Java 集合框架？选择所有适用的选项：
    1.  框架集合
    2.  `java.util`包的类和接口
    3.  接口`List`、`Set`和`Map`
    4.  实现集合数据结构的类和接口

2.  集合中的泛型是什么？选择所有适用的选项：

3.  收集`of()`工厂方法的局限性是什么？选择所有适用的选项：
    1.  不允许`null`元素
    2.  不允许向初始化的集合添加元素
    3.  不允许删除初始化集合中的元素
    4.  不允许修改初始化集合的元素

4.  `java.lang.Iterable`接口的实现允许什么？选择所有适用的选项：
    1.  允许逐个访问集合的元素
    2.  允许在`FOR`语句中使用集合
    3.  允许在`WHILE`语句中使用集合
    4.  允许在`DO...WHILE`语句中使用集合

5.  接口`java.util.Collection`的实现允许什么？选择所有适用的选项：
    1.  将另一个集合的元素添加到集合中
    2.  从集合中删除另一个集合的元素
    3.  只修改属于另一个集合的元素
    4.  从集合中删除不属于其他集合的对象

6.  选择`List`接口方法的所有正确语句：

7.  选择`Set`接口方法的所有正确语句：

8.  选择`Map`接口方法的所有正确语句：
    1.  `int size()`：返回映射中存储的键值对的计数；当`isEmpty()`方法返回`true`时，该方法返回`0`
    2.  `V remove(Object key)`：从映射中删除键和值；返回值，如果没有键或值为`null`，则返回`null`
    3.  `default boolean remove(Object key, Object value)`：如果映射中存在键值对，则删除键值对；如果删除键值对，则返回`true`
    4.  `default boolean replace(K key, V oldValue, V newValue)`：如果提供的键当前映射到`oldValue`，则用提供的`newValue`替换值`oldValue`；如果替换了`oldValue`，则返回`true`，否则返回`false`

9.  选择关于`Collections`类的`static void sort(List<T> list, Comparator<T> comparator)`方法的所有正确语句：
    1.  如果列表元素实现了`Comparable`接口，则对列表的自然顺序进行排序
    2.  它根据提供的`Comparator`对象对列表的顺序进行排序
    3.  如果列表元素实现了`Comparable`接口，则它会根据提供的`Comparator`对象对列表的顺序进行排序
    4.  它根据提供的`Comparator`对象对列表的顺序进行排序，无论列表元素是否实现`Comparable`接口

10.  以下代码执行的结果是什么？

```java
List<String> list1 = Arrays.asList("s1","s2", "s3");
List<String> list2 = Arrays.asList("s3", "s4");
Collections.copy(list1, list2);
System.out.println(list1);    
```

11.  `CollectionUtils`类方法的功能是什么？选择所有适用的选项：
    1.  匹配`Collections`类方法的功能，但处理`null`
    2.  补充了`Collections`类方法的功能
    3.  以`Collections`类方法所不具备的方式搜索、处理和比较 Java 集合
    4.  复制`Collections`类方法的功能

12.  以下代码执行的结果是什么？

```java
Integer[][] ar1 = {{42}};
Integer[][] ar2 = {{42}};
System.out.print(Arrays.equals(ar1, ar2) + " "); 
System.out.println(Arrays.deepEquals(arr3, arr4)); 
```

13.  以下代码执行的结果是什么？

```java
String[] arr1 = { "s1", "s2" };
String[] arr2 = { null };
String[] arr3 = null;
System.out.print(ArrayUtils.getLength(arr1) + " "); 
System.out.print(ArrayUtils.getLength(arr2) + " "); 
System.out.print(ArrayUtils.getLength(arr3) + " "); 
System.out.print(ArrayUtils.isEmpty(arr2) + " "); 
System.out.print(ArrayUtils.isEmpty(arr3));
```

14.  以下代码执行的结果是什么？

```java
 String str1 = "";
 String str2 = null;
 System.out.print((Objects.hash(str1) == 
                   Objects.hashCode(str2)) + " ");
 System.out.print(Objects.hash(str1) + " ");
 System.out.println(Objects.hashCode(str2) + " "); 
```

15.  以下代码执行的结果是什么？

```java
String[] arr = {"c", "x", "a"};
System.out.print(ObjectUtils.min(arr) + " ");
System.out.print(ObjectUtils.median(arr) + " ");
System.out.println(ObjectUtils.max(arr));
```

16.  以下代码执行的结果是什么？

```java
LocalDate lc = LocalDate.parse("1900-02-23");
System.out.println(lc.withYear(21)); 
```

17.  以下代码执行的结果是什么？

```java
LocalTime lt2 = LocalTime.of(20, 23, 12);
System.out.println(lt2.withNano(300));      
```

18.  以下代码执行的结果是什么？

```java
LocalDate ld = LocalDate.of(2020, 2, 23);
LocalTime lt = LocalTime.of(20, 23, 12);
LocalDateTime ldt = LocalDateTime.of(ld, lt);
System.out.println(ldt);                

```

19.  以下代码执行的结果是什么？

```java
LocalDateTime ldt = LocalDateTime.parse("2020-02-23T20:23:12");
System.out.print(ldt.minus(Period.ofYears(2)) + " ");
System.out.print(ldt.plus(Duration.ofMinutes(12)) + " ");
System.out.println(ldt);
```*

# 七、Java 标准和外部库

不使用标准库（也称为 **Java 类库**（**JCL**）就不可能编写 Java 程序。这就是为什么对这类库的深入了解对于成功编程来说就像对语言本身的了解一样重要。

还有*非标准*库，称为**外部库**或**第三方库**，因为它们不包括在 **Java 开发工具包**（**JDK**）发行版中。它们中的一些早已成为任何程序员工具包的永久固定装置。

要跟踪这些库中可用的所有功能并不容易。这是因为一个**集成开发环境**（**IDE**）给了您一个关于语言可能性的提示，但是它不能建议尚未导入的包的功能。唯一自动导入的包是`java.lang`。

本章的目的是向读者概述最流行的 JCL 包和外部库的功能

本章讨论的主题如下：

*   Java 类库（JCL）
*   `java.lang`
*   `java.util`
*   `java.time`
*   `java.io`和`java.nio`
*   `java.sql`和`javax.sql`
*   `java.net`
*   `java.lang.math`和`java.math`
*   `java.awt`、`javax.swing`、``javafx``
*   外部库
*   `org.junit`
*   `org.mockito`
*   `org.apache.log4j`和`org.slf4j`
*   `org.apache.commons`

# Java 类库

JCL 是实现该语言的包的集合。更简单地说，它是 JDK 中包含并准备好使用的`.class`文件的集合。一旦安装了 Java，就可以将它们作为安装的一部分，并可以开始使用 JCL 类作为构建块来构建应用代码，这些构建块负责许多底层管道。JCL 的丰富性和易用性极大地促进了 Java 的普及。

为了使用 JCL 包，可以导入它，而无需向`pom.xml`文件添加新的依赖项。这就是标准库和外部库的区别；如果您需要在 Maven`pom.xml`配置文件中添加一个库（通常是一个`.jar`文件）作为依赖项，那么这个库就是一个外部库。否则，它就是一个标准库或 JCL

一些 JCL 包名以`java`开头。传统上，它们被称为**核心 Java 包**，而那些以`javax`开头的包则被称为“扩展”。之所以这样做，可能是因为这些扩展被认为是可选的，甚至可能独立于 JDK 发布。也有人试图推动前扩展库成为一个核心包。但这将需要将包名从`java`更改为`javax`，这将打破使用`javax`包的现有应用。因此，这个想法被抛弃了，所以核心和扩展之间的区别逐渐消失。

这就是为什么，如果你在 Oracle 官方网站上查看 Java API，你会发现不仅有`java`和`javax`包被列为标准，还有`jdk`、`com.sun`、`org.xml`以及其他一些包。这些额外的包主要由工具或其他专用应用使用。在我们的书中，我们将主要集中在主流 Java 编程上，只讨论`java`和`javax`包。

# `java.lang`

这个包非常重要，使用它不需要导入。JVM 作者决定自动导入它。它包含最常用的 JCL 类：

*   `Object`类：其他 Java 类的基类
*   `Class`类：在运行时携带每个加载类的元数据
*   `String`、`StringBuffer`和`StringBuilder`类：支持类型为`String`的操作
*   所有原始类型的包装类：`Byte`、`Boolean`、`Short`、`Character`、`Integer`、`Long`、`Float`、`Double`
*   `Number`类：前面列出的除`Boolean`之外的所有数值原始类型的包装类的基类
*   `System`类：提供对重要系统操作和标准输入输出的访问（在本书的每个代码示例中，我们都使用了`System.out`对象）
*   `Runtime`类：提供对执行环境的访问
*   `Thread`和`Runnable`接口：创建 Java 线程的基础
*   `Iterable`接口：由迭代语句使用
*   `Math`类：提供基本数值运算的方法
*   `Throwable`类：所有异常的基类
*   `Error`类：一个异常类，它的所有子类都用来传递应用不应该捕捉到的系统错误
*   `Exception`类：该类及其直接子类表示选中的异常
*   `RuntimeException`类：这个类及其子类表示非受检异常，也称为运行时异常
*   `ClassLoader`类：读取`.class`文件并将其放入（装入）内存；也可以用来构建定制的类装入器
*   `Process`和`ProcessBuilder`类：允许创建其他 JVM 进程
*   许多其他有用的类和接口

# `java.util`

`java.util`包的大部分内容专门用于支持 Java 集合：

*   `Collection`接口：集合的许多其他接口的基础接口，它声明了管理集合元素所需的所有基本方法：`size()`、`add()`、`remove()`、`contains()`、`stream()`等；它还扩展了`java.lang.Iterable`接口，继承了`iterator()`、`forEach()`等方法，这意味着`Collection`接口的任何实现或其任何子接口`List`、`Set`、`Queue`、`Deque`等也可以用于迭代语句中：`ArrayList`、`LinkedList`、`HashSet`、`AbstractQueue`、`ArrayDeque`等
*   `Map`接口和实现它的类：`HashMap`、`TreeMap`等
*   `Collections`类：提供许多静态方法来分析、操作和转换集合
*   许多其他集合接口、类和相关工具

我们在第 6 章、“数据结构、泛型和流行工具”中讨论了 Java 集合，并看到了它们的用法示例。

`java.util`包还包括几个其他有用的类：

*   `Objects`：提供了各种与对象相关的实用方法，其中一些我们已经在第 6 章、“数据结构、泛型和流行工具”中进行了概述
*   `Arrays`：包含 160 种静态数组操作方法，其中一些方法我们在第 6 章、“数据结构、泛型和流行工具”中进行了概述
*   `Formatter`：允许格式化任何原始类型`String`、`Date`和其他类型；我们在第 6 章、“数据结构、泛型和流行工具”中演示了它的用法示例
*   `Optional`、`OptionalInt`、`OptionalLong`和`OptionalDouble`：这些类通过包装实际值来避免`NullPointerException`，实际值可以是`null`，也可以不是`null`
*   `Properties`：帮助读取和创建用于应用配置和类似目的的键值对
*   `Random`：通过生成伪随机数流来补充`java.lang.Math.random()`方法
*   `StringTokeneizer`：将`String`对象分解为由指定分隔符分隔的标记
*   `StringJoiner`：构造一个字符序列，由指定的分隔符分隔，并可选地由指定的前缀和后缀包围
*   许多其他有用的工具类，包括支持国际化和 Base64 编码和解码的类

# `java.time`

`java.time`包包含用于管理日期、时间、时段和持续时间的类。包装包括以下内容：

*   `Month`枚举
*   `DayOfWeek`枚举
*   `Clock`使用时区返回当前时刻、日期和时间的类
*   `Duration`和`Period`类表示并比较不同时间单位中的时间量
*   `LocalDate`、`LocalTime`和`LocalDateTime`类表示没有时区的日期和时间
*   `ZonedDateTime`类表示带时区的日期时间
*   `ZoneId`类标识时区，如`America/Chicago`
*   `java.time.format.DateTimeFormatter`类允许按照**国际标准组织**（**ISO**）格式，如`YYYY-MM-DD`等格式显示日期和时间
*   其他一些支持日期和时间操作的类

我们在第 6 章、“数据结构、泛型和流行工具”中讨论了大多数此类。

# `java.io`以及`java.nio` 

`java.io`和`java.nio`包包含支持使用流、序列化和文件系统读写数据的类和接口。这两种包装的区别如下：

*   `java.io`包类允许在没有缓存的情况下读取/写入数据（我们在第 5 章、“字符串、输入/输出和文件”中讨论过），而`java.nio`包的类创建了一个缓冲区，允许在填充的缓冲区中来回移动
*   `java.io`包类阻塞流直到所有数据被读写，而`java.nio`包的类以非阻塞方式实现（我们将在第 15 章、“反应式编程”中讨论非阻塞方式）

# `java.sql`以及`javax.sql`

这两个包组成了一个 **Java 数据库连接**（**JDBC**）API，它允许访问和处理存储在数据源（通常是关系数据库）中的数据。`javax.sql`包通过提供以下支持来补充`java.sql`包：

*   `DataSource`接口作为`DriverManager`类的替代
*   连接和语句池
*   分布式事务
*   行集

我们将讨论这些包，并在第 10 章“管理数据库中的数据”中看到代码示例。

# `java.net`

`java.net`包包含支持以下两个级别的应用联网的类：

*   **底层网络**，基于：
    *   IP 地址
    *   套接字是基本的双向数据通信机制
    *   各种网络接口
*   **高层网络**，基于：
    *   **通用资源标识符**（**URI**）
    *   **通用资源定位器**（**URL**）
    *   URL 指向的资源的连接

我们将讨论这个包，并在第 11 章、“网络编程”中看到代码示例。

# `java.lang.math`以及`java.math`

`java.lang.math`包包含执行基本数值运算的方法，例如计算两个数值的最小值和最大值、绝对值、初等指数、对数、平方根、三角函数以及许多其他数学运算。

`java.math`包通过允许使用`BigDecimal`和`BigInteger`类处理更大的数字，补充了`java.lang`包的 Java 基本类型和包装类。

# `Java.awt`，`javax.swing`，和 JavaFX

第一个支持为桌面应用构建**图形用户界面**（**GUI**）的 Java 库是`java.awt`包中的**抽象窗口工具包**（**AWT**）。它为执行平台的本机系统提供了一个接口，允许创建和管理窗口、布局和事件。它还具有基本的 GUI 小部件（如文本字段、按钮和菜单），提供对系统托盘的访问，并允许启动 Web 浏览器和通过 Java 代码向客户端发送电子邮件。它对本机代码的高度依赖使得基于 AWT 的 GUI 在不同的平台上看起来不同。

1997 年，Sun 微系统公司和 Netscape 通信公司推出了 Java **基础类**，后来被称为 **Swing**，并将它们放在`javax.swing`包中。使用 Swing 构建的 GUI 组件能够模拟一些本机平台的外观，但也允许您插入不依赖于它运行的平台的外观。它通过添加选项卡面板、滚动窗格、表格和列表扩展了 GUI 可以拥有的小部件列表。Swing 组件被称为轻量级组件，因为它们不依赖于本机代码，并且完全用 Java 实现。

2007 年，Sun 微系统公司宣布创建 JavaFX，JavaFX 最终成为一个软件平台，用于在许多不同的设备上创建和交付桌面应用。它旨在取代 Swing 作为 JavaSE 的标准 GUI 库。JavaFX 框架位于以`javafx`开头的包中，支持所有主要的桌面操作系统（DOS）和多个移动操作系统，包括 Symbian 操作系统、Windows 移动操作系统和一些专有的实时操作系统。

JavaFX 基于**层叠样式表**（**CSS**），将平滑动画、Web 视图、音频和视频播放以及样式的支持添加到 GUI 开发人员的库中。但是，Swing 有更多的组件和第三方库，因此使用 JavaFX 可能需要创建很久以前在 Swing 中实现的自定义组件和管道。这就是为什么，尽管 JavaFX 被推荐为桌面 GUI 实现的首选，但根据 [Oracle 网站上的官方回应](http://www.oracle.com/technetwork/java/javafx/overview/faq-1446554.html#6)，Swing 在可预见的未来仍将是 Java 的一部分。所以，可以继续使用 Swing，但如果可能，最好切换到 JavaFX。

我们将讨论 JavaFX，并在第 12 章、“Java GUI 编程”中看到代码示例。

# 外部库

最常用的第三方非 JCL 库的不同列表包括 20 到 100 个库。在本节中，我们将讨论这些列表中的大多数。所有这些都是开源项目。

# `org.junit`

`org.junit`包是开源测试框架 JUnit 的根包。它可以作为以下`pom.xml`依赖项添加到项目中：

```java
<dependency>
    <groupId>junit</groupId>
    <artifactId>junit</artifactId>
    <version>4.12</version>
    <scope>test</scope>
</dependency>
```

前面的`dependency`标记中的`scope`值告诉 Maven 只有在测试代码要运行时才包含库`.jar`文件，而不是包含在应用的生产`.jar`文件中。有了依赖关系，现在就可以创建测试了。您可以自己编写代码，也可以让 IDE 使用以下步骤为您编写代码：

1.  右键单击要测试的类名
2.  选择“转到”
3.  选择“测试”
4.  单击“创建新测试”

5.  单击要测试的类的方法的复选框
6.  使用`@Test`注解为生成的测试方法编写代码
7.  如有必要，添加带有`@Before`和`@After`注解的方法

假设我们有以下类：

```java
public class SomeClass {
    public int multiplyByTwo(int i){
        return i * 2;
    }
}
```

如果您遵循前面列出的步骤，那么在`test`源代码树下将创建以下测试类：

```java
import org.junit.Test;
public class SomeClassTest {
    @Test
    public void multiplyByTwo() {
    }
}
```

现在您可以实现如下的`void multiplyByTwo()`方法：

```java
@Test
public void multiplyByTwo() {
    SomeClass someClass = new SomeClass();
    int result = someClass.multiplyByTwo(2);
    Assert.assertEquals(4, result);
}
```

一个**单元**是一段可以测试的最小代码，因此它的名字。最佳测试实践将方法视为最小的可测试单元。这就是为什么单元测试通常测试方法。

# `org.mockito`

单元测试经常面临的问题之一是需要测试使用第三方库、数据源或其他类的方法的方法。在测试时，您希望控制所有的输入，以便可以预测测试代码的预期结果。在这一点上，模拟或模拟被测试代码与之交互的对象的行为的技术就派上了用场。

一个开源框架 Mockito（`org.mockito`根包名）允许完成**模拟对象**的创建。使用它非常简单和直接。这里有一个简单的例子。假设我们需要测试另一个`SomeClass`方法：

```java
public class SomeClass {
    public int multiplyByTwoTheValueFromSomeOtherClass(SomeOtherClass 
                                                        someOtherClass){
        return someOtherClass.getValue() * 2;
    }
}
```

为了测试这个方法，我们需要确保`getValue()`方法返回一个特定的值，所以我们要模拟这个方法。为此，请执行以下步骤：

1.  向 Maven`pom.xml`配置文件添加依赖项：

```java
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-core</artifactId>
            <version>2.23.4</version>
            <scope>test</scope>
        </dependency>

```

2.  为需要模拟的类调用`Mockito.mock()`方法：

```java
SomeOtherClass mo = Mockito.mock(SomeOtherClass.class);
```

3.  设置需要从方法返回的值：

```java
Mockito.when(mo.getValue()).thenReturn(5);
```

4.  现在，您可以将模拟对象作为参数传递到正在测试的调用模拟方法的方法中：

```java
SomeClass someClass = new SomeClass();
int result = someClass.multiplyByTwoTheValueFromSomeOtherClass(mo);

```

5.  模拟方法返回预定义的结果：

```java
Assert.assertEquals(10, result);
```

6.  完成上述步骤后，测试方法如下所示：

```java
@Test
public void multiplyByTwoTheValueFromSomeOtherClass() {
    SomeOtherClass mo = Mockito.mock(SomeOtherClass.class);
    Mockito.when(mo.getValue()).thenReturn(5);

    SomeClass someClass = new SomeClass();
    int result = 
           someClass.multiplyByTwoTheValueFromSomeOtherClass(mo);
    Assert.assertEquals(10, result);
}
```

Mockito 有一定的局限性。例如，不能模拟静态方法和私有方法。否则，通过可靠地预测所使用的第三方类的结果来隔离正在测试的代码是一个很好的方法

# `org.apache.log4j`以及`org.slf4j`

在这本书中，我们使用`System.out`来显示结果。在实际应用中，也可以这样做，并将输出重定向到一个文件，例如，用于以后的分析。在做了一段时间之后，您会注意到您需要关于每个输出的更多细节：例如，每个语句的日期和时间以及生成日志语句的类名。随着代码库的增长，您会发现最好将不同子系统或包的输出发送到不同的文件，或者在一切正常时关闭一些消息，在检测到问题并且需要有关代码行为的更详细信息时再打开这些消息。您不希望日志文件的大小无法控制地增长。

您可以编写自己的代码来完成这一切。但是有几种框架是基于配置文件中的设置来实现的，您可以在每次需要更改日志记录行为时更改这些设置。最常用的两个框架是`log4j`（发音为 *LOG-FOUR-JAY*）和`slf4j`（发音为 *S-L-F-FOUR-JAY*）。

事实上，这两个框架并不是对手。`slf4j`框架是一个外观，提供对底层实际日志框架的统一访问，其中一个也可以是`log4j`。当程序员事先不知道使用库的应用将使用什么样的日志框架时，这种外观在库开发期间尤其有用。通过使用`slf4j`编写代码，程序员允许稍后将其配置为使用任何日志系统。

因此，如果您的代码将仅由您的团队开发的应用使用，那么仅使用`log4j`就足够了。否则，请考虑使用`slf4j`。

并且，与任何第三方库一样，在使用`log4j`框架之前，必须向 Maven`pom.xml`配置文件添加相应的依赖关系：

```java
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.11.1</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.11.1</version>
</dependency>

```

例如，以下是如何使用框架：

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
public class SomeClass {
    static final Logger logger = 
                        LogManager.getLogger(SomeClass.class.getName());
    public int multiplyByTwoTheValueFromSomeOtherClass(SomeOtherClass 
                                                        someOtherClass){
        if(someOtherClass == null){
            logger.error("The parameter should not be null");
            System.exit(1);
        }
        return someOtherClass.getValue() * 2;
    }
    public static void main(String... args){
        new SomeClass().multiplyByTwoTheValueFromSomeOtherClass(null);
    }
}
```

如果我们运行前面的`main()`方法，结果如下：

```java
18:34:07.672 [main] ERROR SomeClass - The parameter should not be null
Process finished with exit code 1
```

如您所见，如果项目中没有添加特定于`log4j`的配置文件，`log4j`将在`DefaultConfiguration`类中提供默认配置。默认配置如下：

1.  日志消息将转到控制台
2.  消息的模式将是`"%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"`
3.  `logging`的级别为`Level.ERROR`（其他级别为`OFF`、`FATAL`、`WARN`、`INFO`、`DEBUG`、`TRACE`、`ALL`）

通过使用以下内容将`log4j2.xml`文件添加到`resources`文件夹（Maven 将其放置在类路径上），可以获得相同的结果：

```java
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level 
                                                %logger{36} - %msg%n"/>
        </Console>
    </Appenders>
    <Loggers>
        <Root level="error">
            <AppenderRef ref="Console"/>
        </Root>
    </Loggers>
</Configuration>
```

如果这对您来说还不够好，可以将配置更改为记录不同级别的消息、不同的文件等等。[阅读`log4J`文档](https://logging.apache.org)。

# `org.apache.commons`

`org.apache.commons`包是另一个流行的库，它是作为一个名为 **Apache Commons** 的项目开发的。它由一个名为 **Apache 软件基金会**的开源程序员社区维护。这个组织是 1999 年由阿帕奇集团成立的。自 1993 年以来，Apache 小组一直围绕 Apache HTTP 服务器的开发而发展。Apache HTTP 服务器是一个开源的跨平台 Web 服务器，自 1996 年 4 月以来一直是最流行的 Web 服务器。

Apache Commons 项目包括以下三个部分：

*   **Commons Sandbox**：Java 组件开发的工作区；您可以为那里的开放源码工作做出贡献
*   **Commons Dormant**：当前处于非活动状态的组件的存储库；您可以在那里使用代码，但必须自己构建组件，因为这些组件可能不会在不久的将来发布
*   **Commons Proper**：可重用的 Java 组件，组成实际的`org.apache.commons`库

我们讨论了第 5 章中的`org.apache.commons.io`包、“字符串、输入/输出和文件”。
在下面的小节中，我们将只讨论三个最受欢迎的通用包：

*   `org.apache.commons.lang3`
*   `org.apache.commons.collections4`
*   `org.apache.commons.codec.binary`

但是`org.apache.commons`下还有更多的包，其中包含数千个类，这些类很容易使用，可以帮助您的代码更加优雅和高效。

# `lang`和`lang3`

`org.apache.commons.lang3`包实际上是`org.apache.commons.lang`包的版本 3。创建新包的决定是由于版本 3 中引入的更改是向后不兼容的，这意味着使用先前版本的`org.apache.commons.lang`包的现有应用在升级到版本 3 后可能会停止工作。但在大多数主流编程中，向`import`语句添加`3`（作为迁移到新版本的方法）通常不会破坏任何东西。

据文献记载，`org.apache.commons.lang3`包提供了高度可重用的静态实用方法，主要是为`java.lang`类增加价值。这里有几个值得注意的例子：

*   `ArrayUtils`类：允许搜索和操作数组；我们在第 6 章、“数据结构、泛型和流行工具”中讨论和演示了它
*   `ClassUtils`类：提供类的元数据
*   `ObjectUtils`类：检查`null`的对象数组，比较对象，以`null`安全的方式计算对象数组的中值和最小/最大值；我们在第 6 章、“数据结构、泛型和流行工具”中讨论并演示了它
*   `SystemUtils`类：提供执行环境的相关信息
*   `ThreadUtils`类：查找当前正在运行的线程的信息
*   `Validate`类：验证单个值和集合，比较它们，检查`null`，匹配，并执行许多其他验证
*   `RandomStringUtils`类：根据不同字符集的字符生成`String`对象
*   `StringUtils`类：我们在第 5 章中讨论了“字符串、输入/输出和文件”

# `collections4`

尽管从表面上看，`org.apache.commons.collections4`包的内容与`org.apache.commons.collections`包（即包的版本 3）的内容非常相似，但迁移到版本 4 可能不如在`import`语句中添加“4”那么顺利。版本 4 删除了不推荐使用的类，添加了泛型和其他与以前版本不兼容的特性。

要想得到一个在这个包或它的一个子包中不存在的集合类型或集合工具，必须很困难。以下只是包含的功能和工具的高级列表：

*   `Bag`集合接口，具有每个对象的多个副本
*   实现`Bag`接口的十几个类；例如，下面是如何使用`HashBag`类：

```java
        Bag<String> bag = new HashBag<>();
        bag.add("one", 4);
        System.out.println(bag);                 //prints: [4:one]
        bag.remove("one", 1);
        System.out.println(bag);                 //prints: [3:one]
        System.out.println(bag.getCount("one")); //prints: 3
```

*   转换基于`Bag`的集合的`BagUtils`类
*   `BidiMap`双向映射的接口，不仅可以按键检索值，还可以按值检索键；它有几个实现，例如：

```java
        BidiMap<Integer, String> bidi = new TreeBidiMap<>();
        bidi.put(2, "two");
        bidi.put(3, "three");
        System.out.println(bidi);             //prints: {2=two, 3=three}
        System.out.println(bidi.inverseBidiMap()); 
                                              //prints: {three=3, two=2}
        System.out.println(bidi.get(3));      //prints: three
        System.out.println(bidi.getKey("three")); //prints: 3
        bidi.removeValue("three"); 
        System.out.println(bidi);              //prints: {2=two}

```

*   `MapIterator`提供简单快速的映射迭代接口，例如：

```java
        IterableMap<Integer, String> map =
                           new HashedMap<>(Map.of(1, "one", 2, "two"));
        MapIterator it = map.mapIterator();
        while (it.hasNext()) {
            Object key = it.next();
            Object value = it.getValue();
            System.out.print(key + ", " + value + ", "); 
                                              //prints: 2, two, 1, one, 
            if(((Integer)key) == 2){
                it.setValue("three");
            }
        }
        System.out.println("\n" + map);      //prints: {2=three, 1=one}
```

*   使元素保持一定顺序的有序映射和集合，如`List`，例如：

```java
        OrderedMap<Integer, String> map = new LinkedMap<>();
        map.put(4, "four");
        map.put(7, "seven");
        map.put(12, "twelve");
        System.out.println(map.firstKey()); //prints: 4
        System.out.println(map.nextKey(2)); //prints: null
        System.out.println(map.nextKey(7)); //prints: 12
        System.out.println(map.nextKey(4)); //prints: 7
```

*   引用映射；它们的键和/或值可以由垃圾收集器删除
*   `Comparator`接口的各种实现
*   `Iterator`接口的各种实现
*   将数组和枚举转换为集合的类
*   允许测试或创建集合的并集、交集和闭包的工具
*   `CollectionUtils`、`ListUtils`、`MapUtils`、`MultiMapUtils`、`MultiSetUtils`、`QueueUtils`、`SetUtils`以及许多其他特定于接口的工具类

[阅读包装文件](https://commons.apache.org/proper/commons-collections)了解更多细节。

# `codec.binary`

`org.apache.commons.codec.binary`包提供对 Base64、Base32、二进制和十六进制字符串编码和解码的支持。编码是必要的，以确保您跨不同系统发送的数据不会因为不同协议中字符范围的限制而在途中更改。此外，有些系统将发送的数据解释为控制字符（例如调制解调器）。

下面的代码片段演示了这个包的`Base64`类的基本编码和解码功能：

```java
String encodedStr = 
           new String(Base64.encodeBase64("Hello, World!".getBytes()));
System.out.println(encodedStr);         //prints: SGVsbG8sIFdvcmxkIQ==

System.out.println(Base64.isBase64(encodedStr));        //prints: true

String decodedStr = 
               new String(Base64.decodeBase64(encodedStr.getBytes()));
System.out.println(decodedStr);                 //prints: Hello, World!

```

您可以在 [ApacheCommons 项目站点](https://commons.apache.org/proper/commons-codec)上阅读关于这个包的更多信息。

# 总结

在本章中，我们概述了 JCL 最流行的包的功能：`java.lang`、`java.util`、`java.time`、`java.io`和`java.nio`、`java.sql`、`javax.sql`、`java.net`、`java.lang.math`、`java.math`、`java.awt`、`javax.swing`和`javafx`。

最流行的外部库是由`org.junit`、`org.mockito`、`org.apache.log4j`、`org.slf4j`和`org.apache.commons`包表示的，当这些功能已经存在并且可以直接导入和使用时，它可以帮助读者避免编写自定义代码。

在下一章中，我们将讨论 Java 线程并演示它们的用法。我们还将解释并行处理和并发处理之间的区别。我们将演示如何创建线程以及如何执行、监视和停止它。它不仅对准备为多线程处理编写代码的读者非常有用，而且对那些希望提高对 JVM 工作原理的理解的读者也非常有用，这将是下一章的主题。

# 测验

1.  什么是 Java 类库？选择所有适用的选项：
    1.  编译后的类的集合
    2.  Java 安装附带的包
    3.  Maven 自动添加到类路径的`.jar`文件
    4.  任何用 Java 编写的库

2.  什么是 Java 外部库？选择所有适用的选项：

3.  `java.lang`包中包含哪些功能？选择所有适用的选项：

4.  `java.util`包中包含哪些功能？选择所有适用的选项：

5.  `java.time`包中包含哪些功能？选择所有适用的选项：

6.  `java.io`包中包含哪些功能？选择所有适用的选项：

7.  `java.sql`包中包含哪些功能？选择所有适用的选项：

8.  `java.net`包中包含哪些功能？选择所有适用的选项：

9.  `java.math`包中包含哪些功能？选择所有适用的选项：

10.  `javafx`包中包含哪些功能？选择所有适用的选项：

11.  `org.junit`包中包含哪些功能？选择所有适用的选项：

12.  `org.mockito`包中包含哪些功能？选择所有适用的选项：

13.  `org.apache.log4j`包中包含哪些功能？选择所有适用的选项：

14.  `org.apache.commons.lang3`包中包含哪些功能？选择所有适用的选项：

15.  `org.apache.commons.collections4`包中包含哪些功能？选择所有适用的选项：

16.  `org.apache.commons.codec.binary`包中包含哪些功能？选择所有适用的选项：*

# 八、多线程和并发处理

在本章中，我们将讨论通过使用并发处理数据的工作器（线程）来提高 Java 应用性能的方法。我们将解释 Java 线程的概念并演示它们的用法。我们还将讨论并行处理和并发处理的区别，以及如何避免由于并发修改共享资源而导致的不可预知的结果。

本章将讨论以下主题：

*   线程与进程
*   用户线程与守护进程
*   扩展线程类
*   实现`Runnable`接口
*   扩展线程与实现`Runnable`
*   使用线程池
*   从线程获取结果
*   并行与并发处理
*   同一资源的并发修改

# 线程与进程

Java 有两个执行单元：进程和线程。一个**进程**通常代表整个 JVM，尽管应用可以使用`java.lang.ProcessBuilder`创建另一个进程。但是由于多进程的情况不在本书的讨论范围内，所以我们将重点讨论第二个执行单元，即一个**线程**，它与进程类似，但与其他线程的隔离度较低，执行所需资源较少。

一个进程可以有许多线程在运行，并且至少有一个线程称为**主线程**——启动应用的线程，我们在每个示例中都使用它。线程可以共享资源，包括内存和打开的文件，这样可以提高效率。但它的代价是，意外的相互干扰，甚至阻碍执行的风险更高。这就需要编程技巧和对并发技术的理解

# 用户线程与守护进程

有一种特殊的线程叫做守护进程（daemon）。

守护进程一词起源于古希腊语，意思是*神与人之间的神性或超自然存在*和*内在或伴随的精神或激励力量*。

在计算机科学中，术语**守护进程**有更普通的用法，用于*作为后台进程运行，而不是由交互用户直接控制*的计算机程序。这就是为什么 Java 中有以下两种类型的线程：

*   用户线程（默认），由应用启动（主线程就是这样一个例子）
*   在后台工作来支持用户线程活动的守护线程

这就是为什么所有守护线程在最后一个用户线程退出之后立即退出，或者在未处理的异常之后被 JVM 终止。

# 扩展`Thread`类

创建线程的一种方法是扩展`java.lang.Thread`类并覆盖其`run()`方法。例如：

```java
class MyThread extends Thread {
    private String parameter;
    public MyThread(String parameter) {
        this.parameter = parameter;
    }
    public void run() {
        while(!"exit".equals(parameter)){
            System.out.println((isDaemon() ? "daemon" : "  user") +
              " thread " + this.getName() + "(id=" + this.getId() +
                                      ") parameter: " + parameter);
            pauseOneSecond();
        }
        System.out.println((isDaemon() ? "daemon" : "  user") +
          " thread " + this.getName() + "(id=" + this.getId() +
                                  ") parameter: " + parameter);
    }
    public void setParameter(String parameter) {
        this.parameter = parameter;
    }
}
```

如果未覆盖`run()`方法，则线程不执行任何操作。在我们的示例中，只要参数不等于字符串`"exit"`，线程就会每秒打印它的名称和其他属性；否则它就会退出。`pauseOneSecond()`方法如下：

```java
private static void pauseOneSecond(){
    try {
        TimeUnit.SECONDS.sleep(1);
    } catch (InterruptedException e) {
        e.printStackTrace();
    }
}
```

我们现在可以使用`MyThread`类来运行两个线程—一个用户线程和一个守护线程：

```java
public static void main(String... args) {
    MyThread thr1 = new MyThread("One");
    thr1.start();
    MyThread thr2 = new MyThread("Two");
    thr2.setDaemon(true);
    thr2.start();
    pauseOneSecond();
    thr1.setParameter("exit");
    pauseOneSecond();
    System.out.println("Main thread exists");
}
```

如您所见，主线程创建另外两个线程，暂停一秒钟，在用户线程上设置参数`exit`，再暂停一秒钟，最后退出（方法`main()`完成执行）。

如果我们运行前面的代码，我们会看到如下屏幕截图（线程`id`在不同的操作系统中可能不同）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/eed5c70b-11cd-45ca-aa9a-b0dfadc190c6.png)

前面的屏幕截图显示，只要最后一个用户线程（本例中的主线程）退出，守护线程就会自动退出。

# 实现`Runnable`接口

创建线程的第二种方法是使用实现`java.lang.Runnable`的类。下面是这样一个类的示例，它的功能与`MyThread`类几乎完全相同：

```java
class MyRunnable implements Runnable {
    private String parameter, name;
    public MyRunnable(String name) {
        this.name = name;
    }
    public void run() {
        while(!"exit".equals(parameter)){
            System.out.println("thread " + this.name + 
                               ", parameter: " + parameter);
            pauseOneSecond();
        }
        System.out.println("thread " + this.name +
                              ", parameter: " + parameter);
    }
    public void setParameter(String parameter) {
        this.parameter = parameter;
    }
}
```

不同的是没有`isDaemon()`方法、`getId()`或任何其他现成的方法。`MyRunnable`类可以是实现`Runnable`接口的任何类，因此我们无法打印线程是否为守护进程。这就是为什么我们添加了`name`属性，以便我们可以识别线程。

我们可以使用`MyRunnable`类来创建线程，就像我们使用`MyThread`类一样：

```java
public static void main(String... args) {
    MyRunnable myRunnable1 = new MyRunnable("One");
    MyRunnable myRunnable2 = new MyRunnable("Two");

    Thread thr1 = new Thread(myRunnable1);
    thr1.start();
    Thread thr2 = new Thread(myRunnable2);
    thr2.setDaemon(true);
    thr2.start();
    pauseOneSecond();
    myRunnable1.setParameter("exit");
    pauseOneSecond();
    System.out.println("Main thread exists");
}
```

下面的截图证明了`MyRunnable`类的行为与`MyThread`类的行为相似：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/8558468b-719b-4a94-8dd9-d88c70d0ab75.png)

守护线程（名为`Two`的线程）在最后一个用户线程存在后退出，它与`MyThread`类的情况完全相同。

# 扩展线程与实现`Runnable`

`Runnable`的实现具有允许实现扩展另一个类的优点（在某些情况下是唯一可能的选择）。当您想向现有类添加类似线程的行为时，它特别有用。实现`Runnable`允许更灵活的使用。但除此之外，与`Thread`类的扩展相比，在功能上没有区别。

`Thread`类有几个构造器，允许设置线程名称及其所属的组。线程的分组有助于在多个线程并行运行的情况下对它们进行管理。`Thread`类还有几个方法，提供有关线程状态、属性的信息，并允许控制其行为。

如您所见，线程的 ID 是自动生成的。它不能更改，但可以在线程终止后重用。另一方面，可以使用相同的名称设置多个线程。

执行优先级也可以用一个介于`Thread.MIN_PRIORITY`和`Thread.MAX_PRIORITY`之间的值编程设置。值越小，允许线程运行的时间就越多，这意味着它具有更高的优先级。如果未设置，则优先级值默认为`Thread.NORM_PRIORITY`。

线程的状态可以具有以下值之一：

*   `NEW`：线程尚未启动时
*   `RUNNABLE`：执行线程时
*   `BLOCKED`：线程被阻塞，等待监视器锁定时
*   `WAITING`：当一个线程无限期地等待另一个线程执行特定操作时
*   `TIMED_WAITING`：当一个线程等待另一个线程执行某个操作时，等待时间长达指定的等待时间
*   `TERMINATED`：线程退出时

线程和任何对象也可以使用`java.lang.Object`基类的`wait()`、`notify()`和`notifyAll()`方法*彼此*交谈。但是线程行为的这一方面超出了本书的范围。

# 使用线程池

每个线程都需要资源——**CPU** 和**内存**。这意味着必须控制线程的数量，其中一种方法是创建一个固定数量的线程池。此外，创建对象会产生开销，这对于某些应用可能非常重要

在本节中，我们将研究`java.util.concurrent`包中提供的`Executor`接口及其实现。它们封装了线程管理，最大限度地减少了应用开发人员在编写与线程生命周期相关的代码上花费的时间。

在`java.util.concurrent`包中定义了三个`Executor`接口：

*   基本`Executor`接口：只有一个`void execute(Runnable r)`方法。

*   `ExecutorService`接口：对`Executor`进行了扩展，增加了四组方法来管理工作线程和执行器本身的生命周期：
    *   `submit()`将`Runnable`或`Callable`对象放入队列中执行的方法（`Callable`允许工作线程返回值）；返回`Future`接口的对象，用于访问`Callable`返回的值，管理工作线程的状态
    *   `invokeAll()`方法，将接口`Callable`对象的集合放入队列中执行；当所有工作线程完成时返回`Future`对象的`List`（还有一个重载的`invokeAll()`方法超时）
    *   `invokeAny()`方法，将接口`Callable`对象的集合放入队列中执行；返回一个已完成的任何工作线程的`Future`对象（还有一个带超时的重载`invokeAny()`方法）
    *   方法管理工作线程的状态和服务本身，如下所示：
        *   `shutdown()`：防止新的工作线程提交到服务。
        *   `shutdownNow()`：中断每个未完成的工作线程。工作线程应该被写入，这样它就可以周期性地检查自己的状态（例如使用`Thread.currentThread().isInterrupted()`），并自动正常关闭；否则，即使在调用`shutdownNow()`之后，它也会继续运行。
        *   `isShutdown()`：检查执行器是否启动关机。
        *   `awaitTermination(long timeout, TimeUnit timeUnit)`：等待关闭请求后所有工作线程执行完毕，或者超时，或者当前线程中断，以先发生的为准。
        *   `isTerminated()`：检查关闭启动后是否所有工作线程都已完成。除非先调用了`shutdown()`或`shutdownNow()`，否则它永远不会返回`true`。

*   `ScheduledExecutorService`接口：它扩展了`ExecutorService`并添加了允许调度工作线程执行（一次性和周期性）的方法。

可以使用`java.util.concurrent.ThreadPoolExecutor`或`java.util.concurrent.ScheduledThreadPoolExecutor`类创建基于池的`ExecutorService`实现。还有一个`java.util.concurrent.Executors`工厂类，它涵盖了大多数实际案例。因此，在为工作线程池创建编写自定义代码之前，我们强烈建议您使用`java.util.concurrent.Executors`类的以下工厂方法：

*   `newCachedThreadPool()`创建一个线程池，根据需要添加一个新线程，除非之前创建了一个空闲线程；已经空闲 60 秒的线程将从池中删除
*   创建一个按顺序执行工作线程的`ExecutorService`（池）实例的`newSingleThreadExecutor()`
*   `newSingleThreadScheduledExecutor()`创建一个单线程执行器，可以安排在给定的延迟后运行，或者定期执行
*   `newFixedThreadPool(int nThreads)`创建一个线程池，该线程池重用固定数量的工作线程；如果在所有工作线程仍在执行时提交一个新任务，则该任务将被放入队列中，直到有一个工作线程可用为止
*   `newScheduledThreadPool(int nThreads)`创建一个固定大小的线程池，可以计划在给定的延迟后运行，或者定期执行
*   `newWorkStealingThreadPool(int nThreads)`创建一个线程池，该线程池使用`ForkJoinPool`使用的*偷工*算法，在工作线程生成其他线程时特别有用，例如在递归算法中；它还适应指定数量的 CPU，您可以将其设置为高于或低于计算机上的实际 CPU 数

工作窃取算法

工作窃取算法允许已完成分配任务的线程帮助其他仍忙于分配任务的任务。例如，请参见 [Oracle Java 官方文档](https://docs.oracle.com/javase/tutorial/essential/concurrency/forkjoin.html)中对 Fork/Join 实现的描述。

这些方法中的每一个都有一个重载版本，允许在需要时传入一个用来创建新线程的`ThreadFactory`。让我们看看它在代码示例中是如何工作的。首先，我们运行另一个版本的`MyRunnable`类：

```java
class MyRunnable implements Runnable {
    private String name;
    public MyRunnable(String name) {
        this.name = name;
    }
    public void run() {
        try {
            while (true) {
                System.out.println(this.name + " is working...");
                TimeUnit.SECONDS.sleep(1);
            }
        } catch (InterruptedException e) {
            System.out.println(this.name + " was interrupted\n" +
                this.name + " Thread.currentThread().isInterrupted()="
                            + Thread.currentThread().isInterrupted());
        }
    }
}
```

我们不能再使用`parameter`属性来告诉线程停止执行，因为线程生命周期现在将由`ExecutorService`控制，它的方式是调用`interrupt()`线程方法。另外，请注意，我们创建的线程有一个无限循环，因此它永远不会停止执行，除非强制执行（通过调用`interrupt()`方法）。让我们编写执行以下操作的代码：

1.  创建一个包含三个线程的池
2.  确保池不接受更多线程
3.  等待一段固定的时间，让所有线程完成它们所做的事情
4.  停止（中断）未完成任务的线程
5.  退出

以下代码执行前面列表中描述的所有操作：

```java
ExecutorService pool = Executors.newCachedThreadPool();
String[] names = {"One", "Two", "Three"};
for (int i = 0; i < names.length; i++) {
    pool.execute(new MyRunnable(names[i]));
}
System.out.println("Before shutdown: isShutdown()=" + pool.isShutdown() 
                           + ", isTerminated()=" + pool.isTerminated());
pool.shutdown(); // New threads cannot be added to the pool
//pool.execute(new MyRunnable("Four"));    //RejectedExecutionException
System.out.println("After shutdown: isShutdown()=" + pool.isShutdown() 
                           + ", isTerminated()=" + pool.isTerminated());
try {
    long timeout = 100;
    TimeUnit timeUnit = TimeUnit.MILLISECONDS;
    System.out.println("Waiting all threads completion for "
                                + timeout + " " + timeUnit + "...");
    // Blocks until timeout, or all threads complete execution,
    // or the current thread is interrupted, whichever happens first.
    boolean isTerminated = pool.awaitTermination(timeout, timeUnit);
    System.out.println("isTerminated()=" + isTerminated);
    if (!isTerminated) {
        System.out.println("Calling shutdownNow()...");
        List<Runnable> list = pool.shutdownNow();
        System.out.println(list.size() + " threads running");
        isTerminated = pool.awaitTermination(timeout, timeUnit);
        if (!isTerminated) {
            System.out.println("Some threads are still running");
        }
        System.out.println("Exiting");
    }
} catch (InterruptedException ex) {
    ex.printStackTrace();
}
```

尝试在`pool.shutdown()`之后向池中添加另一个线程**会生成**`java.util.concurrent.RejectedExecutionException`。

执行上述代码会产生以下结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/bb120bfc-ee6f-4e8b-aac6-2f1186ac8b4e.png)

注意前面屏幕截图中的`Thread.currentThread().isInterrupted()=false`消息。线程被中断。我们知道是因为线程得到了`InterruptedException`。那么为什么`isInterrupted()`方法返回`false`？这是因为线程状态在收到中断消息后立即被清除。我们现在提到它是因为它是一些程序员错误的来源。例如，如果主线程监视`MyRunnable`线程并对其调用`isInterrupted()`，则返回值将为`false`，这可能会在线程中断后产生误导。

因此，在另一个线程可能正在监视`MyRunnable`线程的情况下，`MyRunnable`的实现必须更改为以下内容（注意在`catch`块中如何调用`interrupt()`方法）：

```java
class MyRunnable implements Runnable {
   private String name;
   public MyRunnable(String name) {
      this.name = name;
   }
   public void run() {
      try {
         while (true) {
             System.out.println(this.name + " is working...");
             TimeUnit.SECONDS.sleep(1);
         }
      } catch (InterruptedException e) {
         Thread.currentThread().interrupt();
         System.out.println(this.name + " was interrupted\n" +
           this.name + " Thread.currentThread().isInterrupted()="
                       + Thread.currentThread().isInterrupted());
      }
   }
}
```

现在，如果我们再次使用相同的`ExecutorService`池运行这个线程，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e9056f10-186e-4093-aa52-06100044952a.png)

如您所见，现在由`isInterrupted()`方法返回的值是`true`，并与发生的事情相对应。公平地说，在许多应用中，一旦线程中断，就不会再次检查其状态。但是设置正确的状态是一种很好的做法，特别是在您不是创建线程的更高级别代码的作者的情况下。

在我们的示例中，我们使用了一个缓存线程池，它根据需要创建一个新线程，或者，如果可用的话，重用已经使用过的线程，但是该线程完成了它的任务并返回到池中进行新的分配。我们不担心创建太多线程，因为我们的演示应用最多有三个工作线程，而且它们的生命周期非常短。

但是，如果应用可能需要的工作线程没有固定的限制，或者没有很好的方法来预测线程可能需要多少内存或可以执行多长时间，那么设置工作线程计数的上限可以防止应用性能的意外降级、内存不足或资源耗尽工作线程使用的任何其他资源。如果线程行为极不可预测，那么单线程池可能是唯一的解决方案，可以选择使用自定义线程池执行器。但在大多数情况下，固定大小的线程池执行器是应用需求和代码复杂性之间的一个很好的实际折衷方案（在本节前面，我们列出了由`Executors`工厂类创建的所有可能的池类型）

将池的大小设置得过低可能会剥夺应用有效利用可用资源的机会。因此，在选择池大小之前，建议花一些时间监视应用，以确定应用行为的特性。事实上，为了适应和利用代码或执行环境中发生的更改，必须在应用的整个生命周期中重复“循环部署监视调整”。

考虑的第一个特征是系统中 CPU 的数量，因此线程池的大小至少可以与 CPU 的计数一样大。然后，您可以监视应用，查看每个线程占用 CPU 的时间以及占用其他资源（如 I/O 操作）的时间。如果不使用 CPU 所花费的时间与线程的总执行时间相当，则可以按以下比率增加池大小：不使用 CPU 的时间除以总执行时间。但这是在另一个资源（磁盘或数据库）不是线程间争用的主题的情况下。如果是后者，那么您可以使用该资源而不是 CPU 作为描述因子。

假设应用的工作线程不太大或执行时间不太长，并且属于典型工作线程的主流群体，这些线程在合理的短时间内完成其任务，通过将所需响应时间与线程使用 CPU 或其他最具争议的资源的时间之比（四舍五入）相加，可以增加池大小。这意味着，在期望的响应时间相同的情况下，线程使用 CPU 或另一个并发访问的资源的次数越少，池的大小就应该越大。如果有争议的资源有自己的能力来改进并发访问（如数据库中的连接池），请首先考虑使用该特性。

如果所需的同时运行的线程数在不同的情况下在运行时发生变化，则可以使池大小成为动态的，并使用新的大小创建一个新池（在所有线程完成后关闭旧池）。添加或删除可用资源后，可能还需要重新计算新池的大小。例如，您可以使用`Runtime.getRuntime().availableProcessors()`根据可用 CPU 的当前计数以编程方式调整池大小。

如果 JDK 附带的现成线程池执行器实现都不能满足特定应用的需要，那么在从头开始编写线程管理代码之前，请先尝试使用`java.util.concurrent.ThreadPoolExecutor`类。它有几个重载构造器。

为了让您了解它的功能，以下是具有最多选项的构造器：

```java
ThreadPoolExecutor (int corePoolSize, 
                    int maximumPoolSize, 
                    long keepAliveTime, 
                    TimeUnit unit, 
                    BlockingQueue<Runnable> workQueue, 
                    ThreadFactory threadFactory, 
                    RejectedExecutionHandler handler)
```

上述构造器的参数如下：

*   `corePoolSize`是池中要保留的线程数，即使它们是空闲的，除非用`true`值调用`allowCoreThreadTimeOut(boolean value)`方法
*   `maximumPoolSize`是池中允许的最大线程数
*   `keepAliveTime`：当线程数大于核心时，这是多余空闲线程等待新任务结束前的最长时间
*   `unit`是`keepAliveTime`参数的时间单位
*   `workQueue`是用于在任务执行之前保存任务的队列；此队列将只保存由`execute()`方法提交的`Runnable`对象
*   `threadFactory`是执行器创建新线程时使用的工厂
*   `handler`是由于达到线程边界和队列容量而阻止执行时要使用的处理器

在创建了`ThreadPoolExecutor`类的对象之后，除了`workQueue`之外，前面的每个构造器参数也可以通过相应的 setter 进行设置，从而允许对现有池特性进行更大的灵活性和动态调整。

# 从线程获取结果

在我们的示例中，到目前为止，我们使用了`ExecutorService`接口的`execute()`方法来启动线程。实际上，这个方法来自于`Executor`基本接口。同时，`ExecutorService`接口还有其他方法（在前面的“使用线程池”一节中列出）可以启动线程并返回线程执行结果。

带回线程执行结果的对象是类型`Future`——一个具有以下方法的接口：

*   `V get()`：阻塞直到线程结束；返回结果（*如果可用*）
*   `V get(long timeout, TimeUnit unit)`：阻塞直到线程完成或提供的超时结束；返回结果（如果可用）
*   `boolean isDone()`：线程结束返回`true`
*   `boolean cancel(boolean mayInterruptIfRunning)`：尝试取消线程的执行；如果成功则返回`true`；如果调用方法时线程已经正常完成，则返回`false`
*   `boolean isCancelled()`：如果线程执行在正常完成之前被取消，则返回`true`

`get()`方法说明中的备注*如果可用*意味着，即使调用无参数的`get()`方法，结果原则上也不总是可用的。这完全取决于生成`Future`对象的方法。以下是返回`Future`对象的`ExecutorService`的所有方法的列表：

*   `Future<?> submit(Runnable task)`：提交线程（任务）执行，返回一个代表任务的`Future`；返回的`Future`对象的`get()`方法返回`null`；例如，我们使用只工作 100 毫秒的`MyRunnable`类：

```java
class MyRunnable implements Runnable {
   private String name;
   public MyRunnable(String name) {
     this.name = name;
   }
   public void run() {
     try {
         System.out.println(this.name + " is working...");
         TimeUnit.MILLISECONDS.sleep(100);
         System.out.println(this.name + " is done");
     } catch (InterruptedException e) {
         Thread.currentThread().interrupt();
         System.out.println(this.name + " was interrupted\n" +
           this.name + " Thread.currentThread().isInterrupted()="
                       + Thread.currentThread().isInterrupted());
     }
   }
}
```

并且，根据上一节的代码示例，让我们创建一个关闭池并在必要时终止所有线程的方法：

```java
void shutdownAndTerminate(ExecutorService pool){
   try {
      long timeout = 100;
      TimeUnit timeUnit = TimeUnit.MILLISECONDS;
      System.out.println("Waiting all threads completion for "
                             + timeout + " " + timeUnit + "...");
      //Blocks until timeout or all threads complete execution, 
      //  or the current thread is interrupted, 
      //  whichever happens first.
      boolean isTerminated = 
                        pool.awaitTermination(timeout, timeUnit);
      System.out.println("isTerminated()=" + isTerminated);
      if (!isTerminated) {
          System.out.println("Calling shutdownNow()...");
          List<Runnable> list = pool.shutdownNow();
          System.out.println(list.size() + " threads running");
          isTerminated = pool.awaitTermination(timeout, timeUnit);
          if (!isTerminated) {
             System.out.println("Some threads are still running");
          }
          System.out.println("Exiting");
      }
   } catch (InterruptedException ex) {
      ex.printStackTrace();
   }
}
```

我们将在`finally`块中使用前面的`shutdownAndTerminate()`方法，以确保没有留下任何正在运行的线程。下面是我们要执行的代码：

```java
ExecutorService pool = Executors.newSingleThreadExecutor();

Future future = pool.submit(new MyRunnable("One"));
System.out.println(future.isDone());         //prints: false
System.out.println(future.isCancelled());    //prints: false
try{
    System.out.println(future.get());        //prints: null
    System.out.println(future.isDone());     //prints: true
    System.out.println(future.isCancelled());//prints: false
} catch (Exception ex){
    ex.printStackTrace();
} finally {
    shutdownAndTerminate(pool);
}
```

您可以在这个屏幕截图上看到这个代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d5dd0d24-60a9-4ea3-ae48-0a6830865883.png)

正如所料，`Future`对象的`get()`方法返回`null`，因为`Runnable`的`run()`方法不返回任何内容。从返回的`Future`中我们只能得到任务是否完成的信息。

*   `Future<T> submit(Runnable task, T result)`：提交线程（任务）执行，返回一个`Future`代表任务，其中包含提供的`result`，例如，我们将使用下面的类作为结果：

```java
class Result {
    private String name;
    private double result;
    public Result(String name, double result) {
        this.name = name;
        this.result = result;
    }
    @Override
    public String toString() {
        return "Result{name=" + name +
                ", result=" + result + "}";
    }
}
```

下面的代码演示了`submit()`方法返回的`Future`如何返回默认结果：

```java
ExecutorService pool = Executors.newSingleThreadExecutor();
Future<Result> future = pool.submit(new MyRunnable("Two"), 
                                        new Result("Two", 42.));
System.out.println(future.isDone());          //prints: false
System.out.println(future.isCancelled());     //prints: false
try{
    System.out.println(future.get());         //prints: null
    System.out.println(future.isDone());      //prints: true
    System.out.println(future.isCancelled()); //prints: false
} catch (Exception ex){
    ex.printStackTrace();
} finally {
    shutdownAndTerminate(pool);
}
```

如果执行前面的代码，输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/86bb26c0-972a-4cb1-af6e-8db3ae6227aa.png)

正如所料，`Future`的`get()`方法返回作为参数传入的对象。

*   `Future<T> submit(Callable<T> task)`：提交线程（任务）执行，返回一个`Future`，表示任务，返回结果由`Callable`接口的`V call()`方法生成并返回，即`Callable`方法接口唯一的一个方法。例如：

```java
class MyCallable implements Callable {
   private String name;
   public MyCallable(String name) {
        this.name = name;
   }
   public Result call() {
      try {
         System.out.println(this.name + " is working...");
         TimeUnit.MILLISECONDS.sleep(100);
         System.out.println(this.name + " is done");
         return new Result(name, 42.42);
      } catch (InterruptedException e) {
         Thread.currentThread().interrupt();
         System.out.println(this.name + " was interrupted\n" +
           this.name + " Thread.currentThread().isInterrupted()="
                       + Thread.currentThread().isInterrupted());
      }
      return null;
   }
```

上述代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/10490b6b-1acc-4195-bb95-37c3127cd99f.png)

如您所见，`Future`的`get()`方法返回由`MyCallable`类的`call()`方法生成的值

*   `List<Future<T>> invokeAll(Collection<Callable<T>> tasks)`：执行所提供集合的所有`Callable`任务；返回`Futures`列表，其中包含已执行`Callable`对象生成的结果
*   `List<Future<T>> invokeAll(Collection<Callable<T>>`：执行所提供集合的所有`Callable`任务；返回`Futures`列表，其中包含已执行的`Callable`对象产生的结果或超时过期，以先发生的为准
*   `T invokeAny(Collection<Callable<T>> tasks)`：执行所提供集合的所有`Callable`任务，如果有，返回一个已成功完成的任务的结果（即不抛出异常）
*   `T invokeAny(Collection<Callable<T>> tasks, long timeout, TimeUnit unit)`：执行所提供集合的所有`Callable`任务；如果在所提供的超时过期之前有一个任务成功完成，则返回该任务的结果（即不抛出异常）

如您所见，有许多方法可以从线程中获得结果。选择的方法取决于应用的特定需要。

# 并行与并发处理

当我们听到工作线程同时执行时，我们会自动地假设它们实际上做了编程所要并行执行的事情。只有在我们深入研究了这样一个系统之后，我们才意识到，只有当线程分别由不同的 CPU 执行时，这种并行处理才是可能的。否则，它们的时间共享相同的处理能力。我们认为他们在同一时间工作，只是因为他们使用的时间间隔非常短，只是我们在日常生活中使用的时间单位的一小部分。当线程共享同一个资源时，在计算机科学中，我们说它们同时进行。

# 同一资源的并发修改

两个或多个线程在其他线程读取同一值的同时修改该值，这是对并发访问问题之一的最一般描述。更微妙的问题包括**线程干扰**和**内存一致性**错误，这两种错误都会在看似良性的代码片段中产生意想不到的结果。在本节中，我们将演示此类情况以及避免此类情况的方法。

乍一看，解决方案似乎非常简单：一次只允许一个线程修改/访问资源，就这样。但是如果访问需要很长时间，就会产生一个瓶颈，可能会消除多线程并行工作的优势。或者，如果一个线程在等待访问另一个资源时阻塞了对一个资源的访问，而第二个线程在等待访问第一个资源时阻塞了对第二个资源的访问，则会产生一个称为**死锁**的问题。这是程序员在使用多线程时可能遇到的挑战的两个非常简单的例子。

首先，我们将重现由同一值的并发修改引起的问题。我们创建一个`Calculator`接口：

```java
interface Calculator {
    String getDescription();
    double calculate(int i);
}
```

我们将使用`getDescription()`方法来捕获实现的描述。以下是第一个实现：

```java
class CalculatorNoSync implements Calculator{
    private double prop;
    private String description = "Without synchronization";
    public String getDescription(){ return description; }
    public double calculate(int i){
        try {
            this.prop = 2.0 * i;
            TimeUnit.MILLISECONDS.sleep(i);
            return Math.sqrt(this.prop);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Calculator was interrupted");
        }
        return 0.0;
    }
}
```

如您所见，`calculate()`方法将一个新值赋给`prop`属性，然后执行其他操作（我们通过调用`sleep()`方法来模拟它），然后计算分配给`prop`属性的值的平方根。`"Without synchronization"`描述描述了在没有任何协调或**同步**的情况下，每次调用`calculate()`方法时`prop`属性的值都在变化，当线程同时修改同一资源时，在线程之间进行协调时调用。

我们现在将在两个线程之间共享这个对象，这意味着`prop`属性将被同时更新和使用。因此，围绕`prop`属性进行某种线程同步是必要的，但我们已经决定，我们的第一个实现不会这样做。

下面是我们在执行我们要创建的每个`Calculator`实现时要使用的方法：

```java
void invokeAllCallables(Calculator c){
    System.out.println("\n" + c.getDescription() + ":");
    ExecutorService pool = Executors.newFixedThreadPool(2);
    List<Callable<Result>> tasks = List.of(new MyCallable("One", c), 
                                           new MyCallable("Two", c));
    try{
        List<Future<Result>> futures = pool.invokeAll(tasks);
        List<Result> results = new ArrayList<>();
        while (results.size() < futures.size()){
            TimeUnit.MILLISECONDS.sleep(5);
            for(Future future: futures){
                if(future.isDone()){
                    results.add((Result)future.get());
                }
            }
        }
        for(Result result: results){
            System.out.println(result);
        }
    } catch (Exception ex){
        ex.printStackTrace();
    } finally {
        shutdownAndTerminate(pool);
    }
}
```

如您所见，前面的方法执行以下操作：

*   打印传入的`Calculator`实现的描述
*   为两个线程创建固定大小的池
*   创建两个`Callable`任务的列表，这些任务是以下`MyCallable`类的对象：

```java
class MyCallable implements Callable<Result> {
    private String name;
    private Calculator calculator;
    public MyCallable(String name, Calculator calculator) {
        this.name = name;
        this.calculator = calculator;
    }
    public Result call() {
        double sum = 0.0;
        for(int i = 1; i < 20; i++){
            sum += calculator.calculate(i);
        }
        return new Result(name, sum);
    }
}
```

*   任务列表传入池的`invokeAll()`方法，每个任务通过调用`call()`方法来执行；每个`call()`方法将传入的`Calculator`对象的`calculate()`方法应用到从 1 到 20 的 19 个数字中的每一个，并对结果进行汇总；结果和与`MyCallable`对象的名称一起返回到`Result`对象中

*   每个`Result`对象最终返回到`Future`对象中
*   然后`invokeAllCallables()`方法对`Future`对象列表进行迭代，检查每个对象是否完成任务；当任务完成时，结果被添加到`List<Result> results`中
*   所有任务完成后，`invokeAllCallables()`方法将打印`List<Result> results`的所有元素并终止池

以下是我们运行`invokeAllCallables(new CalculatorNoSync())`得到的结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/209c5910-690f-41fb-990d-883b3f565d12.png)

每次运行前面的代码时，实际的数字都略有不同，但是任务`One`的结果永远不会等于任务`Two`的结果，这是因为在设置`prop`字段的值和在`calculate()`方法中返回其平方根之间的时间段内，另一个线程设法分配了不同的值至`prop`。这是螺纹干涉的情况。

有几种方法可以解决这个问题。我们从一个原子变量开始，以此实现对属性的线程安全并发访问。然后我们还将演示两种线程同步方法。

# 原子变量

**原子变量**是一个仅当其当前值与期望值匹配时才能更新的变量。在我们的例子中，这意味着如果`prop`值已被另一个线程更改，则不应使用它。

`java.util.concurrent.atomic`包有十几个类支持这种逻辑：`AtomicBoolean`、`AtomicInteger`、`AtomicReference`和`AtomicIntegerArray`，举几个例子。这些类中的每一个都有许多方法可用于不同的同步需求。[查看这些类的在线 API 文档](https://docs.oracle.com/en/java/javase/12/docs/api/java.base/java/util/concurrent/atomic/package-summary.html)。在演示中，我们将仅使用其中的两种方法：

*   `V get()`：返回当前值
*   `boolean compareAndSet(V expectedValue, V newValue)`：如果当前值等于运算符（`==`），则将值设置为`newValue`；如果成功，则返回`true`，如果实际值不等于期望值，则返回`false`

下面是如何使用`AtomicReference`类来解决线程的干扰问题，同时使用这两种方法访问`Calculator`对象的`prop`属性：

```java
class CalculatorAtomicRef implements Calculator {
    private AtomicReference<Double> prop = new AtomicReference<>(0.0);
    private String description = "Using AtomicReference";
    public String getDescription(){ return description; }
    public double calculate(int i){
        try {
            Double currentValue = prop.get();
            TimeUnit.MILLISECONDS.sleep(i);
            boolean b = this.prop.compareAndSet(currentValue, 2.0 * i);
            //System.out.println(b);    //prints: true for one thread 
                                        //and false for another thread
            return Math.sqrt(this.prop.get());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Calculator was interrupted");
        }
        return 0.0;
    }
}
```

如您所见，前面的代码确保在线程睡眠时，`prop`属性的`currentValue`不会更改。下面是我们运行`invokeAllCallables(new CalculatorAtomicRef())`时产生的消息截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/8202d85b-72aa-4669-b2a0-70556c065507.png)

现在线程产生的结果是相同的。

`java.util.concurrent`包的以下类也提供同步支持：

*   `Semaphore`：限制可以访问资源的线程数
*   `CountDownLatch`：允许一个或多个线程等待，直到在其他线程中执行的一组操作完成
*   `CyclicBarrier`：允许一组线程等待彼此到达公共屏障点
*   `Phaser`：提供了一种更灵活的屏障形式，可用于控制多线程之间的阶段计算
*   `Exchanger`：允许两个线程在一个集合点交换对象，在多个管道设计中非常有用

# 同步方法

另一种解决问题的方法是使用同步方法。这里是`Calculator`接口的另一个实现，它使用这种解决线程干扰的方法：

```java
class CalculatorSyncMethod implements Calculator {
    private double prop;
    private String description = "Using synchronized method";
    public String getDescription(){ return description; }
    synchronized public double calculate(int i){
        try {
            this.prop = 2.0 * i;
            TimeUnit.MILLISECONDS.sleep(i);
            return Math.sqrt(this.prop);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Calculator was interrupted");
        }
        return 0.0;
    }
}
```

我们刚刚在`calculate()`方法前面添加了`synchronized`关键字。现在，如果我们运行`invokeAllCallables(new CalculatorSyncMethod())`，两个线程的结果总是一样的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/7764236d-0565-4849-b880-a27ed306dff6.png)

这是因为在当前线程（已经进入同步方法的线程）退出同步方法之前，另一个线程无法进入同步方法。这可能是最简单的解决方案，但如果该方法需要很长时间才能执行，则此方法可能会导致性能下降。在这种情况下，可以使用同步块，它在一个原子操作中只包装几行代码。

# 同步块

以下是用于解决线程干扰问题的同步块的示例：

```java
class CalculatorSyncBlock implements Calculator {
    private double prop;
    private String description = "Using synchronized block";
    public String getDescription(){
        return description;
    }
    public double calculate(int i){
        try {
            //there may be some other code here
            synchronized (this) {
                this.prop = 2.0 * i;
                TimeUnit.MILLISECONDS.sleep(i);
                return Math.sqrt(this.prop);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Calculator was interrupted");
        }
        return 0.0;
    }
}
```

如您所见，`synchronized`块在`this`对象上获取一个锁，该锁由两个线程共享，并且只有在线程退出块之后才释放它。在我们的演示代码中，该块覆盖了该方法的所有代码，因此在性能上没有差异。但是想象一下这个方法中有更多的代码（我们将位置注释为`there may be some other code here`。如果是这样的话，代码的同步部分就更小，因此成为瓶颈的机会就更少。

如果我们运行`invokeAllCallables(new CalculatorSyncBlock())`，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/896e24c1-8eac-4287-ba0b-a24468e01158.png)

如您所见，结果与前两个示例完全相同，在`java.util.concurrent.locks`包中组装了针对不同需求和不同行为的不同类型的锁

Java 中的每个对象都从基对象继承了`wait()`、`notify()`和`notifyAll()`方法。这些方法还可以用来控制线程的行为及其对锁的访问。

# 并发集合

解决并发性的另一种方法是使用来自`java.util.concurrent`包的线程安全集合，阅读 [Javadoc](https://docs.oracle.com/en/java/javase/12/docs/api/index.html) 查看您的申请是否接受托收限制。以下是这些托收清单和一些建议：

*   `ConcurrentHashMap<K,V>`：支持检索的完全并发和更新的高期望并发，当并发要求很高，需要允许对写操作进行锁定但不需要锁定元素时使用。
*   `ConcurrentLinkedQueue<E>`：基于链接节点的线程安全队列，采用高效的非阻塞算法。
*   `ConcurrentLinkedDeque<E>`：基于链接节点的并发队列，当多个线程共享对一个公共集合的访问时，`ConcurrentLinkedQueque`和`ConcurrentLinkedDeque`都是合适的选择。
*   `ConcurrentSkipListMap<K,V>`：并发`ConcurrentNavigableMap`接口实现。
*   `ConcurrentSkipListSet<E>`：基于`ConcurrentSkipListMap`的并发`NavigableSet`实现。`ConcurrentSkipListSet`和`ConcurrentSkipListMap`类，根据 *Javadoc*，对包含、添加和删除操作及其变体，提供预期平均`O(logn)`时间成本。升序视图及其迭代器的速度比降序视图快；当您需要按特定顺序快速遍历元素时，请使用它们。
*   `CopyOnWriteArrayList<E>`：一种线程安全的`ArrayList`变体，所有的修改操作（`add`、`set`等）都是通过对底层数组进行一个新的拷贝来实现的；根据 *Javadoc*，`CopyOnWriteArrayList`类通常成本太高，但当遍历操作的数量远远超过修改时，它可能比其他方法更有效，当您不能或不想同步遍历，但需要排除并发线程之间的干扰时，它会很有用；当您不需要在不同位置添加新元素且不需要排序时，使用它；否则，使用`ConcurrentSkipListSet`。
*   `CopyOnWriteArraySet<E>`：所有操作都使用内部`CopyOnWriteArrayList`的集合。

*   `PriorityBlockingQueue`：当一个自然的顺序是可以接受的，并且您需要快速向尾部添加元素和快速从队列头部移除元素时，这是一个更好的选择；**阻塞**是指队列在检索元素时等待变为非空，在存储元素时等待队列中的空间变为可用。
*   `ArrayBlockingQueue`、`LinkedBlockingQueue`和`LinkedBlockingDeque`具有固定大小（有界）；其他队列是无界的。

使用这些和指南中类似的特性和建议，但是在实现功能之前和之后执行全面的测试和性能度量。为了演示其中的一些收集功能，让我们使用`CopyOnWriteArrayList<E>`。首先，让我们看看当我们试图同时修改它时，`ArrayList`是如何工作的：

```java
List<String> list = Arrays.asList("One", "Two");
System.out.println(list);
try {
    for (String e : list) {
        System.out.println(e);  //prints: One
        list.add("Three");      //UnsupportedOperationException
    }
} catch (Exception ex) {
    ex.printStackTrace();
}
System.out.println(list);       //prints: [One, Two]

```

正如预期的那样，在对列表进行迭代时尝试修改列表会生成一个异常，并且该列表保持不变。

现在，让我们在同样的情况下使用`CopyOnWriteArrayList<E>`：

```java
List<String> list = 
             new CopyOnWriteArrayList<>(Arrays.asList("One", "Two"));
System.out.println(list);
try {
    for (String e : list) {
        System.out.print(e + " "); //prints: One Two
        list.add("Three");         //adds element Three
    }
} catch (Exception ex) {
    ex.printStackTrace();
}
System.out.println("\n" + list);   //prints: [One, Two, Three, Three]

```

此代码生成的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c026c614-aa3c-4931-a52b-2941ed12bdae.png)

如您所见，该列表已被修改，没有异常，但不是当前迭代的副本。如果需要，您可以使用这种行为。

# 内存一致性错误

在多线程环境中，内存一致性错误可能有多种形式和原因。它们在`java.util.concurrent`包的 *Javadoc* 中有很好的讨论。在这里，我们将只提到最常见的情况，这是由于缺乏能见度造成的。

当一个线程更改属性值时，另一个线程可能不会立即看到更改，并且不能对原始类型使用`synchronized`关键字。在这种情况下，可以考虑对属性使用`volatile`关键字；它保证了不同线程之间的读/写可见性。

并发问题不容易解决。这就是为什么现在越来越多的开发人员采取更激进的方法也就不足为奇了。他们更喜欢在一组无状态操作中处理数据，而不是管理对象状态。我们将在第 13 章、“函数式编程”和第 14 章、“Java 标准流”中看到这些代码的示例。Java 和许多现代语言以及计算机系统似乎正朝着这个方向发展。

# 总结

在这一章中，我们讨论了多线程处理，以及如何组织它，以及如何避免由于并发修改共享资源而导致的不可预知的结果。我们向读者展示了如何创建线程并使用线程池执行它们。我们还演示了如何从成功完成的线程中提取结果，并讨论了并行处理和并发处理之间的区别

在下一章中，我们将让读者更深入地了解 JVM 及其结构和进程，并详细讨论防止内存溢出的垃圾收集过程。在本章的最后，读者将了解什么构成了 Java 应用执行、JVM 中的 Java 进程、垃圾收集以及 JVM 通常是如何工作的。

# 测验

1.  选择所有正确的语句：
    1.  JVM 进程可以有主线程
    2.  主线程是主进程
    3.  一个进程可以启动另一个进程
    4.  一个线程可以启动另一个线程

2.  选择所有正确的语句：
    1.  守护进程是一个用户线程
    2.  守护线程在第一个用户线程完成后退出
    3.  守护线程在最后一个用户线程完成后退出
    4.  主线程是一个用户线程

3.  选择所有正确的语句：
    1.  所有线程都有`java.lang.Thread`作为基类
    2.  所有线程扩展`java.lang.Thread`
    3.  所有线程实现`java.lang.Thread`
    4.  守护线程不扩展`java.lang.Thread`

4.  选择所有正确的语句：
    1.  任何类都可以实现`Runnable`接口
    2.  `Runnable`接口实现是一个线程
    3.  `Runnable`接口实现由线程使用
    4.  `Runnable`接口只有一个方法

5.  选择所有正确的语句：
    1.  线程名称必须是唯一的
    2.  线程 ID 自动生成
    3.  可以设置线程名称
    4.  可以设置线程优先级

6.  选择所有正确的语句：
    1.  线程池执行线程
    2.  线程池重用线程
    3.  某些线程池可以有固定的线程数
    4.  某些线程池可以有无限个线程

7.  选择所有正确的语句：
    1.  `Future`对象是从线程获取结果的唯一方法
    2.  `Callable`对象是从线程获取结果的唯一方法
    3.  `Callable`对象允许从线程获取结果
    4.  `Future`对象表示线程

8.  选择所有正确的语句：
    1.  并发处理可以并行进行
    2.  只有在计算机上有几个 CPU 或内核的情况下，才能进行并行处理
    3.  并行处理是并发处理
    4.  没有多个 CPU，就不可能进行并发处理

9.  选择所有正确的语句：
    1.  并发修改总是导致错误的结果
    2.  原子变量保护属性不受并发修改
    3.  原子变量保护属性不受线程干扰
    4.  原子变量是保护属性不受并发修改的唯一方法

10.  选择所有正确的语句：
    1.  同步方法是避免线程干扰的最佳方法
    2.  `synchronized`关键字可以应用于任何方法
    3.  同步方法可能会造成处理瓶颈
    4.  同步方法易于实现

11.  选择所有正确的语句：
    1.  同步块只有在小于方法时才有意义
    2.  同步块需要共享锁
    3.  每个 Java 对象都可以提供一个锁
    4.  同步块是避免线程干扰的最佳方法

12.  选择所有正确的语句：
    1.  首选使用并发集合，而不是使用非并发集合
    2.  使用并发集合会产生一些开销
    3.  不是每个并发集合都适合每个并发处理场景
    4.  可以通过调用`Collections.makeConcurrent()`方法来创建并发集合

13.  选择所有正确的语句：
    1.  避免内存一致性错误的唯一方法是声明`volatile`变量
    2.  使用`volatile`关键字可以确保值在所有线程中的变化的可见性
    3.  避免并发的方法之一是避免任何状态管理
    4.  无状态工具方法不能有并发问题