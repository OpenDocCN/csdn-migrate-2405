# Java 编程问题（五）

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 七、Java 反射类、接口、构造器、方法和字段

> 原文：[Java Coding Problems](https://libgen.rs/book/index.php?md5=3280024C263466704C8F7525E5BB6AAE)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)
> 
> 贡献者：[飞龙](https://github.com/wizardforcel)
> 
> 本文来自[【ApacheCN Java 译文集】](https://github.com/apachecn/apachecn-java-zh)，自豪地采用[谷歌翻译](https://translate.google.cn/)。

本章包括涉及 Java 反射 API 的 17 个问题。从经典主题，如检查和实例化 Java 工件（例如，模块、包、类、接口、超类、构造器、方法、注解和数组），到*合成*和*桥接*构造或基于嵌套的访问控制（JDK11），本章详细介绍了 Java 反射 API。在本章结束时，Java 反射 API 将不会有任何秘密未被发现，您将准备好向您的同事展示反射可以做什么。

# 问题

使用以下问题来测试您的 Java 反射 API 编程能力。我强烈建议您在使用解决方案和下载示例程序之前，先尝试一下每个问题：

149.  **检查包**：编写几个检查 Java 包的示例（例如名称、类列表等）。
150.  **检查类和超类**：写几个检查类和超类的例子（例如，通过类名、修饰符、实现的接口、构造器、方法和字段获取`Class`）。
151.  **通过反射构造器来实例化**：编写通过反射创建实例的程序。

152.  **获取接收器类型的注解**：编写获取接收器类型注解的程序。
153.  **获得合成和桥接结构**：编写一个程序，通过反射获得*合成*和*桥接*结构。
154.  **检查变量个数**：编写一个程序，检查一个方法是否获得变量个数。
155.  **检查默认方法**：编写程序检查方法是否为`default`。
156.  **基于嵌套的反射访问控制**：编写一个程序，通过反射提供对基于嵌套的结构的访问。
157.  **获取器和设置器的反射**：写几个例子，通过反射调用获取器和设置器。另外，编写一个程序，通过反射生成获取器和设置器。
158.  **反射注解**：写几个通过反射获取不同种类注解的例子。
159.  **调用实例方法**：编写一个程序，通过反射调用实例方法。
160.  **获取`static`方法**：编写一个程序，对给定类的`static`方法进行分组，并通过反射调用其中一个方法。
161.  **获取方法、字段和异常的泛型类型**：编写一个程序，通过反射获取给定方法、字段和异常的泛型类型。
162.  **获取公共和私有字段**：编写一个程序，通过反射获取给定类的`public`和`private`字段。
163.  **使用数组**：写几个通过反射使用数组的例子。
164.  **检查模块**：写几个通过反射检查 Java9 模块的例子。
165.  **动态代理**：编写依赖*动态代理*的程序，统计给定接口的方法调用次数。

# 解决方案

以下各节介绍上述问题的解决方案。记住，通常没有一个正确的方法来解决一个特定的问题。另外，请记住，这里显示的解释只包括解决问题所需的最有趣和最重要的细节。您可以从[这个页面](https://github.com/PacktPublishing/Java-Coding-Problems)下载示例解决方案以查看更多详细信息并尝试程序。

# 149 检查包

当我们需要获取有关特定包的信息时，`java.lang.Package`类是我们的主要关注点。使用这个类，我们可以找到包的名称、实现这个包的供应商、它的标题、包的版本等等。

此类通常用于查找包含特定类的包的名称。例如，`Integer`类的包名可以容易地获得如下：

```java
Class clazz = Class.forName("java.lang.Integer");
Package packageOfClazz = clazz.getPackage();

// java.lang
String packageNameOfClazz = packageOfClazz.getName();
```

现在，我们来查找`File`类的包名：

```java
File file = new File(".");
Package packageOfFile = file.getClass().getPackage();

// java.io
String packageNameOfFile = packageOfFile.getName();
```

如果我们试图找到当前类的包名，那么我们可以依赖于`this.getClass().getPackage().getName()`。这在非静态环境中工作。

但是如果我们只想快速列出当前类装入器的所有包，那么我们可以依赖`getPackages()`方法，如下所示：

```java
Package[] packages = Package.getPackages();
```

基于`getPackages()`方法，我们可以列出调用者的类装入器定义的所有包，以及以给定前缀开头的祖先包，如下所示：

```java
public static List<String> fetchPackagesByPrefix(String prefix) {

  return Arrays.stream(Package.getPackages())
    .map(Package::getName)
    .filter(n -> n.startsWith(prefix))
    .collect(Collectors.toList());
}
```

如果这个方法存在于一个名为`Packages`的实用类中，那么我们可以如下调用它：

```java
List<String> packagesSamePrefix 
  = Packages.fetchPackagesByPrefix("java.util");
```

您将看到类似于以下内容的输出：

```java
java.util.function, java.util.jar, java.util.concurrent.locks,
java.util.spi, java.util.logging, ...
```

有时，我们只想在系统类加载器中列出一个包的所有类。让我们看看怎么做。

# 获取包的类

例如，我们可能希望列出当前应用的一个包中的类（例如，`modern.challenge`包）或编译时库中的一个包中的类（例如，`commons-lang-2.4.jar`。

类被包装在可以在 Jar 中存档的包中，尽管它们不必这样。为了涵盖这两种情况，我们需要发现给定的包是否存在于 JAR 中。我们可以通过`ClassLoader.getSystemClassLoader().getResource(package_path)`加载资源并检查返回的资源 URL 来完成。如果包不在 JAR 中，那么资源将是以`file:`方案开始的 URL，如下面的示例（我们使用的是`modern.challenge`）：

```java
file:/D:/Java%20Modern%20Challenge/Code/Chapter%207/Inspect%20packages/build/classes/modern/challenge
```

但是如果包在 JAR 中（例如，`org.apache.commons.lang3.builder`，那么 URL 将以`jar:`方案开始，如下例所示：

```java
jar:file:/D:/.../commons-lang3-3.9.jar!/org/apache/commons/lang3/builder
```

如果我们考虑到来自 JAR 的包的资源以`jar:`前缀开头，那么我们可以编写一个方法来区分它们，如下所示：

```java
private static final String JAR_PREFIX = "jar:";

public static List<Class<?>> fetchClassesFromPackage(
    String packageName) throws URISyntaxException, IOException {

  List<Class<?>> classes = new ArrayList<>();
  String packagePath = packageName.replace('.', '/');

  URL resource = ClassLoader
    .getSystemClassLoader().getResource(packagePath);

  if (resource != null) {
    if (resource.toString().startsWith(JAR_PREFIX)) {
      classes.addAll(fetchClassesFromJar(resource, packageName));
    } else {
      File file = new File(resource.toURI());
      classes.addAll(fetchClassesFromDirectory(file, packageName));
    }
  } else {
    throw new RuntimeException("Resource not found for package: " 
      + packageName);
  }

  return classes;
}
```

因此，如果给定的包在 JAR 中，那么我们调用另一个辅助方法`fetchClassesFromJar()`；否则，我们调用这个辅助方法`fetchClassesFromDirectory()`。顾名思义，这些助手知道如何从 JAR 或目录中提取给定包的类。

主要来说，这两种方法只是一些用来识别具有`.class`扩展名的文件的*意大利面*代码片段。每个类都通过`Class.forName()`来确保返回的是`Class`，而不是`String`。这两种方法在本书附带的代码中都可用。

如何列出不在系统类加载器中的包中的类，例如，外部 JAR 中的包？实现这一点的便捷方法依赖于`URLClassLoader`。此类用于从引用 JAR 文件和目录的 URL 搜索路径加载类和资源。我们将只处理 Jar，但对目录也这样做非常简单。

因此，根据给定的路径，我们需要获取所有 Jar 并将它们返回为`URL[]`（这个数组需要定义`URLClassLoader`。例如，我们可以依赖于`Files.find()`方法遍历给定的路径并提取所有 Jar，如下所示：

```java
public static URL[] fetchJarsUrlsFromClasspath(Path classpath)
    throws IOException {

  List<URL> urlsOfJars = new ArrayList<>();
  List<File> jarFiles = Files.find(
      classpath,
      Integer.MAX_VALUE,
      (path, attr) -> !attr.isDirectory() &&
        path.toString().toLowerCase().endsWith(JAR_EXTENSION))
      .map(Path::toFile)
      .collect(Collectors.toList());

  for (File jarFile: jarFiles) {

    try {
      urlsOfJars.add(jarFile.toURI().toURL());
    } catch (MalformedURLException e) {
      logger.log(Level.SEVERE, "Bad URL for{0} {1}",
        new Object[] {
          jarFile, e
        });
    }
  }

  return urlsOfJars.toArray(URL[]::new);
}
```

注意，我们正在扫描所有子目录，从给定的路径开始。当然，这是一个设计决策，很容易参数化搜索深度。现在，让我们从`tomcat8/lib`文件夹中获取 Jar（不需要为此安装 Tomcat；只需使用 Jar 的任何其他本地目录并进行适当的修改）：

```java
URL[] urls = Packages.fetchJarsUrlsFromClasspath(
  Path.of("D:/tomcat8/lib"));
```

现在，我们可以实例化`URLClassLoader`：

```java
URLClassLoader urlClassLoader = new URLClassLoader(
  urls, Thread.currentThread().getContextClassLoader());
```

这将为给定的 URL 构造一个新的`URLClassLoader`对象，并使用当前的类加载器进行委托（第二个参数也可以是`null`）。我们的`URL[]`只指向 JAR，但根据经验，假设任何`jar:`方案 URL 都引用 JAR 文件，而任何以`/`结尾的`file:`方案 URL 都引用目录。

`tomcat8/lib`文件夹中的一个 Jar 称为`tomcat-jdbc.jar`。在这个 JAR 中，有一个名为`org.apache.tomcat.jdbc.pool`的包。让我们列出这个包的类：

```java
List<Class<?>> classes = Packages.fetchClassesFromPackage(
  "org.apache.tomcat.jdbc.pool", urlClassLoader);
```

`fetchClassesFromPackage()`方法是一个助手，它只扫描`URLClassLoader`的`URL[]`数组并获取给定包中的类。它的源代码与本书附带的代码一起提供。

# 检查模块内的包

如果我们使用 Java9 模块化，那么我们的包将生活在模块中。例如，如果我们在一个名为`org.tournament`的模块中的一个名为`com.management`的包中有一个名为`Manager`的类，那么我们可以这样获取该模块的所有包：

```java
Manager mgt = new Manager();
Set<String> packages = mgt.getClass().getModule().getPackages();
```

另外，如果我们想创建一个类，那么我们需要以下的`Class.forName()`风格：

```java
Class<?> clazz = Class.forName(mgt.getClass()
  .getModule(), "com.management.Manager");
```

请记住，每个模块在磁盘上都表示为具有相同名称的目录。例如，`org.tournament`模块在磁盘上有一个同名文件夹。此外，每个模块被映射为一个具有此名称的单独 JAR（例如，`org.tournament.jar`）。通过记住这些坐标，很容易修改本节中的代码，从而列出给定模块的给定包的所有类。

# 150 检查类

通过使用 Java 反射 API，我们可以检查类的详细信息，对象的类名、修饰符、构造器、方法、字段、实现接口等。

假设我们有以下`Pair`类：

```java
public final class Pair<L, R> extends Tuple implements Comparable {

  final L left;
  final R right;

  public Pair(L left, R right) {
    this.left = left;
    this.right = right;
  }

  public class Entry<L, R> {}
    ...
}
```

我们还假设有一个实例：

```java
Pair pair = new Pair(1, 1);
```

现在，让我们使用反射来获取`Pair`类的名称。

# 通过实例获取`Pair`类的名称

通过拥有`Pair`的实例（对象），我们可以通过调用`getClass()`方法，以及`Class.getName()`、`getSimpleName()`、`getCanonicalName()`找到其类的名称，如下例所示：

```java
Class<?> clazz = pair.getClass();

// modern.challenge.Pair
System.out.println("Name: " + clazz.getName());

// Pair
System.out.println("Simple name: " + clazz.getSimpleName());

// modern.challenge.Pair
System.out.println("Canonical name: " + clazz.getCanonicalName());
```

匿名类没有简单的和规范的名称。

注意，`getSimpleName()`返回非限定类名。或者，我们可以获得如下类：

```java
Class<Pair> clazz = Pair.class;
Class<?> clazz = Class.forName("modern.challenge.Pair");
```

# 获取`Pair`类修饰符

为了得到类的修饰符（`public`、`protected`、`private`、`final`、`static`、`abstract`、`interface`，我们可以调用`Class.getModifiers()`方法。此方法返回一个`int`值，该值将每个修饰符表示为标志位。为了解码结果，我们依赖于`Modifier`类，如下所示：

```java
int modifiers = clazz.getModifiers();

System.out.println("Is public? " 
  + Modifier.isPublic(modifiers)); // true
System.out.println("Is final? " 
  + Modifier.isFinal(modifiers)); // true
System.out.println("Is abstract? " 
  + Modifier.isAbstract(modifiers)); // false
```

# 获取`Pair`类实现的接口

为了获得由类或对象表示的接口直接实现的接口，我们只需调用`Class.getInterfaces()`。此方法返回一个数组。因为`Pair`类实现了一个接口（`Comparable`，所以返回的数组将包含一个元素：

```java
Class<?>[] interfaces = clazz.getInterfaces();

// interface java.lang.Comparable
System.out.println("Interfaces: " + Arrays.toString(interfaces));

// Comparable
System.out.println("Interface simple name: " 
  + interfaces[0].getSimpleName());
```

# 获取`Pair`类构造器

类的`public`构造器可以通过`Class.getConstructors()`类获得。返回结果为`Constructor<?>[]`：

```java
Constructor<?>[] constructors = clazz.getConstructors();

// public modern.challenge.Pair(java.lang.Object,java.lang.Object)
System.out.println("Constructors: " + Arrays.toString(constructors));
```

要获取所有声明的构造器（例如，`private`和`protected`构造器），请调用`getDeclaredConstructors()`。搜索某个构造器时，调用`getConstructor​(Class<?>... parameterTypes)`或`getDeclaredConstructor​(Class<?>... parameterTypes)`。

# 获取`Pair`类字段

类的所有字段都可以通过`Class.getDeclaredFields()`方法访问。此方法返回一个数组`Field`：

```java
Field[] fields = clazz.getDeclaredFields();

// final java.lang.Object modern.challenge.Pair.left
// final java.lang.Object modern.challenge.Pair.right
System.out.println("Fields: " + Arrays.toString(fields));
```

为了获取字段的实际名称，我们可以很容易地提供一个辅助方法：

```java
public static List<String> getFieldNames(Field[] fields) {

  return Arrays.stream(fields)
    .map(Field::getName)
    .collect(Collectors.toList());
}
```

现在，我们只收到字段的名称：

```java
List<String> fieldsName = getFieldNames(fields);

// left, right
System.out.println("Fields names: " + fieldsName);
```

获取字段的值可以通过一个名为`Object get(Object obj)`的通用方法和一组`getFoo()`方法来完成（有关详细信息，请参阅文档）。`obj`表示`static`或实例字段。例如，假设`ProcedureOutputs`类有一个名为`callableStatement`的`private`字段，其类型为`CallableStatement`。让我们用`Field.get()`方法访问此字段，检查`CallableStatement`是否关闭：

```java
ProcedureOutputs procedureOutputs 
  = storedProcedure.unwrap(ProcedureOutputs.class);

Field csField = procedureOutputs.getClass()
  .getDeclaredField("callableStatement"); 
csField.setAccessible(true);

CallableStatement cs 
  = (CallableStatement) csField.get(procedureOutputs);

System.out.println("Is closed? " + cs.isClosed());
```

如果只获取`public`字段，请调用`getFields()`。要搜索某个字段，请调用`getField​(String fieldName)`或`getDeclaredField​(String name)`。

# 获取`Pair`类方法

类的`public`方法可以通过`Class.getMethods()`方法访问。此方法返回一个数组`Method`：

```java
Method[] methods = clazz.getMethods();
// public boolean modern.challenge.Pair.equals(java.lang.Object)
// public int modern.challenge.Pair.hashCode()
// public int modern.challenge.Pair.compareTo(java.lang.Object)
// ...
System.out.println("Methods: " + Arrays.toString(methods));
```

为了获取方法的实际名称，我们可以快速提供一个辅助方法：

```java
public static List<String> getMethodNames(Method[] methods) {

  return Arrays.stream(methods)
    .map(Method::getName)
    .collect(Collectors.toList());
}
```

现在，我们只检索方法的名称：

```java
List<String> methodsName = getMethodNames(methods);

// equals, hashCode, compareTo, wait, wait,
// wait, toString, getClass, notify, notifyAll
System.out.println("Methods names: " + methodsName);
```

获取所有声明的方法（例如，`private`、`protected`），调用`getDeclaredMethods()`。要搜索某个方法，请调用`getMethod​(String name, Class<?>... parameterTypes)`或`getDeclaredMethod​(String name, Class<?>... parameterTypes)`。

# 获取`Pair`类模块

如果我们使用 JDK9 模块化，那么我们的类将生活在模块中。`Pair`类不在模块中，但是我们可以通过 JDK9 的`Class.getModule()`方法很容易得到类的模块（如果类不在模块中，那么这个方法返回`null`）：

```java
// null, since Pair is not in a Module
Module module = clazz.getModule();
```

# 获取`Pair`类超类

`Pair`类扩展了`Tuple`类，因此`Tuple`类是`Pair`的超类。我们可以通过`Class.getSuperclass()`方法得到，如下所示：

```java
Class<?> superClass = clazz.getSuperclass();
// modern.challenge.Tuple
System.out.println("Superclass: " + superClass.getName());
```

# 获取某个类型的名称

从 JDK8 开始，我们可以获得特定类型名称的信息字符串。

此方法返回与`getName()`、`getSimpleName()`或`getCanonicalName()`中的一个或多个相同的字符串：

*   对于原始类型，它会为所有三个方法返回相同的结果：

```java
System.out.println("Type: " + int.class.getTypeName()); // int
```

*   对于`Pair`，返回与`getName()`、`getCanonicalName()`相同的东西：

```java
// modern.challenge.Pair
System.out.println("Type name: " + clazz.getTypeName());
```

*   对于内部类（比如`Entry`代表`Pair`，它返回与`getName()`相同的东西：

```java
// modern.challenge.Pair$Entry
System.out.println("Type name: " 
  + Pair.Entry.class.getTypeName());
```

*   对于匿名类，它返回与`getName()`相同的内容：

```java
Thread thread = new Thread() {
  public void run() {
    System.out.println("Child Thread");
  }
};

// modern.challenge.Main$1
System.out.println("Anonymous class type name: "
  + thread.getClass().getTypeName());
```

*   对于数组，它返回与`getCanonicalName()`相同的内容：

```java
Pair[] pairs = new Pair[10];
// modern.challenge.Pair[]
System.out.println("Array type name: " 
  + pairs.getClass().getTypeName());
```

# 获取描述类的字符串

从 JDK8 开始，我们可以通过`Class.toGenericString()`方法获得类的快速描述（包含修饰符、名称、类型参数等）。

我们来看几个例子：

```java
// public final class modern.challenge.Pair<L,R>
System.out.println("Description of Pair: " 
  + clazz.toGenericString());

// public abstract interface java.lang.Runnable
System.out.println("Description of Runnable: " 
  + Runnable.class.toGenericString());

// public abstract interface java.util.Map<K,V>
System.out.println("Description of Map: " 
  + Map.class.toGenericString());
```

# 获取类的类型描述符字符串

从 JDK12 开始，我们可以通过`Class.descriptorString()`方法获取类的类型描述符作为`String`对象：

```java
// Lmodern/challenge/Pair;
System.out.println("Type descriptor of Pair: " 
  + clazz.descriptorString());

// Ljava/lang/String;
System.out.println("Type descriptor of String: " 
  + String.class.descriptorString());
```

# 获取数组的组件类型

JDK12 只为数组提供了`Class<?> componentType()`方法。此方法返回数组的组件类型，如下两个示例所示：

```java
Pair[] pairs = new Pair[10];
String[] strings = new String[] {"1", "2", "3"};

// class modern.challenge.Pair
System.out.println("Component type of Pair[]: " 
  + pairs.getClass().componentType());

// class java.lang.String
System.out.println("Component type of String[]: " 
  + strings.getClass().componentType());
```

# 为数组类型获取类，其组件类型由`Pair`描述

从 JDK12 开始，我们可以得到一个数组类型的`Class`，该数组类型的组件类型由给定的类通过`Class.arrayType()`来描述：

```java
Class<?> arrayClazz = clazz.arrayType();

// modern.challenge.Pair<L,R>[]
System.out.println("Array type: " + arrayClazz.toGenericString());
```

# 151 通过反射构造器的实例化

我们可以使用 Java 反射 API 通过`Constructor.newInstance()`实例化一个类。

让我们考虑以下类，它有四个构造器：

```java
public class Car {

  private int id;
  private String name;
  private Color color;

  public Car() {}

  public Car(int id, String name) {
    this.id = id;
    this.name = name;
  }

  public Car(int id, Color color) {
    this.id = id;
    this.color = color;
  }

  public Car(int id, String name, Color color) {
    this.id = id;
    this.name = name;
    this.color = color;
  }

  // getters and setters omitted for brevity
}
```

一个`Car`实例可以通过这四个构造器中的一个来创建。`Constructor`类公开了一个方法，该方法接受构造器的参数类型，并返回反映匹配构造器的`Constructor`对象。这种方法称为`getConstructor​(Class<?>... parameterTypes)`。

让我们调用前面的每个构造器：

```java
Class<Car> clazz = Car.class;

Constructor<Car> emptyCnstr 
  = clazz.getConstructor();

Constructor<Car> idNameCnstr 
  = clazz.getConstructor(int.class, String.class);

Constructor<Car> idColorCnstr 
  = clazz.getConstructor(int.class, Color.class);

Constructor<Car> idNameColorCnstr 
  = clazz.getConstructor(int.class, String.class, Color.class);
```

此外，`Constructor.newInstance​(Object... initargs)`可以返回`Car`的实例，该实例对应于被调用的构造器：

```java
Car carViaEmptyCnstr = emptyCnstr.newInstance();

Car carViaIdNameCnstr = idNameCnstr.newInstance(1, "Dacia");

Car carViaIdColorCnstr = idColorCnstr
  .newInstance(1, new Color(0, 0, 0));

Car carViaIdNameColorCnstr = idNameColorCnstr
  .newInstance(1, "Dacia", new Color(0, 0, 0));
```

现在，我们来看看如何通过反射实例化一个`private`构造器。

# 通过私有构造器实例化类

Java 反射 API 也可以通过其`private`构造器来实例化类。例如，假设我们有一个名为`Cars`的工具类。按照最佳实践，我们将此类定义为`final`，并使用`private`构造器来禁止实例：

```java
public final class Cars {

  private Cars() {}
    // static members
}
```

取这个构造器可以通过`Class.getDeclaredConstructor()`完成，如下：

```java
Class<Cars> carsClass = Cars.class;
Constructor<Cars> emptyCarsCnstr = carsClass.getDeclaredConstructor();
```

在这个实例中调用`newInstance()`会抛出`IllegalAccessException`，因为被调用的构造器有`private`访问权限。但是，Java 反射允许我们通过标志方法`Constructor.setAccessible()`修改访问级别。这一次，实例化按预期工作：

```java
emptyCarsCnstr.setAccessible(true);
Cars carsViaEmptyCnstr = emptyCarsCnstr.newInstance();
```

为了阻止这种方法，建议抛出一个来自`private`构造器的错误，如下所示：

```java
public final class Cars {

  private Cars() {
    throw new AssertionError("Cannot be instantiated");
  }

  // static members
}
```

这一次，实例化尝试将以`AssertionError`失败。

# 从 JAR 实例化类

假设我们在`D:/Java Modern Challenge/Code/lib/`文件夹中有一个 Guava JAR，我们想创建一个`CountingInputStream`的实例并从一个文件中读取一个字节。

首先，我们为番石榴罐子定义一个`URL[]`数组，如下所示：

```java
URL[] classLoaderUrls = new URL[] {
  new URL(
    "file:///D:/Java Modern Challenge/Code/lib/guava-16.0.1.jar")
};
```

然后，我们将为这个`URL[]`数组定义`URLClassLoader`：

```java
URLClassLoader urlClassLoader = new URLClassLoader(classLoaderUrls);
```

接下来，我们将加载目标类（`CountingInputStream`是一个计算从`InputStream`读取的字节数的类）：

```java
Class<?> cisClass = urlClassLoader.loadClass(
  "com.google.common.io.CountingInputStream");
```

一旦目标类被加载，我们就可以获取它的构造器（`CountingInputStream`有一个单独的构造器包装给定的`InputStream`：

```java
Constructor<?> constructor 
  = cisClass.getConstructor(InputStream.class);
```

此外，我们还可以通过这个构造器创建一个`CountingInputStream`的实例：

```java
Object instance = constructor.newInstance(
  new FileInputStream​(Path.of("test.txt").toFile()));
```

为了确保返回的实例是可操作的，我们调用它的两个方法（`read()`方法一次读取一个字节，而`getCount()`方法返回读取的字节数）：

```java
Method readMethod = cisClass.getMethod("read");
Method countMethod = cisClass.getMethod("getCount");
```

接下来，让我们读一个字节，看看`getCount()`返回什么：

```java
readMethod.invoke(instance);
Object readBytes = countMethod.invoke(instance);
System.out.println("Read bytes (should be 1): " + readBytes); // 1
```

# 有用的代码片段

作为奖励，让我们看看在使用反射和构造器时通常需要的几个代码片段。

首先，让我们获取可用构造器的数量：

```java
Class<Car> clazz = Car.class;
Constructor<?>[] cnstrs = clazz.getConstructors();
System.out.println("Car class has " 
  + cnstrs.length + " constructors"); // 4
```

现在，让我们看看这四个构造器中有多少个参数：

```java
for (Constructor<?> cnstr : cnstrs) {
  int paramCount = cnstr.getParameterCount();
  System.out.println("\nConstructor with " 
    + paramCount + " parameters");
}
```

为了获取构造器的每个参数的详细信息，我们可以调用`Constructor.getParameters()`。该方法返回`Parameter`数组（JDK8 中添加了该类，提供了*解剖*参数的综合方法列表）：

```java
for (Constructor<?> cnstr : cnstrs) {
  Parameter[] params = cnstr.getParameters();
  ...
}
```

如果我们只需要知道参数的类型，那么`Constructor.getParameterTypes()`将完成以下工作：

```java
for (Constructor<?> cnstr : cnstrs) {
  Class<?>[] typesOfParams = cnstr.getParameterTypes();
  ...
}
```

# 152 获取接收器类型的注解

从 JDK8 开始，我们可以使用显式的*接收器*参数。这主要意味着我们可以声明一个实例方法，该实例方法使用`this`Java 关键字获取封闭类型的参数。

通过显式的*接收器*参数，我们可以将类型注解附加到`this`。例如，假设我们有以下注解：

```java
@Target({ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Ripe {}
```

我们用它来注解`Melon`类的`eat()`方法中的`this`：

```java
public class Melon {
  ...
  public void eat(@Ripe Melon this) {}
  ...
}
```

也就是说，只有当`Melon`的实例代表一个成熟的瓜时，我们才能调用`eat()`方法：

```java
Melon melon = new Melon("Gac", 2000);

// works only if the melon is ripe
melon.eat();
```

通过 JDK8，采用`java.lang.reflect.Executable.getAnnotatedReceiverType()`方法，可以在显式*接收器*参数上进行反射注解。该方法在`Constructor`和`Method`类中也有，因此可以这样使用：

```java
Class<Melon> clazz = Melon.class;
Method eatMethod = clazz.getDeclaredMethod("eat");

AnnotatedType annotatedType = eatMethod.getAnnotatedReceiverType();

// modern.challenge.Melon
System.out.println("Type: " + annotatedType.getType().getTypeName());

// [@modern.challenge.Ripe()]
System.out.println("Annotations: " 
  + Arrays.toString(annotatedType.getAnnotations()));

// [interface java.lang.reflect.AnnotatedType]
System.out.println("Class implementing interfaces: " 
  + Arrays.toString(annotatedType.getClass().getInterfaces()));

AnnotatedType annotatedOwnerType 
  = annotatedType.getAnnotatedOwnerType();

// null
System.out.println("\nAnnotated owner type: " + annotatedOwnerType);
```

# 153 获得合成和桥接构造

通过使用*合成*构造，我们几乎可以理解编译器添加的任何构造。更确切地说，符合 Java 语言规范：Java 编译器引入的任何构造，如果在源代码中没有对应的构造，则必须标记为合成，除了默认构造器、类初始化方法以及`Enum`类的`valueOf()`方法和`values`。

有不同种类的*合成*构造（例如，字段、方法和构造器），但是让我们看一个*合成*字段的示例。假设我们有以下类：

```java
public class Melon {
  ...
  public class Slice {}
  ...
}
```

注意，我们有一个名为`Slice`的内部类。在编译代码时，编译器将通过添加一个用于引用顶级类的*合成*字段来更改此类。这个*合成*字段提供了从嵌套类访问封闭类成员的便利。

为了检查这个*合成*字段的存在，让我们获取所有声明的字段并对它们进行计数：

```java
Class<Melon.Slice> clazzSlice = Melon.Slice.class;
Field[] fields = clazzSlice.getDeclaredFields();

// 1
System.out.println("Number of fields: " + fields.length);
```

即使我们没有显式声明任何字段，也要注意报告了一个字段。让我们看看它是否是*合成*，看看它的名字：

```java
// true
System.out.println("Is synthetic: " + fields[0].isSynthetic());

// this$0
System.out.println("Name: " + fields[0].getName());
```

与本例类似，我们可以通过`Method.isSynthetic()`和`Constructor.isSynthetic()`方法检查方法或构造器是否是*合成的*。

现在，我们来谈谈*桥接*方法。这些方法也是*合成*，它们的目标是处理泛型的*类型擦除*。

考虑以下`Melon`类：

```java
public class Melon implements Comparator<Melon> {

  @Override
  public int compare(Melon m1, Melon m2) {
    return Integer.compare(m1.getWeight(), m2.getWeight());
  }
  ...
}
```

在这里，我们实现`Comparator`接口并覆盖`compare()`方法。此外，我们明确规定了`compare()`方法需要两个`Melon`实例。编译器将继续执行*类型擦除*，并创建一个包含两个对象的新方法，如下所示：

```java
public int compare(Object m1, Object m2) {
  return compare((Melon) m1, (Melon) m2);
}
```

这种方法被称为*桥接*方法。我们看不到，但是 Java 反射 API 可以：

```java
Class<Melon> clazz = Melon.class;
Method[] methods = clazz.getDeclaredMethods();
Method compareBridge = Arrays.asList(methods).stream()
  .filter(m -> m.isSynthetic() && m.isBridge())
  .findFirst()
  .orElseThrow();

// public int modern.challenge.Melon.compare(
// java.lang.Object, java.lang.Object)
System.out.println(compareBridge);
```

# 154 检查参数的可变数量

在 Java 中，如果一个方法的签名包含一个`varargs`类型的参数，那么该方法可以接收数量可变的参数。

例如，`plantation()`方法采用可变数量的参数，例如，`Seed... seeds`：

```java
public class Melon {
  ...
  public void plantation(String type, Seed...seeds) {}
  ...
}
```

现在，Java 反射 API 可以通过`Method.isVarArgs()`方法判断这个方法是否支持可变数量的参数，如下所示：

```java
Class<Melon> clazz = Melon.class;
Method[] methods = clazz.getDeclaredMethods();

for (Method method: methods) {
  System.out.println("Method name: " + method.getName() 
    + " varargs? " + method.isVarArgs());
}
```

您将收到类似以下内容的输出：

```java
Method name: plantation, varargs? true
Method name: getWeight, varargs? false
Method name: toString, varargs? false
Method name: getType, varargs? false
```

# 155 检查默认方法

Java8 用`default`方法丰富了接口的概念。这些方法编写在接口内部，并有一个默认实现。例如，`Slicer`接口有一个默认方法，叫做`slice()`：

```java
public interface Slicer {

  public void type();

  default void slice() {
    System.out.println("slice");
  }
}
```

现在，`Slicer`的任何实现都必须实现`type()`方法，并且可以选择性地覆盖`slice()`方法或依赖于默认实现。

Java 反射 API 可以通过`Method.isDefault()`标志方法识别`default`方法：

```java
Class<Slicer> clazz = Slicer.class;
Method[] methods = clazz.getDeclaredMethods();

for (Method method: methods) {
  System.out.println("Method name: " + method.getName() 
    + ", is default? " + method.isDefault());
}
```

我们将收到以下输出：

```java
Method name: type, is default? false
Method name: slice, is default? true
```

# 156 基于反射的嵌套访问控制

在 JDK11 的特性中，我们有几个*热点*（字节码级别的变化）。其中一个*热点*被称为 JEP181，或者**基于嵌套的访问控制**（**NESTS**）。基本上，*NEST* 术语定义了一个新的访问控制上下文，*允许逻辑上属于同一代码实体的类，但是用不同的类文件编译的类，访问彼此的私有成员，而不需要编译器插入可访问性方法（第 11 页）*。

因此，换句话说，*嵌套*允许将嵌套类编译为属于同一封闭类的不同类文件。然后允许它们访问彼此的私有类，而无需使用*合成*/*桥接*方法。

让我们考虑以下代码：

```java
public class Car {

  private String type = "Dacia";

  public class Engine {

    private String power = "80 hp";

    public void addEngine() {
      System.out.println("Add engine of " + power 
        + " to car of type " + type);
    }
  }
}
```

让我们在 JDK10 中为`Car.class`运行`javap`（Java 类文件反汇编工具，它允许我们分析字节码）。以下屏幕截图突出显示了此代码的重要部分：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/e2d1c933-70ae-43e5-87b4-7e44b9ab0893.png)

我们可以看到，为了从`Engine.addEngine()`方法访问封闭类字段`Car.type`，Java 修改了代码并添加了一个*桥接*`package`-`private`方法，称为`access$000()`。主要是综合生成的，可以通过`Method.isSynthetic()`和`Method.isBridge()`方法反射看到。

即使我们看到（或感知到）`Car`（外部）和`Engine`（嵌套）类在同一个类中，它们也被编译到不同的文件（`Car.class`和`Car$Engine.class`）。与此一致，我们的期望意味着外部类和嵌套类可以访问彼此的`private`成员。

但是在不同的文件中，这是不可能的。为了维持我们的期望，Java 增加了*桥接*`package`—`private`方法`access$000()`。

然而，Java11 引入了*嵌套*访问控制上下文，它为外部类和嵌套类中的`private`访问提供支持。这一次，外部类和嵌套类被链接到两个属性，它们形成了一个*嵌套*（我们说它们是*嵌套伙伴*）。嵌套类主要链接到`NestMembers`属性，而外部类链接到`NestHost`属性。不产生额外的*合成*方法。

在下面的屏幕截图中，我们可以看到在 JDK11 中为`Car.class`执行`javap`（注意`NestMembers`属性）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/cadb2b26-b9ae-4ffa-bb61-49103cc8d62b.png)

下面的屏幕截图显示了 JDK11 中针对`Car$Engine.class`的`javap`输出（注意`NestHost`属性）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/7b8c248d-5c48-4756-ab33-419f92a4a49b.png)

# 通过反射 API 的访问

如果没有基于嵌套的访问控制，反射功能也会受到限制。例如，在 JDK11 之前，下面的代码片段将抛出`IllegalAccessException`：

```java
Car newCar = new Car();
Engine engine = newCar.new Engine();

Field powerField = Engine.class.getDeclaredField("power");
powerField.set(engine, power);
```

我们可以通过显式调用`powerField.setAccessible(true)`来允许访问：

```java
...
Field powerField = Engine.class.getDeclaredField("power");
powerField.setAccessible(true);
powerField.set(engine, power);
...
```

从 JDK11 开始，不需要调用`setAccessible()`。

此外，JDK11 还提供了三种方法，它们通过支持*嵌套*来丰富 Java 反射 API。这些方法是`Class.getNestHost()`、`Class.getNestMembers()`和`Class.isNestmateOf()`。

让我们考虑下面的`Melon`类，其中包含几个嵌套类（`Slice`、`Peeler`和`Juicer`）：

```java
public class Melon {
  ...
  public class Slice {
    public class Peeler {}
  }

  public class Juicer {}
  ...
}
```

现在，让我们为它们中的每一个定义一个`Class`：

```java
Class<Melon> clazzMelon = Melon.class;
Class<Melon.Slice> clazzSlice = Melon.Slice.class;
Class<Melon.Juicer> clazzJuicer = Melon.Juicer.class;
Class<Melon.Slice.Peeler> clazzPeeler = Melon.Slice.Peeler.class;
```

为了查看每个类的`NestHost`，我们需要调用`Class.getNestHost()`：

```java
// class modern.challenge.Melon
Class<?> nestClazzOfMelon = clazzMelon.getNestHost();

// class modern.challenge.Melon
Class<?> nestClazzOfSlice = clazzSlice.getNestHost();

// class modern.challenge.Melon
Class<?> nestClazzOfPeeler = clazzPeeler.getNestHost();

// class modern.challenge.Melon
Class<?> nestClazzOfJuicer = clazzJuicer.getNestHost();
```

这里应该强调两点。首先，注意`Melon`的`NestHost`是`Melon`本身。第二，注意`Peeler`的`NestHost`是`Melon`，而不是`Slice`。由于`Peeler`是`Slice`的一个内部类，我们可以认为它的`NestHost`是`Slice`，但这个假设是不成立的。

现在，让我们列出每个类的`NestMembers`：

```java
Class<?>[] nestMembersOfMelon = clazzMelon.getNestMembers();
Class<?>[] nestMembersOfSlice = clazzSlice.getNestMembers();
Class<?>[] nestMembersOfJuicer = clazzJuicer.getNestMembers();
Class<?>[] nestMembersOfPeeler = clazzPeeler.getNestMembers();
```

它们将返回相同的`NestMembers`：

```java
[class modern.challenge.Melon, class modern.challenge.Melon$Juicer, class modern.challenge.Melon$Slice, class modern.challenge.Melon$Slice$Peeler]
```

最后，让我们检查一下*嵌套伙伴*：

```java
boolean melonIsNestmateOfSlice 
  = clazzMelon.isNestmateOf(clazzSlice);  // true

boolean melonIsNestmateOfJuicer 
  = clazzMelon.isNestmateOf(clazzJuicer); // true

boolean melonIsNestmateOfPeeler 
  = clazzMelon.isNestmateOf(clazzPeeler); // true

boolean sliceIsNestmateOfJuicer 
  = clazzSlice.isNestmateOf(clazzJuicer); // true

boolean sliceIsNestmateOfPeeler 
  = clazzSlice.isNestmateOf(clazzPeeler); // true

boolean juicerIsNestmateOfPeeler 
  = clazzJuicer.isNestmateOf(clazzPeeler); // true
```

# 157 读写器的反射

简单提醒一下，获取器和设置器是用于访问类的字段（例如，`private`字段）的方法（也称为访问器）。

首先，让我们看看如何获取现有的获取器和设置器。稍后，我们将尝试通过反射生成缺少的获取器和设置器。

# 获取获取器和设置器

主要有几种通过反射获得类的获取器和设置器的解决方案。假设我们要获取以下`Melon`类的获取器和设置器：

```java
public class Melon {

  private String type;
  private int weight;
  private boolean ripe;
  ...

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public int getWeight() {
    return weight;
  }

  public void setWeight(int weight) {
    this.weight = weight;
  }

  public boolean isRipe() {
    return ripe;
  }

  public void setRipe(boolean ripe) {
    this.ripe = ripe;
  }
  ...
}
```

让我们从一个通过反射（例如，通过`Class.getDeclaredMethods()`）获取类的所有声明方法的解决方案开始。现在，循环`Method[]`并通过特定于获取器和设置器的约束对其进行过滤（例如，从`get`/`set`前缀开始，返回`void`或某个类型，等等）。

另一种解决方案是通过反射（例如，通过`Class.getDeclaredFields()`）获取类的所有声明字段。现在，循环`Field[]`并尝试通过`Class.getDeclaredMethod()`将字段的名称（前缀为`get`/`set`/`is`和第一个大写字母）和字段的类型（对于设置器）传递给它来获得获取器和设置器。

最后，一个更优雅的解决方案将依赖于`PropertyDescriptor`和`Introspector`api。这些 API 在`java.beans.*`包中提供，专门用于处理 JavaBeans。

这两个类暴露的许多特征依赖于场景背后的反射。

`PropertyDescriptor`类可以通过`getReadMethod()`返回用于读取 JavaBean 属性的方法。此外，它还可以通过`getWriteMethod()`返回用于编写 JavaBean 属性的方法。依靠这两种方法，我们可以获取`Melon`类的获取器和设置器，如下所示：

```java
for (PropertyDescriptor pd:
    Introspector.getBeanInfo(Melon.class).getPropertyDescriptors()) {

  if (pd.getReadMethod() != null && !"class".equals(pd.getName())) {
    System.out.println(pd.getReadMethod());
  }

  if (pd.getWriteMethod() != null && !"class".equals(pd.getName())) {
    System.out.println(pd.getWriteMethod());
  }
}
```

输出如下：

```java
public boolean modern.challenge.Melon.isRipe()
public void modern.challenge.Melon.setRipe(boolean)
public java.lang.String modern.challenge.Melon.getType()
public void modern.challenge.Melon.setType(java.lang.String)
public int modern.challenge.Melon.getWeight()
public void modern.challenge.Melon.setWeight(int)
```

现在，假设我们有以下`Melon`实例：

```java
Melon melon = new Melon("Gac", 1000);
```

在这里，我们要称之为`getType()`获取器：

```java
// the returned type is Gac
Object type = new PropertyDescriptor("type",
  Melon.class).getReadMethod().invoke(melon);
```

现在，让我们称之为`setWeight()`设定者：

```java
// set weight of Gac to 2000
new PropertyDescriptor("weight", Melon.class)
  .getWriteMethod().invoke(melon, 2000);
```

调用不存在的属性将导致`IntrospectionException`：

```java
try {
  Object shape = new PropertyDescriptor("shape",
      Melon.class).getReadMethod().invoke(melon);
  System.out.println("Melon shape: " + shape);
} catch (IntrospectionException e) {
  System.out.println("Property not found: " + e);
}
```

# 生成获取器和设置器

假设`Melon`有三个字段（`type`、`weight`和`ripe`），只定义`type`的获取器和`ripe`的设置器：

```java
public class Melon {

  private String type;
  private int weight;
  private boolean ripe;
  ...

  public String getType() {
    return type;
  }

  public void setRipe(boolean ripe) {
    this.ripe = ripe;
  }
  ...
}
```

为了生成丢失的获取器和设置器，我们首先识别它们。下面的解决方案循环给定类的声明字段，并假设`foo`字段没有获取器，如果以下情况适用：

*   没有`get`/`isFoo()`方法
*   返回类型与字段类型不同
*   参数的数目不是 0

对于每个缺少的获取器，此解决方案在映射中添加一个包含字段名和类型的条目：

```java
private static Map<String, Class<?>> 
    fetchMissingGetters(Class<?> clazz) {

  Map<String, Class<?>> getters = new HashMap<>();
  Field[] fields = clazz.getDeclaredFields();
  String[] names = new String[fields.length];
  Class<?>[] types = new Class<?>[fields.length];

  Arrays.setAll(names, i -> fields[i].getName());
  Arrays.setAll(types, i -> fields[i].getType());

  for (int i = 0; i < names.length; i++) {
    String getterAccessor = fetchIsOrGet(names[i], types[i]);

    try {
      Method getter = clazz.getDeclaredMethod(getterAccessor);
      Class<?> returnType = getter.getReturnType();

      if (!returnType.equals(types[i]) ||
          getter.getParameterCount() != 0) {
        getters.put(names[i], types[i]);
      }
    } catch (NoSuchMethodException ex) {
      getters.put(names[i], types[i]);
      // log exception
    }
  }

  return getters;
}
```

此外，解决方案循环给定类的声明字段，并假设`foo`字段没有设置器，如果以下情况适用：

*   字段不是`final`
*   没有`setFoo()`方法
*   方法返回`void`
*   该方法只有一个参数
*   参数类型与字段类型相同
*   如果参数名存在，则应与字段名相同

对于每个缺少的设置器，此解决方案在映射中添加一个包含字段名和类型的条目：

```java
private static Map<String, Class<?>> 
    fetchMissingSetters(Class<?> clazz) {

  Map<String, Class<?>> setters = new HashMap<>();
  Field[] fields = clazz.getDeclaredFields();
  String[] names = new String[fields.length];
  Class<?>[] types = new Class<?>[fields.length];

  Arrays.setAll(names, i -> fields[i].getName());
  Arrays.setAll(types, i -> fields[i].getType());

  for (int i = 0; i < names.length; i++) {
    Field field = fields[i];
    boolean finalField = !Modifier.isFinal(field.getModifiers());

    if (finalField) {
      String setterAccessor = fetchSet(names[i]);

      try {
        Method setter = clazz.getDeclaredMethod(
            setterAccessor, types[i]);

        if (setter.getParameterCount() != 1 ||
            !setter.getReturnType().equals(void.class)) {

          setters.put(names[i], types[i]);
          continue;
        }

        Parameter parameter = setter.getParameters()[0];
        if ((parameter.isNamePresent() &&
              !parameter.getName().equals(names[i])) ||
                !parameter.getType().equals(types[i])) {
          setters.put(names[i], types[i]);
        }
      } catch (NoSuchMethodException ex) {
        setters.put(names[i], types[i]);
        // log exception
      }
    }
  }

  return setters;
}
```

到目前为止，我们知道哪些字段没有获取器和设置器。它们的名称和类型存储在映射中。让我们循环映射并生成获取器：

```java
public static StringBuilder generateGetters(Class<?> clazz) {

  StringBuilder getterBuilder = new StringBuilder();
  Map<String, Class<?>> accessors = fetchMissingGetters(clazz);

  for (Entry<String, Class<?>> accessor: accessors.entrySet()) {
    Class<?> type = accessor.getValue();
    String field = accessor.getKey();
    String getter = fetchIsOrGet(field, type);

    getterBuilder.append("\npublic ")
      .append(type.getSimpleName()).append(" ")
      .append(getter)
      .append("() {\n")
      .append("\treturn ")
      .append(field)
      .append(";\n")
      .append("}\n");
  }

  return getterBuilder;
}
```

让我们生成设置器：

```java
public static StringBuilder generateSetters(Class<?> clazz) {

  StringBuilder setterBuilder = new StringBuilder();
  Map<String, Class<?>> accessors = fetchMissingSetters(clazz);

  for (Entry<String, Class<?>> accessor: accessors.entrySet()) {
    Class<?> type = accessor.getValue();
    String field = accessor.getKey();
    String setter = fetchSet(field);

    setterBuilder.append("\npublic void ")
      .append(setter)
      .append("(").append(type.getSimpleName()).append(" ")
      .append(field).append(") {\n")
      .append("\tthis.")
      .append(field).append(" = ")
      .append(field)
      .append(";\n")
      .append("}\n");
  }

  return setterBuilder;
}
```

前面的解决方案依赖于下面列出的三个简单助手。代码很简单：

```java
private static String fetchIsOrGet(String name, Class<?> type) {
  return "boolean".equalsIgnoreCase(type.getSimpleName()) ?
    "is" + uppercase(name) : "get" + uppercase(name);
}

private static String fetchSet(String name) {
  return "set" + uppercase(name);
}

private static String uppercase(String name) {
  return name.substring(0, 1).toUpperCase() + name.substring(1);
}
```

现在，我们把它命名为`Melon`类：

```java
Class<?> clazz = Melon.class;
StringBuilder getters = generateGetters(clazz);
StringBuilder setters = generateSetters(clazz);
```

输出将显示以下生成的获取器和设置器：

```java
public int getWeight() {
  return weight;
}

public boolean isRipe() {
  return ripe;
}

public void setWeight(int weight) {
  this.weight = weight;
}

public void setType(String type) {
  this.type = type;
}
```

# 158 反射注解

Java 注解从 Java 反射 API 得到了很多关注。让我们看看几种用于检查几种注解（例如，包、类和方法）的解决方案。

主要地，表示支持注解的工件的所有主要反射 API 类（例如，`Package`、`Constructor`、`Class`、`Method`和`Field`揭示了一组处理注解的常用方法。常用方法包括：

*   `getAnnotations()`：返回特定于某个工件的所有注解
*   `getDeclaredAnnotations()`：返回直接声明给某个工件的所有注解
*   `getAnnotation()`：按类型返回注解
*   `getDeclaredAnnotation()`：通过直接声明给某个工件的类型返回注解（JDK1.8）
*   `getDeclaredAnnotationsByType()`：按类型返回直接声明给某个工件的所有注解（JDK1.8）
*   `isAnnotationPresent()`：如果在给定工件上找到指定类型的注解，则返回`true`

`getAnnotatedReceiverType()`在前面“在接收器类型上获取注解”部分中进行了讨论。

在下一节中，我们将讨论如何检查包、类、方法等的注解。

# 检查包注解

在`package-info.java`中添加了特定于包的注解，如下面的屏幕截图所示。在这里，`modern.challenge`包被注解为`@Packt`注解：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/e48d485d-b2c7-4def-85a2-8f297f863e6e.png)

检查包的注解的一个方便的解决方案是从它的一个类开始的。例如，如果在这个包（`modern.challenge`中，我们有`Melon`类，那么我们可以得到这个包的所有注解，如下所示：

```java
Class<Melon> clazz = Melon.class;
Annotation[] pckgAnnotations = clazz.getPackage().getAnnotations();
```

通过`Arrays.toString()`打印的`Annotation[]`显示一个结果：

```java
[@modern.challenge.Packt()]
```

# 检查类注解

`Melon`类有一个注解`@Fruit`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/db423fce-65bb-4f44-8c69-321f7240a260.png)

但我们可以通过`getAnnotations()`将它们全部取出来：

```java
Class<Melon> clazz = Melon.class;
Annotation[] clazzAnnotations = clazz.getAnnotations();
```

通过`Arrays.toString()`打印的返回数组显示一个结果：

```java
[@modern.challenge.Fruit(name="melon", value="delicious")]
```

为了访问注解的名称和值属性，我们可以按如下方式强制转换它：

```java
Fruit fruitAnnotation = (Fruit) clazzAnnotations[0];
System.out.println("@Fruit name: " + fruitAnnotation.name());
System.out.println("@Fruit value: " + fruitAnnotation.value());
```

或者我们可以使用`getDeclaredAnnotation()`方法直接获取正确的类型：

```java
Fruit fruitAnnotation = clazz.getDeclaredAnnotation(Fruit.class);
```

# 检查方法注解

我们来看看`Melon`类中`eat()`方法的`@Ripe`注解：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/a62edba6-1f84-46b8-9c24-dda5c288f30f.png)

首先，让我们获取所有声明的注解，然后，让我们继续到`@Ripe`：

```java
Class<Melon> clazz = Melon.class;
Method methodEat = clazz.getDeclaredMethod("eat");
Annotation[] methodAnnotations = methodEat.getDeclaredAnnotations();
```

通过`Arrays.toString()`打印的返回数组显示一个结果：

```java
[@modern.challenge.Ripe(value=true)]
```

让我们把`methodAnnotations[0]`转换成`Ripe`：

```java
Ripe ripeAnnotation = (Ripe) methodAnnotations[0];
System.out.println("@Ripe value: " + ripeAnnotation.value());
```

或者我们可以使用`getDeclaredAnnotation()`方法直接获取正确的类型：

```java
Ripe ripeAnnotation = methodEat.getDeclaredAnnotation(Ripe.class);
```

# 检查抛出异常的注解

为了检查抛出异常的注解，我们需要调用`getAnnotatedExceptionTypes()`方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/b9027589-c212-446e-be95-acd214df17c2.png)

此方法返回抛出的异常类型，包括注解的异常类型：

```java
Class<Melon> clazz = Melon.class;
Method methodEat = clazz.getDeclaredMethod("eat");
AnnotatedType[] exceptionsTypes 
  = methodEat.getAnnotatedExceptionTypes();
```

通过`Arrays.toString()`打印的返回数组显示一个结果：

```java
[@modern.challenge.Runtime() java.lang.IllegalStateException]
```

提取第一个异常类型的步骤如下：

```java
// class java.lang.IllegalStateException
System.out.println("First exception type: "
  + exceptionsTypes[0].getType());
```

提取第一个异常类型的注解可以按如下方式进行：

```java
// [@modern.challenge.Runtime()]
System.out.println("Annotations of the first exception type: " 
  + Arrays.toString(exceptionsTypes[0].getAnnotations()));
```

# 检查返回类型的注解

为了检查方法返回的注解，我们需要调用`getAnnotatedReturnType()`方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/3f955909-7c68-42e5-a1ad-06f887e73368.png)

此方法返回给定方法的带注解的返回类型：

```java
Class<Melon> clazz = Melon.class;
Method methodSeeds = clazz.getDeclaredMethod("seeds");
AnnotatedType returnType = methodSeeds.getAnnotatedReturnType();

// java.util.List<modern.challenge.Seed>
System.out.println("Return type: " 
  + returnType.getType().getTypeName());

// [@modern.challenge.Shape(value="oval")]
System.out.println("Annotations of the return type: " 
  + Arrays.toString(returnType.getAnnotations()));
```

# 检查方法参数的注解

有方法，可以调用`getParameterAnnotations()`来检查其参数的注解：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/9381a23e-4a3b-4dfc-ba66-be8ccaaf06ed.png)

此方法返回一个矩阵（数组数组），其中包含形式参数上的注解，顺序如下：

```java
Class<Melon> clazz = Melon.class;
Method methodSlice = clazz.getDeclaredMethod("slice", int.class);
Annotation[][] paramAnnotations 
  = methodSlice.getParameterAnnotations();
```

获取每个参数类型及其注解（在本例中，我们有一个带有两个注解的`int`参数）可以通过`getParameterTypes()`完成。由于此方法也维护了声明顺序，因此我们可以提取一些信息，如下所示：

```java
Class<?>[] parameterTypes = methodSlice.getParameterTypes();

int i = 0;
for (Annotation[] annotations: paramAnnotations) {
  Class parameterType = parameterTypes[i++];
  System.out.println("Parameter: " + parameterType.getName());

  for (Annotation annotation: annotations) {
    System.out.println("Annotation: " + annotation);
    System.out.println("Annotation name: " 
      + annotation.annotationType().getSimpleName());
  }
}
```

并且，输出应如下所示：

```java
Parameter type: int
Annotation: @modern.challenge.Ripe(value=true)
Annotation name: Ripe
Annotation: @modern.challenge.Shape(value="square")
Annotation name: Shape
```

# 检查字段注解

有一个字段，我们可以通过`getDeclaredAnnotations()`获取它的注解：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/6aa9184c-29ee-4e3d-b36e-4a9ad3ada53f.png)

代码如下：

```java
Class<Melon> clazz = Melon.class;
Field weightField = clazz.getDeclaredField("weight");
Annotation[] fieldAnnotations = weightField.getDeclaredAnnotations();
```

获取`@Unit`注解的值可以如下所示：

```java
Unit unitFieldAnnotation = (Unit) fieldAnnotations[0];
System.out.println("@Unit value: " + unitFieldAnnotation.value());
```

或者，使用`getDeclaredAnnotation()`方法直接获取正确的类型：

```java
Unit unitFieldAnnotation 
  = weightField.getDeclaredAnnotation(Unit.class);
```

# 检查超类的注解

为了检查超类的注解，我们需要调用`getAnnotatedSuperclass()`方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/08f3f44f-a25c-4a17-8fb0-1401133208ed.png)

此方法返回带注解的超类类型：

```java
Class<Melon> clazz = Melon.class;
AnnotatedType superclassType = clazz.getAnnotatedSuperclass();
```

我们也来了解一下：

```java
// modern.challenge.Cucurbitaceae
 System.out.println("Superclass type: " 
   + superclassType.getType().getTypeName());

 // [@modern.challenge.Family()]
 System.out.println("Annotations: " 
   + Arrays.toString(superclassType.getDeclaredAnnotations()));

 System.out.println("@Family annotation present: " 
   + superclassType.isAnnotationPresent(Family.class)); // true
```

# 检查接口注解

为了检查实现接口的注解，我们需要调用`getAnnotatedInterfaces()`方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/ac95c0fb-01d8-44f8-b31a-f2d8c07800a4.png)

此方法返回带注解的接口类型：

```java
Class<Melon> clazz = Melon.class;
AnnotatedType[] interfacesTypes = clazz.getAnnotatedInterfaces();
```

通过`Arrays.toString()`打印的返回数组显示一个结果：

```java
[@modern.challenge.ByWeight() java.lang.Comparable]
```

提取第一个接口类型可以如下完成：

```java
// interface java.lang.Comparable
System.out.println("First interface type: " 
  + interfacesTypes[0].getType());
```

此外，提取第一接口类型的注解可以如下进行：

```java
// [@modern.challenge.ByWeight()]
System.out.println("Annotations of the first exception type: " 
  + Arrays.toString(interfacesTypes[0].getAnnotations()));
```

# 按类型获取注解

在某些组件上有多个相同类型的注解，我们可以通过`getAnnotationsByType()`获取所有注解。对于一个类，我们可以按如下方式进行：

```java
Class<Melon> clazz = Melon.class;
Fruit[] clazzFruitAnnotations 
  = clazz.getAnnotationsByType(Fruit.class);
```

# 获取声明的注解

尝试按类型获取直接在某个工件上声明的单个注解可以按以下示例所示进行：

```java
Class<Melon> clazz = Melon.class;
Method methodEat = clazz.getDeclaredMethod("eat");
Ripe methodRipeAnnotation 
  = methodEat.getDeclaredAnnotation(Ripe.class);
```

# 159 调用实例方法

假设我们有以下`Melon`类：

```java
public class Melon {
  ...
  public Melon() {}

  public List<Melon> cultivate(
      String type, Seed seed, int noOfSeeds) {

    System.out.println("The cultivate() method was invoked ...");

    return Collections.nCopies(noOfSeeds, new Melon("Gac", 5));
  }
  ...
}
```

我们的目标是调用`cultivate()`方法并通过 Java 反射 API 获得返回。

首先，让我们通过`Method.getDeclaredMethod()`获取`cultivate()`方法作为`Method`。我们所要做的就是将方法的名称（在本例中为`cultivate()`）和正确类型的参数（`String`、`Seed`和`int`传递给`getDeclaredMethod()`。`getDeclaredMethod()`的第二个参数是`Class<?>`类型的`varargs`，因此对于没有参数的方法可以为空，也可以包含参数类型列表，如下例所示：

```java
Method cultivateMethod = Melon.class.getDeclaredMethod(
  "cultivate", String.class, Seed.class, int.class);
```

然后，获取一个`Melon`类的实例。我们想要调用一个实例方法；因此，我们需要一个实例。依靠`Melon`的空构造器和 Java 反射 API，我们可以做到：

```java
Melon instanceMelon = Melon.class
  .getDeclaredConstructor().newInstance();
```

最后，我们重点讨论了`Method.invoke()`方法。主要是给这个方法传递调用`cultivate()`方法的实例和一些参数值：

```java
List<Melon> cultivatedMelons = (List<Melon>) cultivateMethod.invoke(
  instanceMelon, "Gac", new Seed(), 10);
```

以下消息显示调用成功：

```java
The cultivate() method was invoked ...
```

另外，如果我们通过`System.out.println()`打印调用返回，则得到如下结果：

```java
[Gac(5g), Gac(5g), Gac(5g), ...]
```

我们刚刚通过反射培养了 10 个`Gac`。

# 160 获取静态方法

假设我们有以下`Melon`类：

```java
public class Melon {
  ...
  public void eat() {}

  public void weighsIn() {}

  public static void cultivate(Seed seeds) {
    System.out.println("The cultivate() method was invoked ...");
  }

  public static void peel(Slice slice) {
    System.out.println("The peel() method was invoked ...");
  }

  // getters, setters, toString() omitted for brevity
}
```

这个类有两个`static`方法-`cultivate()`和`peel()`。让我们在`List<Method>`中获取这两种方法。

这个问题的解决方案有两个主要步骤：

1.  获取给定类的所有可用方法
2.  通过`Modifier.isStatic()`方法过滤包含`static`修饰符的

在代码中，如下所示：

```java
List<Method> staticMethods = new ArrayList<>();

Class<Melon> clazz = Melon.class;
Method[] methods = clazz.getDeclaredMethods();

for (Method method: methods) {

  if (Modifier.isStatic(method.getModifiers())) {
    staticMethods.add(method);
  }
}
```

通过`System.out.println()`打印列表的结果如下：

```java
[public static void 
  modern.challenge.Melon.peel(modern.challenge.Slice),

 public static void 
  modern.challenge.Melon.cultivate(modern.challenge.Seed)]
```

再往前一步，我们可能想调用这两个方法中的一个。

例如，我们调用`peel()`方法（注意我们传递的是`null`而不是`Melon`的实例，因为`static`方法不需要实例）：

```java
Method method = clazz.getMethod("peel", Slice.class);
method.invoke(null, new Slice());
```

成功调用`peel()`方法的输出信号：

```java
The peel() method was invoked ...
```

# 161 获取方法、字段和异常的泛型

假设我们有以下`Melon`类（列出的只是与这个问题相关的部分）：

```java
public class Melon<E extends Exception>
    extends Fruit<String, Seed> implements Comparable<Integer> {

  ...
  private List<Slice> slices;
  ...

  public List<Slice> slice() throws E {
    ...
  }

  public Map<String, Integer> asMap(List<Melon> melons) {
    ...
  }
  ...
}
```

`Melon`类包含几个与不同工件相关联的泛型类型。超类、接口、类、方法和字段的泛型类型主要是`ParameterizedType`实例。对于每个`ParameterizedType`，我们需要通过`ParameterizedType.getActualTypeArguments()`获取参数的实际类型。此方法返回的`Type[]`可以迭代提取每个参数的信息，如下所示：

```java
public static void printGenerics(Type genericType) {

  if (genericType instanceof ParameterizedType) {
    ParameterizedType type = (ParameterizedType) genericType;
    Type[] typeOfArguments = type.getActualTypeArguments();

    for (Type typeOfArgument: typeOfArguments) {
      Class classTypeOfArgument = (Class) typeOfArgument;
      System.out.println("Class of type argument: " 
        + classTypeOfArgument);

      System.out.println("Simple name of type argument: " 
        + classTypeOfArgument.getSimpleName());
    }
  }
}
```

现在，让我们看看如何处理方法的泛型。

# 方法的泛型

例如，让我们获取`slice()`和`asMap()`方法的通用返回类型。这可以通过`Method.getGenericReturnType()`方法实现，如下所示：

```java
Class<Melon> clazz = Melon.class;

Method sliceMethod = clazz.getDeclaredMethod("slice");
Method asMapMethod = clazz.getDeclaredMethod("asMap", List.class);

Type sliceReturnType = sliceMethod.getGenericReturnType();
Type asMapReturnType = asMapMethod.getGenericReturnType();
```

现在，调用`printGenerics(sliceReturnType)`将输出以下内容：

```java
Class of type argument: class modern.challenge.Slice
Simple name of type argument: Slice
```

并且，调用`printGenerics(asMapReturnType)`将输出以下内容：

```java
Class of type argument: class java.lang.String
Simple name of type argument: String

Class of type argument: class java.lang.Integer
Simple name of type argument: Integer
```

方法的通用参数可通过`Method.getGenericParameterTypes()`获得，如下所示：

```java
Type[] asMapParamTypes = asMapMethod.getGenericParameterTypes();
```

此外，我们为每个`Type`（每个泛型参数）调用`printGenerics()`：

```java
for (Type paramType: asMapParamTypes) {
  printGenerics(paramType);
}
```

以下是输出（只有一个通用参数，`List<Melon>`）：

```java
Class of type argument: class modern.challenge.Melon
Simple name of type argument: Melon
```

# 字段的泛型

对于字段（例如，`slices`），可以通过`Field.getGenericType()`获取泛型，如下所示：

```java
Field slicesField = clazz.getDeclaredField("slices");
Type slicesType = slicesField.getGenericType();
```

调用`printGenerics(slicesType)`将输出以下内容：

```java
Class of type argument: class modern.challenge.Slice
Simple name of type argument: Slice
```

# 超类的泛型

获取超类的泛型可以通过调用当前类的`getGenericSuperclass()`方法来完成：

```java
Type superclassType = clazz.getGenericSuperclass();
```

调用`printGenerics(superclassType)`将输出以下内容：

```java
Class of type argument: class java.lang.String
Simple name of type argument: String

Class of type argument: class modern.challenge.Seed
Simple name of type argument: Seed
```

# 接口泛型

通过调用当前类的`getGenericInterfaces()`方法，可以得到实现接口的泛型：

```java
Type[] interfacesTypes = clazz.getGenericInterfaces();
```

此外，我们为每个`Type`调用`printGenerics()`。输出如下（有单一接口，`Comparable<Integer>`

```java
Class of type argument: class java.lang.Integer
Simple name of type argument: Integer
```

# 异常的泛型

异常的泛型类型在`TypeVariable`或`ParameterizedType`实例中具体化。这一次，基于`TypeVariable`的泛型信息提取和打印的助手方法可以写为：

```java
public static void printGenericsOfExceptions(Type genericType) {

  if (genericType instanceof TypeVariable) {
    TypeVariable typeVariable = (TypeVariable) genericType;
    GenericDeclaration genericDeclaration
      = typeVariable.getGenericDeclaration();

    System.out.println("Generic declaration: " + genericDeclaration);

    System.out.println("Bounds: ");
    for (Type type: typeVariable.getBounds()) {
      System.out.println(type);
    }
  }
}
```

有了这个助手，我们可以通过`getGenericExceptionTypes()`将方法抛出的异常传递给它。如果异常类型是类型变量（`TypeVariable`）或参数化类型（`ParameterizedType`），则创建它。否则，将解决：

```java
Type[] exceptionsTypes = sliceMethod.getGenericExceptionTypes();
```

此外，我们为每个`Type`调用`printGenerics()`：

```java
for (Type paramType: exceptionsTypes) {
  printGenericsOfExceptions(paramType);
}
```

输出如下：

```java
Generic declaration: class modern.challenge.Melon
Bounds: class java.lang.Exception
```

最可能的情况是，打印有关泛型的提取信息将没有用处，因此，可以根据您的需要随意调整前面的帮助程序。例如，收集信息并以`List`、`Map`等形式返回。

# 162 获取公共和私有字段

这个问题的解决依赖于`Modifier.isPublic()`和`Modifier.isPrivate()`方法。

假设下面的`Melon`类有两个`public`字段和两个`private`字段：

```java
public class Melon {

  private String type;
  private int weight;

  public Peeler peeler;
  public Juicer juicer;
  ...
}
```

首先需要通过`getDeclaredFields()`方法获取该类对应的`Field[]`数组：

```java
Class<Melon> clazz = Melon.class;
Field[] fields = clazz.getDeclaredFields();
```

`Field[]`包含前面的四个字段。此外，让我们迭代这个数组，并对每个`Field`应用`Modifier.isPublic()`和`Modifier.isPrivate()`标志方法：

```java
List<Field> publicFields = new ArrayList<>();
List<Field> privateFields = new ArrayList<>();

for (Field field: fields) {
  if (Modifier.isPublic(field.getModifiers())) {
    publicFields.add(field);
  }

  if (Modifier.isPrivate(field.getModifiers())) {
    privateFields.add(field);
  }
}
```

`publicFields`列表只包含`public`字段，`privateFields`列表只包含`private`字段。如果我们通过`System.out.println()`快速打印这两个列表，那么输出如下：

```java
Public fields:
[public modern.challenge.Peeler modern.challenge.Melon.peeler,
public modern.challenge.Juicer modern.challenge.Melon.juicer]

Private fields:
[private java.lang.String modern.challenge.Melon.type,
private int modern.challenge.Melon.weight]
```

# 163 使用数组

Java 反射 API 附带了一个专用于处理数组的类。这个类被命名为`java.lang.reflect.Array`。

例如，下面的代码片段创建了一个数组`int`。第一个参数告诉数组中每个元素的类型。第二个参数表示数组的长度。因此，10 个整数的数组可以通过`Array.newInstance()`定义如下：

```java
int[] arrayOfInt = (int[]) Array.newInstance(int.class, 10);
```

使用 Java 反射，我们可以改变数组的内容。有一个通用的`set()`方法和一堆`set*Foo*()`方法（例如`setInt()`、`setFloat()`）。将索引 0 处的值设置为 100 可以按以下方式进行：

```java
Array.setInt(arrayOfInt, 0, 100);
```

从数组中获取值可以通过`get()`和`getFoo()`方法完成（这些方法将数组和索引作为参数，并从指定的索引返回值）：

```java
int valueIndex0 = Array.getInt(arrayOfInt, 0);
```

获取一个数组的`Class`可以如下操作：

```java
Class<?> stringClass = String[].class;
Class<?> clazz = arrayOfInt.getClass();
```

我们可以通过`getComponentType()`提取数组的类型：

```java
// int
Class<?> typeInt = clazz.getComponentType();

// java.lang.String
Class<?> typeString = stringClass.getComponentType();
```

# 164 检查模块

Java9 通过 Java 平台模块系统增加了*模块*的概念。基本上，模块是由该模块管理的一组包（例如，模块决定哪些包在模块外部可见）。

具有两个模块的应用的形状可以如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/53a35686-cd53-4883-9763-1d15ace0a122.png)

有两个模块-`org.player`和`org.tournament`。`org.player`模块需要`org.tournament`模块，`org.tournament`模块导出`com.management`包。

Java 反射 API 通过`java.lang.Module`类（在`java.base module`中）表示一个模块。通过 Java 反射 API，我们可以提取信息或修改模块。

最开始，我们可以得到一个`Module`实例，如下两个例子所示：

```java
Module playerModule = Player.class.getModule();
Module managerModule = Manager.class.getModule();
```

模块名称可以通过`Module.getName()`方法获得：

```java
// org.player
System.out.println("Class 'Player' is in module: " 
  + playerModule.getName());

// org.tournament
System.out.println("Class 'Manager' is in module: " 
  + managerModule.getName());
```

有一个`Module`实例，我们可以调用几种方法来获取不同的信息。例如，我们可以确定某个模块是否已命名，或者是否已导出或打开某个包：

```java
boolean playerModuleIsNamed = playerModule.isNamed();   // true
boolean managerModuleIsNamed = managerModule.isNamed(); // true

boolean playerModulePnExported 
  = playerModule.isExported("com.members");     // false
boolean managerModulePnExported 
  = managerModule.isExported("com.management"); // true

boolean playerModulePnOpen 
  = playerModule.isOpen("com.members");     // false
boolean managerModulePnOpen 
  = managerModule.isOpen("com.management"); // false
```

除了获取信息外，`Module`类还允许我们修改模块。例如，`org.player`模块没有将`com.members`包导出到`org.tournament`模块。我们可以快速检查：

```java
boolean before = playerModule.isExported(
  "com.members", managerModule); // false
```

但我们可以通过反射来改变这一点。我们可以通过`Module.addExports()`方法进行导出（同一类别中我们有`addOpens()`、`addReads()`、`addUses()`：

```java
playerModule.addExports("com.members", managerModule);
```

现在，让我们再次检查：

```java
boolean after = playerModule.isExported(
  "com.members", managerModule); // true
```

模块还利用了自己的描述符。`ModuleDescriptor`类可用作处理模块的起点：

```java
ModuleDescriptor descriptorPlayerModule 
  = playerModule.getDescriptor();
```

例如，我们可以按如下方式获取模块的包：

```java
Set<String> pcks = descriptorPlayerModule.packages();
```

# 165 动态代理

*动态代理*可用于支持不同功能的实现，这些功能属于**交叉切入点**（**CCC**）类别。CCC 是那些表示核心功能的辅助功能的关注点，例如数据库连接管理、事务管理（例如 Spring`@Transactional`）、安全性和日志记录。

更确切地说，Java 反射附带了一个名为`java.lang.reflect.Proxy`的类，其主要目的是为在运行时创建接口的动态实现提供支持。`Proxy`反映了具体接口在运行时的实现。

我们可以将`Proxy`看作是*前包装器*，它将我们的调用传递给正确的方法。可选地，`Proxy`可以在委托调用之前干预该过程。

动态代理依赖于单个类（`InvocationHandler`）和单个方法（`invoke()`），如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-cd-prob/img/7aa4bc4f-a8ec-42a5-b2ad-a4fdc0c20e83.png)

如果我们从这个图中描述流程，那么我们得到以下步骤：

1.  参与者通过公开的*动态代理*调用所需的方法（例如，如果我们要调用`List.add()`方法，我们将通过动态代理，而不是直接调用）

2.  动态代理将调用分派给一个`InvocationHandler`实现的实例（每个代理实例都有一个关联的调用处理器）

3.  分派的调用将以包含代理对象、要调用的方法（作为`Method`实例）和此方法的参数数组的三元组的形式命中`invoke()`方法

4.  `InvocationHandler`将运行额外的可选功能（例如，CCC）并调用相应的方法

5.  `InvocationHandler`将调用结果作为对象返回

如果我们尝试恢复此流，那么可以说动态代理通过单个类（`InvocationHandler`）和单个方法（`invoke()`）支持对任意类的多个方法的调用。

# 实现动态代理

例如，让我们编写一个动态代理来统计`List`方法的调用次数。

通过`Proxy.newProxyInstance()`方法创建动态代理。`newProxyInstance()`方法有三个参数：

*   `ClassLoader`：用于加载动态代理类
*   `Class<?>[]`：这是要实现的接口数组
*   `InvocationHandler`：这是将方法调用分派到的调用处理器

看看这个例子：

```java
List<String> listProxy = (List<String>) Proxy.newProxyInstance(
  List.class.getClassLoader(), new Class[] {
    List.class}, invocationHandler);
```

这段代码返回`List`接口的动态实现。此外，通过该代理的所有调用都将被调度到`invocationHandler`实例。

主要地，`InvocationHandler`实现的框架如下所示：

```java
public class DummyInvocationHandler implements InvocationHandler {

  @Override
  public Object invoke(Object proxy, Method method, Object[] args)
      throws Throwable {
    ...
  }
}
```

因为我们要计算`List`的方法的调用次数，所以我们应该存储所有的方法签名以及每个方法的调用次数。这可以通过在`CountingInvocationHandler`的构造器中初始化`Map`来实现（这是我们的`InvocationHandler`实现，`invocationHandler`是它的一个实例）：

```java
public class CountingInvocationHandler implements InvocationHandler {

  private final Map<String, Integer> counter = new HashMap<>();
  private final Object targetObject;

  public CountingInvocationHandler(Object targetObject) {
    this.targetObject = targetObject;

    for (Method method:targetObject.getClass().getDeclaredMethods()) {
      this.counter.put(method.getName() 
        + Arrays.toString(method.getParameterTypes()), 0);
    }
  }
  ...
}
```

`targetObject`字段保存`List`接口的实现（在本例中为`ArrayList`）。

我们创建一个`CountingInvocationHandler`实例如下：

```java
CountingInvocationHandler invocationHandler 
  = new CountingInvocationHandler(new ArrayList<>());
```

`invoke()`方法只是对调用进行计数，并使用指定的参数调用`Method`：

```java
@Override
public Object invoke(Object proxy, Method method, Object[] args)
    throws Throwable {

  Object resultOfInvocation = method.invoke(targetObject, args);
  counter.computeIfPresent(method.getName() 
    + Arrays.toString(method.getParameterTypes()), (k, v) -> ++v);

  return resultOfInvocation;
}
```

最后，我们公开了一个方法，该方法返回给定方法的调用次数：

```java
public Map<String, Integer> countOf(String methodName) {

  Map<String, Integer> result = counter.entrySet().stream()
    .filter(e -> e.getKey().startsWith(methodName + "["))
    .filter(e -> e.getValue() != 0)
    .collect(Collectors.toMap(Entry::getKey, Entry::getValue));

  return result;
}
```

绑定到本书的代码将这些代码片段粘在一个名为`CountingInvocationHandler`的类中。

此时我们可以使用`listProxy`调用几个方法，如下所示：

```java
listProxy.add("Adda");
listProxy.add("Mark");
listProxy.add("John");
listProxy.remove("Adda");
listProxy.add("Marcel");
listProxy.remove("Mark");
listProxy.add(0, "Akiuy");
```

让我们看看我们调用了多少次`add()`和`remove()`方法：

```java
// {add[class java.lang.Object]=4, add[int, class java.lang.Object]=1}
invocationHandler.countOf("add");

// {remove[class java.lang.Object]=2}
invocationHandler.countOf("remove");
```

因为`add()`方法是通过它的两个签名调用的，所以得到的`Map`包含两个条目。

# 总结

这是本章的最后一个问题。希望我们已经完成了对 Java 反射 API 的全面遍历。我们已经详细讨论了有关类、接口、构造器、方法、字段、注解等的问题

从本章下载应用以查看结果和其他详细信息。
