# C++ 高性能编程（三）

> 原文：[`annas-archive.org/md5/753c0f2773b6b78b5104ecb1b57442d4`](https://annas-archive.org/md5/753c0f2773b6b78b5104ecb1b57442d4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：范围和视图

本章将继续上一章关于算法及其局限性的内容。Ranges 库中的视图是 Algorithm 库的强大补充，它允许我们将多个转换组合成一个惰性评估的视图，覆盖元素序列。阅读完本章后，您将了解什么是范围视图，以及如何将它们与标准库中的容器、迭代器和算法结合使用。

具体来说，我们将涵盖以下主要主题：

+   算法的可组合性

+   范围适配器

+   将视图实例化为容器

+   在范围内生成、转换和抽样元素

在我们深入讨论 Ranges 库本身之前，让我们讨论一下为什么它被添加到 C++20 中，以及为什么我们想要使用它。

# Ranges 库的动机

随着 Ranges 库引入到 C++20 中，我们在实现算法时从标准库中获益的方式得到了一些重大改进。以下列表显示了新功能：

+   定义迭代器和范围要求的概念现在可以由编译器更好地检查，并在开发过程中提供更多帮助

+   `<algorithm>`头文件中所有函数的新重载都受到了刚才提到的概念的约束，并接受范围作为参数，而不是迭代器对

+   迭代器头文件中的约束迭代器

+   范围视图，使得可以组合算法

本章将重点放在最后一项上：视图的概念，它允许我们组合算法以避免将数据不必要地复制到拥有的容器中。为了充分理解这一点，让我们从算法库中的可组合性不足开始。

## 算法库的局限性

标准库算法在一个基本方面存在局限性：可组合性。让我们通过查看*第五章*，*算法*中的最后一个示例来了解这一点，我们在那里简要讨论了这个问题。如果您还记得，我们有一个类来表示特定年份和特定考试分数的`Student`。

```cpp
struct Student {
  int year_{};
  int score_{};
  std::string name_{};
  // ...
}; 
```

如果我们想要从一个大量学生的集合中找到他们第二年的最高分，我们可能会在`score_`上使用`max_element()`，但由于我们只想考虑特定年份的学生，这就变得棘手了。通过使用接受范围和投影的新算法（参见*第五章*，*算法*），我们可能会得到类似这样的结果：

```cpp
auto get_max_score(const std::vector<Student>& students, int year) {
  auto by_year = = { return s.year_ == year; }; 
  // The student list needs to be copied in
  // order to filter on the year
  auto v = std::vector<Student>{};
  std::ranges::copy_if(students, std::back_inserter(v), by_year);
  auto it = std::ranges::max_element(v, std::less{}, &Student::score_);
  return it != v.end() ? it->score_ : 0; 
} 
```

以下是一个示例，说明了它的使用方法：

```cpp
auto students = std::vector<Student>{
  {3, 120, "Niki"},
  {2, 140, "Karo"},
  {3, 190, "Sirius"},
  {2, 110, "Rani"},
   // ...
};
auto score = get_max_score(students, 2);
std::cout << score << '\n'; 
// Prints 140 
```

这个`get_max_score()`的实现很容易理解，但在使用`copy_if()`和`std::back_inserter()`时会创建不必要的`Student`对象的副本。

您现在可能会认为`get_max_score()`可以写成一个简单的`for-`循环，这样就可以避免由于`copy_if()`而产生额外的分配。

```cpp
auto get_max_score(const std::vector<Student>& students, int year) {
  auto max_score = 0;
  for (const auto& student : students) {
    if (student.year_ == year) {
      max_score = std::max(max_score, student.score_);
    }
  }
  return max_score;
} 
```

虽然在这个小例子中很容易实现，但我们希望能够通过组合小的算法构建块来实现这个算法，而不是使用单个`for`-循环从头开始实现它。

我们希望有一种语法，它与使用算法一样易读，但又能够避免在算法的每一步中构造新的容器。这就是 Ranges 库中的视图发挥作用的地方。虽然 Ranges 库包含的不仅仅是视图，但与 Algorithm 库的主要区别在于能够将本质上不同类型的迭代器组合成惰性评估的范围。

如果使用 Ranges 库中的视图编写前面的示例，它将如下所示：

```cpp
auto max_value(auto&& range) {
  const auto it = std::ranges::max_element(range);
  return it != range.end() ? *it : 0;
}
auto get_max_score(const std::vector<Student>& students, int year) {
  const auto by_year = = { return s.year_ == year; };
  return max_value(students 
    | std::views::filter(by_year)
    | std::views::transform(&Student::score_));
} 
```

现在我们又开始使用算法，因此可以避免可变变量、`for`循环和`if`语句。在我们的初始示例中，保存特定年份学生的额外向量现在已经被消除。相反，我们已经组成了一个范围视图，它代表了所有通过`by_year`谓词过滤的学生，然后转换为只暴露分数。然后将视图传递给一个小型实用程序函数`max_value()`，该函数使用`max_element()`算法来比较所选学生的分数，以找到最大值。

通过将算法链接在一起来组成算法，并同时避免不必要的复制，这就是我们开始使用 Ranges 库中的视图的动机。

# 从 Ranges 库中理解视图

Ranges 库中的视图是对范围的惰性评估迭代。从技术上讲，它们只是具有内置逻辑的迭代器，但从语法上讲，它们为许多常见操作提供了非常愉快的语法。

以下是如何使用视图来对向量中的每个数字进行平方的示例（通过迭代）：

```cpp
auto numbers = std::vector{1, 2, 3, 4};
auto square = [](auto v) {  return v * v; };
auto squared_view = std::views::transform(numbers, square);
for (auto s : squared_view) {  // The square lambda is invoked here
  std::cout << s << " ";
}
// Output: 1 4 9 16 
```

变量`squared_view`不是`numbers`向量的值平方的副本；它是一个代理对象，有一个细微的区别——每次访问一个元素时，都会调用`std::transform()`函数。这就是为什么我们说视图是惰性评估的。

从外部来看，你仍然可以像任何常规容器一样迭代`squared_view`，因此你可以执行常规算法，比如`find()`或`count()`，但在内部，你没有创建另一个容器。

如果要存储范围，可以使用`std::ranges::copy()`将视图实现为容器。（这将在本章后面进行演示。）一旦视图被复制回容器，原始容器和转换后的容器之间就不再有任何依赖关系。

使用范围，还可以创建一个过滤视图，其中只有范围的一部分是可见的。在这种情况下，只有满足条件的元素在迭代视图时是可见的：

```cpp
auto v = std::vector{4, 5, 6, 7, 6, 5, 4};
auto odd_view = 
  std::views::filter(v, [](auto i){ return (i % 2) == 1; });
for (auto odd_number : odd_view) {
  std::cout << odd_number << " ";
}
// Output: 5 7 5 
```

Ranges 库的多功能性的另一个例子是它提供了创建一个视图的可能性，该视图可以迭代多个容器，就好像它们是一个单一的列表一样：

```cpp
auto list_of_lists = std::vector<std::vector<int>> {
  {1, 2},
  {3, 4, 5},
  {5},
  {4, 3, 2, 1}
};
auto flattened_view = std::views::join(list_of_lists);
for (auto v : flattened_view) 
  std::cout << v << " ";
// Output: 1 2 3 4 5 5 4 3 2 1

auto max_value = *std::ranges::max_element(flattened_view);
// max_value is 5 
```

现在我们已经简要地看了一些使用视图的例子，让我们来检查所有视图的共同要求和属性

## 视图是可组合的

视图的全部功能来自于能够将它们组合在一起。由于它们不复制实际数据，因此可以在数据集上表达多个操作，而在内部只迭代一次。为了理解视图是如何组成的，让我们看一下我们的初始示例，但是不使用管道运算符来组合视图；相反，让我们直接构造实际的视图类。这是它的样子：

```cpp
auto get_max_score(const std::vector<Student>& s, int year) {
  auto by_year = = { return s.year_ == year; };

  auto v1 = std::ranges::ref_view{s}; // Wrap container in a view
  auto v2 = std::ranges::filter_view{v1, by_year};
  auto v3 = std::ranges::transform_view{v2, &Student::score_};
  auto it = std::ranges::max_element(v3);
  return it != v3.end() ? *it : 0;
} 
```

我们首先创建了一个`std::ranges::ref_view`，它是一个围绕容器的薄包装。在我们的情况下，它将向量`s`转换为一个便宜的视图。我们需要这个，因为我们的下一个视图`std::ranges::filter_view`需要一个视图作为它的第一个参数。正如你所看到的，我们通过引用链中的前一个视图来组成我们的下一个视图。

这种可组合视图的链当然可以任意延长。算法`max_element()`不需要知道完整链的任何信息；它只需要迭代范围`v3`，就像它是一个普通的容器一样。

以下图是`max_element()`算法、视图和输入容器之间关系的简化视图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_06_01.png)

图 6.1：顶层算法 std::ranges::max_element()从视图中提取值，这些视图惰性地处理来自底层容器（std::vector）的元素

现在，这种组合视图的方式有点冗长，如果我们试图去除中间变量`v1`和`v2`，我们最终会得到这样的东西：

```cpp
using namespace std::ranges; // _view classes live in std::ranges
auto scores = 
  transform_view{filter_view{ref_view{s}, by_year},
    &Student::score_}; 
```

现在，这可能看起来不太语法优雅。通过摆脱中间变量，我们得到了一些即使对训练有素的人来说也很难阅读的东西。我们还被迫从内到外阅读代码以理解依赖关系。幸运的是，Ranges 库为我们提供了范围适配器，这是组合视图的首选方式。

## 范围视图配有范围适配器

正如你之前看到的，Ranges 库还允许我们使用范围适配器和管道运算符来组合视图，从而获得更加优雅的语法（你将在*第十章*，*代理对象和延迟评估*中学习如何在自己的代码中使用管道运算符）。前面的代码示例可以通过使用范围适配器对象进行重写，我们会得到类似这样的东西：

```cpp
using namespace std::views; // range adaptors live in std::views
auto scores = s | filter(by_year) | transform(&Student::score_); 
```

从左到右阅读语句的能力，而不是从内到外，使得代码更容易阅读。如果你使用过 Unix shell，你可能熟悉这种用于链接命令的表示法。

Ranges 库中的每个视图都有一个相应的范围适配器对象，可以与管道运算符一起使用。在使用范围适配器时，我们还可以跳过额外的`std::ranges::ref_view`，因为范围适配器直接与`viewable_ranges`一起工作，即可以安全转换为`view`的范围。

您可以将范围适配器视为一个全局无状态对象，它实现了两个函数：`operator()()`和`operator|()`。这两个函数都构造并返回视图对象。管道运算符是在前面的示例中使用的。但也可以使用调用运算符使用嵌套语法来形成视图，如下所示：

```cpp
using namespace std::views;
auto scores = transform(filter(s, by_year), &Student::score_); 
```

同样，在使用范围适配器时，无需将输入容器包装在`ref_view`中。

总之，Ranges 库中的每个视图包括：

+   一个类模板（实际视图类型），它操作视图对象，例如`std::ranges::transform_view`。这些视图类型可以在命名空间`std::ranges`下找到。

+   一个范围适配器对象，它从范围创建视图类的实例，例如`std::views::transform`。所有范围适配器都实现了`operator()()`和`operator|()`，这使得可以使用管道运算符或嵌套来组合转换。范围适配器对象位于命名空间`std::views`下。

## 视图是具有复杂性保证的非拥有范围

在前一章中，介绍了范围的概念。任何提供`begin()`和`end()`函数的类型，其中`begin()`返回一个迭代器，`end()`返回一个哨兵，都可以作为范围。我们得出结论，所有标准容器都是范围。容器拥有它们的元素，因此我们可以称它们为拥有范围。

视图也是一个范围，它提供`begin()`和`end()`函数。然而，与容器不同，视图不拥有它们所覆盖的范围中的元素。

视图的构造必须是一个常量时间操作，*O(1)*。它不能执行任何依赖于底层容器大小的工作。对于视图的赋值、复制、移动和销毁也是如此。这使得在使用视图来组合多个算法时，很容易推断性能。它还使得视图无法拥有元素，因为这将需要在构造和销毁时具有线性时间复杂度。

## 视图不会改变底层容器

乍一看，视图可能看起来像是输入容器的变异版本。然而，容器根本没有发生变异：所有处理都是在迭代器中进行的。视图只是一个代理对象，当迭代时，*看起来*像是一个变异的容器。

```cpp
int to std::string:
```

```cpp
auto ints = std::list{2, 3, 4, 2, 1};
auto strings = ints 
  | std::views::transform([](auto i) { return std::to_string(i); }); 
```

也许我们有一个在容器上操作的函数，我们想要使用范围算法进行转换，然后我们想要返回并将其存储回容器。例如，在上面的例子中，我们可能确实想要将字符串存储在一个单独的容器中。您将在下一节中学习如何做到这一点。

## 视图可以实体化为容器

有时，我们想要将视图存储在容器中，即**实体化**视图。所有视图都可以实体化为容器，但这并不像您希望的那样容易。C++20 提出了一个名为`std::ranges::to<T>()`的函数模板，它可以将视图转换为任意容器类型`T`，但并没有完全实现。希望我们在将来的 C++版本中能够得到类似的东西。在那之前，我们需要做更多的工作来实体化视图。

在前面的例子中，我们将`ints`转换为`std::strings`，如下所示：

```cpp
auto ints = std::list{2, 3, 4, 2, 1};
auto r = ints 
  | std::views::transform([](auto i) { return std::to_string(i); }); 
```

现在，如果我们想要将范围`r`实体化为一个向量，我们可以像这样使用`std::ranges::copy（）`：

```cpp
auto vec = std::vector<std::string>{};
std::ranges::copy(r, std::back_inserter(vec)); 
```

实体化视图是一个常见的操作，所以如果我们有一个通用的实用程序来处理这种情况会很方便。假设我们想要将一些任意视图实体化为`std::vector`；我们可以使用一些通用编程来得到以下方便的实用函数：

```cpp
auto to_vector(auto&& r) {
  std::vector<std::ranges::range_value_t<decltype(r)>> v;
  if constexpr(std::ranges::sized_range<decltype(r)>) {
    v.reserve(std::ranges::size(r));
  }
  std::ranges::copy(r, std::back_inserter(v));
  return v;
} 
https://timur.audio/how-to-make-a-container-from-a-c20-range, which is well worth a read. 
```

在本书中，我们还没有讨论过泛型编程，但接下来的几章将解释使用`auto`参数类型和`if constexpr`。

我们正在使用`reserve（）`来优化此函数的性能。它将为范围中的所有元素预先分配足够的空间，以避免进一步的分配。但是，我们只能在知道范围的大小时调用`reserve（）`，因此我们必须使用`if constexpr`语句在编译时检查范围是否为`size_range`。

有了这个实用程序，我们可以将某种类型的容器转换为持有另一种任意类型元素的向量。让我们看看如何使用`to_vector（）`将整数列表转换为`std::strings`的向量。这是一个例子：

```cpp
auto ints = std::list{2, 3, 4, 2, 1};
auto r = ints 
  | std::views::transform([](auto i) { return std::to_string(i); });
auto strings = to_vector(r); 
// strings is now a std::vector<std::string> 
```

请记住，一旦视图被复制回容器，原始容器和转换后的容器之间就不再有任何依赖关系。这也意味着实体化是一种急切的操作，而所有视图操作都是惰性的。

## 视图是惰性评估的

视图执行的所有工作都是惰性的。这与`<algorithm>`头文件中的函数相反，后者在调用时立即对所有元素执行其工作。

您已经看到`std::views::filter`视图可以替换算法`std::copy_if（）`，而`std::views::transform`视图可以替换`std::transform（）`算法。当我们将视图用作构建块并将它们链接在一起时，我们通过避免急切算法所需的容器元素的不必要复制而受益于惰性评估。

但是`std::sort（）`呢？有对应的排序视图吗？答案是否定的，因为它需要视图首先急切地收集所有元素以找到要返回的第一个元素。相反，我们必须自己显式调用视图上的排序来做到这一点。在大多数情况下，我们还需要在排序之前实体化视图。我们可以通过一个例子来澄清这一点。假设我们有一个通过某个谓词过滤的数字向量，如下所示：

```cpp
auto vec = std::vector{4, 2, 7, 1, 2, 6, 1, 5};
auto is_odd = [](auto i) { return i % 2 == 1; };
auto odd_numbers = vec | std::views::filter(is_odd); 
```

如果我们尝试使用`std::ranges::sort（）`或`std::sort（）`对我们的视图`odd_numbers`进行排序，我们将收到编译错误：

```cpp
std::ranges::sort(odd_numbers); // Doesn't compile 
```

编译器抱怨`odd_numbers`范围提供的迭代器类型。排序算法需要随机访问迭代器，但这不是我们的视图提供的迭代器类型，即使底层输入容器是`std::vector`。我们需要在排序之前实体化视图：

```cpp
auto v = to_vector(odd_numbers);
std::ranges::sort(v);
// v is now 1, 1, 5, 7 
```

但为什么这是必要的呢？答案是这是惰性评估的结果。过滤视图（以及许多其他视图）在需要延迟读取一个元素时无法保留底层范围（在本例中为`std::vector`）的迭代器类型。

那么，有没有可以排序的视图？是的，一个例子是`std::views::take`，它返回范围中的前*n*个元素。以下示例在排序之前编译和运行良好，无需在排序之前实现视图：

```cpp
auto vec = std::vector{4, 2, 7, 1, 2, 6, 1, 5};
auto first_half = vec | std::views::take(vec.size() / 2);
std::ranges::sort(first_half);
// vec is now 1, 2, 4, 7, 2, 6, 1, 5 
```

迭代器的质量已经得到保留，因此可以对`first_half`视图进行排序。最终结果是底层向量`vec`中前一半的元素已经被排序。

您现在对来自 Ranges 库的视图以及它们的工作原理有了很好的理解。在下一节中，我们将探讨如何使用标准库中包含的视图。

# 标准库中的视图

到目前为止，在本章中，我们一直在谈论来自 Ranges 库的视图。正如前面所述，这些视图类型需要在常数时间内构造，并且还具有常数时间的复制、移动和赋值运算符。然而，在 C++中，我们在 C++20 添加 Ranges 库之前就已经谈论过视图类。这些视图类是非拥有类型，就像`std::ranges::view`一样，但没有复杂性保证。

在本节中，我们将首先探索与`std::ranges::view`概念相关联的 Ranges 库中的视图，然后转到与`std::ranges::view`不相关联的`std::string_view`和`std::span`。

## 范围视图

Ranges 库中已经有许多视图，我认为我们将在未来的 C++版本中看到更多这样的视图。本节将快速概述一些可用视图，并根据其功能将它们放入不同的类别中。

### 生成视图

```cpp
-2, -1, 0, and 1:
```

```cpp
for (auto i : std::views::iota(-2, 2)) {
  std::cout << i << ' ';
}
// Prints -2 -1 0 1 
```

通过省略第二个参数，`std::views::iota`将在请求时产生无限数量的值。

### 转换视图

转换视图是转换范围的元素或范围结构的视图。一些示例包括：

+   `std::views::transform`：转换每个元素的值和/或类型

+   `std::views::reverse`：返回输入范围的反转版本

+   `std::views::split`：拆分每个元素并将每个元素拆分为子范围。结果范围是范围的范围

+   `std::views::join`：split 的相反操作；展平所有子范围

以下示例使用`split`和`join`从逗号分隔的值字符串中提取所有数字：

```cpp
auto csv = std::string{"10,11,12"};
auto digits = csv 
  | std::views::split(',')      // [ [1, 0], [1, 1], [1, 2] ]
  | std::views::join;           // [ 1, 0, 1, 1, 1, 2 ]
for (auto i : digits) {   std::cout << i; }
// Prints 101112 
```

### 采样视图

采样视图是选择范围中的元素子集的视图，例如：

+   `std::views::filter`：仅返回满足提供的谓词的元素

+   `std::views::take`：返回范围中的*n*个第一个元素

+   `std::views::drop`：在丢弃前*n*个元素后返回范围中的所有剩余元素

在本章中，您已经看到了许多使用`std::views::filter`的示例；这是一个非常有用的视图。`std::views::take`和`std::views::drop`都有一个`_while`版本，它接受一个谓词而不是一个数字。以下是使用`take`和`drop_while`的示例：

```cpp
auto vec = std::vector{1, 2, 3, 4, 5, 4, 3, 2, 1};
 auto v = vec
   | std::views::drop_while([](auto i) { return i < 5; })
   | std::views::take(3);
 for (auto i : v) { std::cout << i << " "; }
 // Prints 5 4 3 
```

此示例使用`drop_while`从前面丢弃小于 5 的值。剩下的元素传递给`take`，它返回前三个元素。现在到我们最后一类范围视图。

### 实用视图

在本章中，您已经看到了一些实用视图的用法。当您有想要转换或视为视图的东西时，它们非常方便。在这些视图类别中的一些示例是`ref_view`、`all_view`、`subrange`、`counted`和`istream_view`。

以下示例向您展示了如何读取一个包含浮点数的文本文件，然后打印它们。

假设我们有一个名为`numbers.txt`的文本文件，其中包含重要的浮点数，如下所示：

```cpp
1.4142 1.618 2.71828 3.14159 6.283 ... 
```

然后，我们可以通过使用`std::ranges::istream_view`来创建一个`floats`的视图：

```cpp
auto ifs = std::ifstream("numbers.txt");
for (auto f : std::ranges::istream_view<float>(ifs)) {
  std::cout << f << '\n';
}
ifs.close(); 
```

通过创建一个`std::ranges::istream_view`并将其传递给一个`istream`对象，我们可以简洁地处理来自文件或任何其他输入流的数据。

Ranges 库中的视图已经经过精心选择和设计。在未来的标准版本中很可能会有更多的视图。了解不同类别的视图有助于我们将它们区分开，并在需要时更容易找到它们。

## 重新审视 std::string_view 和 std::span

值得注意的是，标准库在 Ranges 库之外还提供了其他视图。在*第四章*，*数据结构*中引入的`std::string_view`和`std::span`都是非拥有范围，非常适合与 Ranges 视图结合使用。

与 Ranges 库中的视图不同，不能保证这些视图可以在常数时间内构造。例如，从以 null 结尾的 C 风格字符串构造`std::string_view`可能会调用`strlen()`，这是一个*O(n)*操作。

假设出于某种原因，我们有一个重置范围中前`n`个值的函数：

```cpp
auto reset(std::span<int> values, int n) {
  for (auto& i : std::ranges::take_view{values, n}) {
    i = int{};
  }
} 
```

在这种情况下，不需要使用范围适配器来处理`values`，因为`values`已经是一个视图。通过使用`std::span`，我们可以传递内置数组或容器，如`std::vector`：

```cpp
int a[]{33, 44, 55, 66, 77};
reset(a, 3); 
// a is now [0, 0, 0, 66, 77]
auto v = std::vector{33, 44, 55, 66, 77};
reset(v, 2); 
// v is now [0, 0, 55, 66, 77] 
```

类似地，我们可以将`std::string_view`与 Ranges 库一起使用。以下函数将`std::string_view`的内容拆分为`std::vector`的`std::string`元素：

```cpp
auto split(std::string_view s, char delim) {
  const auto to_string = [](auto&& r) -> std::string {
    const auto cv = std::ranges::common_view{r};
    return {cv.begin(), cv.end()};
  };
  return to_vector(std::ranges::split_view{s, delim} 
    | std::views::transform(to_string));
} 
```

lambda `to_string`将一系列`char`转换为`std::string`。`std::string`构造函数需要相同的迭代器和 sentinel 类型，因此范围被包装在`std::ranges::common_view`中。实用程序`to_vector()`将视图实现并返回`std::vector<std::string>`。`to_vector()`在本章前面已经定义过。

我们的`split()`函数现在可以用于`const char*`字符串和`std::string`对象，如下所示：

```cpp
 const char* c_str = "ABC,DEF,GHI";  // C style string
  const auto v1 = split(c_str, ',');  // std::vector<std::string>
  const auto s = std::string{"ABC,DEF,GHI"};
  const auto v2 = split(s, ',');      // std::vector<std::string>
  assert(v1 == v2);                   // true 
```

我们现在将通过谈论我们期望在未来版本的 C++中看到的 Ranges 库来结束这一章。

# Ranges 库的未来

在 C++20 中被接受的 Ranges 库是基于 Eric Niebler 编写的库，可以在[`github.com/ericniebler/range-v3`](https://github.com/ericniebler/range-v3)上找到。目前，这个库中只有一小部分组件已经成为标准的一部分，但更多的东西可能很快就会被添加进来。

除了许多有用的视图尚未被接受，例如`group_by`、`zip`、`slice`和`unique`之外，还有**actions**的概念，可以像视图一样进行管道传递。但是，与视图一样，操作执行范围的急切变异，而不是像视图那样进行惰性求值。排序是典型操作的一个例子。

如果您等不及这些功能被添加到标准库中，我建议您看一下 range-v3 库。

# 总结

这一章介绍了使用范围视图构建算法背后的许多动机。通过使用视图，我们可以高效地组合算法，并使用管道操作符简洁的语法。您还学会了一个类成为视图意味着什么，以及如何使用将范围转换为视图的范围适配器。

视图不拥有其元素。构造范围视图需要是一个常数时间操作，所有视图都是惰性求值的。您已经看到了如何将容器转换为视图的示例，以及如何将视图实现为拥有容器。

最后，我们简要概述了标准库中提供的视图，以及 C++中范围的可能未来。

这一章是关于容器、迭代器、算法和范围的系列的最后一章。我们现在将转向 C++中的内存管理。


# 第七章：内存管理

在阅读了前面的章节之后，应该不会再感到惊讶，我们处理内存的方式对性能有很大影响。CPU 花费大量时间在 CPU 寄存器和主内存之间传输数据（加载和存储数据到主内存和从主内存中读取数据）。正如在*第四章*，*数据结构*中所示，CPU 使用内存缓存来加速对内存的访问，程序需要对缓存友好才能运行得快。

本章将揭示更多关于计算机如何处理内存的方面，以便您知道在调整内存使用时必须考虑哪些事项。此外，本章还涵盖了：

+   自动内存分配和动态内存管理。

+   C++对象的生命周期以及如何管理对象所有权。

+   高效的内存管理。有时，存在严格的内存限制，迫使我们保持数据表示紧凑，有时我们有大量的可用内存，但需要通过使内存管理更高效来加快程序运行速度。

+   如何最小化动态内存分配。分配和释放动态内存相对昂贵，有时我们需要避免不必要的分配以使程序运行更快。

我们将从解释一些概念开始这一章，这些概念在我们深入研究 C++内存管理之前需要理解。这个介绍将解释虚拟内存和虚拟地址空间，堆内存与栈内存，分页和交换空间。

# 计算机内存

计算机的物理内存是所有运行在系统上的进程共享的。如果一个进程使用了大量内存，其他进程很可能会受到影响。但从程序员的角度来看，我们通常不必担心其他进程正在使用的内存。这种内存的隔离是因为今天的大多数操作系统都是**虚拟内存**操作系统，它们提供了一个假象，即一个进程拥有了所有的内存。每个进程都有自己的**虚拟地址空间**。

## 虚拟地址空间

程序员看到的虚拟地址空间中的地址由操作系统和处理器的**内存管理单元**（**MMU**）映射到物理地址。每次访问内存地址时都会发生这种映射或转换。

这种额外的间接层使操作系统能够使用物理内存来存储进程当前正在使用的部分，并将其余的虚拟内存备份到磁盘上。在这个意义上，我们可以把物理主内存看作是虚拟内存空间的缓存，而虚拟内存空间位于辅助存储上。通常用于备份内存页面的辅助存储区域通常称为**交换空间**、**交换文件**或简单地称为**页面文件**，具体取决于操作系统。

虚拟内存使进程能够拥有比物理地址空间更大的虚拟地址空间，因为未使用的虚拟内存不需要占用物理内存。

## 内存页面

实现虚拟内存的最常见方式是将地址空间划分为称为**内存页面**的固定大小块。当一个进程访问虚拟地址处的内存时，操作系统会检查内存页面是否由物理内存（页面帧）支持。如果内存页面没有映射到主内存中，将会发生硬件异常，并且页面将从磁盘加载到内存中。这种硬件异常称为**页面错误**。这不是错误，而是为了从磁盘加载数据到内存而必要的中断。不过，正如你可能已经猜到的那样，这与读取已经驻留在内存中的数据相比非常慢。

当主内存中没有更多可用的页面帧时，必须驱逐一个页面帧。如果要驱逐的页面是脏的，也就是说，自从上次从磁盘加载以来已经被修改，那么它需要被写入磁盘才能被替换。这种机制称为**分页**。如果内存页面没有被修改，那么内存页面就会被简单地驱逐。

并非所有支持虚拟内存的操作系统都支持分页。例如，iOS 具有虚拟内存，但脏页面永远不会存储在磁盘上；只有干净的页面才能从内存中驱逐。如果主内存已满，iOS 将开始终止进程，直到再次有足够的空闲内存。Android 使用类似的策略。不将内存页面写回移动设备的闪存存储的原因之一是它会消耗电池电量，还会缩短闪存存储本身的寿命。

下图显示了两个运行中的进程。它们都有自己的虚拟内存空间。一些页面映射到物理内存，而另一些则没有。如果进程 1 需要使用从地址 0x1000 开始的内存页面，就会发生页面错误。然后该内存页面将被映射到一个空闲的内存帧。还要注意虚拟内存地址与物理地址不同。进程 1 的第一个内存页面，从虚拟地址 0x0000 开始，映射到从物理地址 0x4000 开始的内存帧：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_01.png)

图 7.1：虚拟内存页面，映射到物理内存中的内存帧。未使用的虚拟内存页面不必占用物理内存。

## 抖动

**抖动**可能发生在系统的物理内存不足且不断分页的情况下。每当一个进程在 CPU 上被调度时，它试图访问已被分页出去的内存。加载新的内存页面意味着其他页面首先必须存储在磁盘上。在磁盘和内存之间来回移动数据通常非常缓慢；在某些情况下，这几乎会使计算机停滞，因为系统花费了所有的时间在分页上。查看系统的页面错误频率是确定程序是否开始抖动的好方法。

了解硬件和操作系统如何处理内存的基础知识对于优化性能很重要。接下来，我们将看到在执行 C++程序时内存是如何处理的。

# 进程内存

堆栈和堆是 C++程序中最重要的两个内存段。还有静态存储和线程本地存储，但我们稍后会更多地讨论这些。实际上，严格来说，C++并不谈论堆栈和堆；相反，它谈论自由存储、存储类和对象的存储持续时间。然而，由于堆栈和堆的概念在 C++社区中被广泛使用，并且我们所知道的所有 C++实现都使用堆栈来实现函数调用和管理局部变量的自动存储，因此了解堆栈和堆是很重要的。

在本书中，我还将使用术语*堆栈*和*堆*而不是对象的存储持续时间。我将使用术语*堆*和*自由存储*互换使用，并不会对它们进行区分。

堆栈和堆都驻留在进程的虚拟内存空间中。堆栈是所有局部变量驻留的地方；这也包括函数的参数。每次调用函数时，堆栈都会增长，并在函数返回时收缩。每个线程都有自己的堆栈，因此堆栈内存可以被视为线程安全。另一方面，堆是一个在运行进程中所有线程之间共享的全局内存区域。当我们使用`new`（或 C 库函数`malloc()`和`calloc()`）分配内存时，堆会增长，并在使用`delete`（或`free()`）释放内存时收缩。通常，堆从低地址开始增长，向上增长，而堆栈从高地址开始增长，向下增长。*图 7.2*显示了堆栈和堆在虚拟地址空间中以相反方向增长：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_02.png)

图 7.2：进程的地址空间。堆栈和堆以相反方向增长。

接下来的部分将提供有关堆栈和堆的更多细节，并解释在我们编写的 C++程序中何时使用这些内存区域。

## 堆栈内存

堆栈在许多方面与堆不同。以下是堆栈的一些独特属性：

+   堆栈是一个连续的内存块。

+   它有一个固定的最大大小。如果程序超出最大堆栈大小，程序将崩溃。这种情况称为堆栈溢出。

+   堆栈内存永远不会变得分散。

+   从堆栈中分配内存（几乎）总是很快的。页面错误可能会发生，但很少见。

+   程序中的每个线程都有自己的堆栈。

本节中接下来的代码示例将检查其中一些属性。让我们从分配和释放开始，以了解堆栈在程序中的使用方式。

通过检查堆栈分配的数据的地址，我们可以轻松找出堆栈增长的方向。以下示例代码演示了进入和离开函数时堆栈的增长和收缩：

```cpp
void func1() {
  auto i = 0;
  std::cout << "func1(): " << std::addressof(i) << '\n';
}
void func2() {
  auto i = 0;
  std::cout << "func2(): " << std::addressof(i) << '\n';
  func1();
}

int main() { 
  auto i = 0; 
  std::cout << "main():  " << std::addressof(i) << '\n'; 
  func2();
  func1(); 
} 
```

运行程序时可能的输出如下：

```cpp
main():  0x7ea075ac 
func2(): 0x7ea07594 
func1(): 0x7ea0757c 
func1(): 0x7ea07594 
```

通过打印堆栈分配的整数的地址，我们可以确定堆栈在我的平台上增长了多少，以及增长的方向。每次我们进入`func1()`或`func2()`时，堆栈都会增加 24 个字节。整数`i`将分配在堆栈上，长度为 4 个字节。剩下的 20 个字节包含在函数结束时需要的数据，例如返回地址，可能还有一些用于对齐的填充。

以下图示说明了程序执行期间堆栈的增长和收缩。第一个框说明了程序刚进入`main()`函数时内存的样子。第二个框显示了当我们执行`func1()`时堆栈的增加，依此类推：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_03.png)

图 7.3：当进入函数时，堆栈增长和收缩

堆栈分配的总内存是在线程启动时创建的固定大小的连续内存块。那么，堆栈有多大，当我们达到堆栈的限制时会发生什么呢？

如前所述，每次程序进入函数时，堆栈都会增长，并在函数返回时收缩。每当我们在同一函数内创建新的堆栈变量时，堆栈也会增长，并在此类变量超出范围时收缩。堆栈溢出的最常见原因是深度递归调用和/或在堆栈上使用大型自动变量。堆栈的最大大小在不同平台之间有所不同，并且还可以为单个进程和线程进行配置。

让我们看看是否可以编写一个程序来查看默认情况下系统的堆栈有多大。我们将首先编写一个名为`func()`的函数，该函数将无限递归。在每个函数的开始，我们将分配一个 1 千字节的变量，每次进入`func()`时都会将其放入堆栈。每次执行`func()`时，我们打印堆栈的当前大小：

```cpp
void func(std::byte* stack_bottom_addr) { 
  std::byte data[1024];     
  std::cout << stack_bottom_addr - data << '\n'; 
  func(stack_bottom_addr); 
} 

int main() { 
  std::byte b; 
  func(&b); 
} 
```

堆栈的大小只是一个估计值。我们通过从`main()`中定义的第一个局部变量的地址减去`func()`中定义的第一个局部变量的地址来计算它。

当我用 Clang 编译代码时，我收到一个警告，即`func()`永远不会返回。通常，这是一个我们不应该忽略的警告，但这次，这正是我们想要的结果，所以我们忽略了警告并运行了程序。程序在堆栈达到其限制后不久崩溃。在程序崩溃之前，它设法打印出数千行堆栈的当前大小。输出的最后几行看起来像这样：

```cpp
... 
8378667 
8379755 
8380843 
```

由于我们在减去`std::byte`指针，所以大小以字节为单位，因此在我的系统上，堆栈的最大大小似乎约为 8 MB。在类 Unix 系统上，可以使用`ulimit`命令和选项`-s`来设置和获取进程的堆栈大小：

```cpp
$ ulimit -s
$ 8192 
```

`ulimit`（用户限制的缩写）返回以千字节为单位的最大堆栈大小的当前设置。`ulimit`的输出证实了我们实验的结果：如果我没有显式配置，我的 Mac 上的堆栈大约为 8 MB。

在 Windows 上，默认的堆栈大小通常设置为 1 MB。如果堆栈大小没有正确配置，那么在 Windows 上运行良好的程序在 macOS 上可能会因堆栈溢出而崩溃。

通过这个例子，我们还可以得出结论，我们不希望用尽堆栈内存，因为当发生这种情况时，程序将崩溃。在本章的后面，我们将看到如何实现一个基本的内存分配器来处理固定大小的分配。然后我们将了解到，堆栈只是另一种类型的内存分配器，可以非常高效地实现，因为使用模式总是顺序的。我们总是在堆栈的顶部（连续内存的末尾）请求和释放内存。这确保了堆栈内存永远不会变得碎片化，并且我们可以通过仅移动堆栈指针来分配和释放内存。

## 堆内存

堆（或者更正确的术语是自由存储区，在 C++中）是动态存储数据的地方。如前所述，堆在多个线程之间共享，这意味着堆的内存管理需要考虑并发性。这使得堆中的内存分配比堆栈分配更复杂，因为堆中的内存分配是每个线程的本地分配。

堆栈内存的分配和释放模式是顺序的，即内存总是按照分配的相反顺序进行释放。另一方面，对于动态内存，分配和释放可以任意发生。对象的动态生命周期和内存分配的变量大小增加了**内存碎片**的风险。

理解内存碎片问题的简单方法是通过一个示例来说明内存如何发生碎片化。假设我们有一个小的连续内存块，大小为 16 KB，我们正在从中分配内存。我们正在分配两种类型的对象：类型**A**，大小为 1 KB，和类型**B**，大小为 2 KB。我们首先分配一个类型**A**的对象，然后是一个类型**B**的对象。这样重复，直到内存看起来像下面的图像：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_04.png)

图 7.4：分配类型 A 和 B 对象后的内存

接下来，所有类型**A**的对象都不再需要，因此它们可以被释放。内存现在看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_05.png)

图 7.5：释放类型 A 对象后的内存

现在有 10KB 的内存正在使用，还有 6KB 可用。现在，假设我们想要分配一个类型为**B**的新对象，它占用 2KB。尽管有 6KB 的空闲内存，但我们找不到 2KB 的内存块，因为内存已经变得碎片化。

现在您已经对计算机内存在运行过程中的结构和使用有了很好的理解，现在是时候探索 C++对象在内存中的生存方式了。

# 内存中的对象

我们在 C++程序中使用的所有对象都驻留在内存中。在这里，我们将探讨如何在内存中创建和删除对象，并描述对象在内存中的布局方式。

## 创建和删除对象

在本节中，我们将深入探讨使用`new`和`delete`的细节。考虑以下使用`new`在自由存储器上创建对象，然后使用`delete`删除它的方式：

```cpp
auto* user = new User{"John"};  // allocate and construct 
user->print_name();             // use object 
delete user;                    // destruct and deallocate 
```

我不建议以这种方式显式调用`new`和`delete`，但现在让我们忽略这一点。让我们来重点讨论一下；正如注释所建议的那样，`new`实际上做了两件事，即：

+   分配内存以容纳`User`类型的新对象

+   通过调用`User`类的构造函数在分配的内存空间中构造一个新的`User`对象

同样的事情也适用于`delete`，它：

+   通过调用其析构函数来销毁`User`对象

+   释放`User`对象所在的内存

实际上，在 C++中可以将这两个操作（内存分配和对象构造）分开。这很少使用，但在编写库组件时有一些重要和合法的用例。

### 放置 new

C++允许我们将内存分配与对象构造分开。例如，我们可以使用`malloc()`分配一个字节数组，并在该内存区域中构造一个新的`User`对象。看一下以下代码片段：

```cpp
auto* memory = std::malloc(sizeof(User));
auto* user = ::new (memory) User("john"); 
```

使用`::new (memory)`的可能不熟悉的语法称为**放置 new**。这是`new`的一种非分配形式，它只构造一个对象。`::`前面的双冒号确保了从全局命名空间进行解析，以避免选择`operator new`的重载版本。

在前面的示例中，放置 new 构造了`User`对象，并将其放置在指定的内存位置。由于我们使用`std::malloc()`为单个对象分配内存，所以它保证了正确的对齐（除非`User`类已声明为过对齐）。稍后，我们将探讨在使用放置 new 时必须考虑对齐的情况。

没有放置删除，因此为了销毁对象并释放内存，我们需要显式调用析构函数，然后释放内存：

```cpp
user->~User();
std::free(memory); 
```

这是您应该显式调用析构函数的唯一时机。除非您使用放置 new 创建了一个对象，否则永远不要这样调用析构函数。

C++17 在`<memory>`中引入了一组实用函数，用于在不分配或释放内存的情况下构造和销毁对象。因此，现在可以使用一些以`std::uninitialized_`开头的函数来构造、复制和移动对象到未初始化的内存区域，而不是调用放置 new。而且，现在可以使用`std::destroy_at()`在特定内存地址上销毁对象，而无需释放内存。

前面的示例可以使用这些新函数重写。下面是它的样子：

```cpp
auto* memory = std::malloc(sizeof(User));
auto* user_ptr = reinterpret_cast<User*>(memory);
std::uninitialized_fill_n(user_ptr, 1, User{"john"});
std::destroy_at(user_ptr);
std::free(memory); 
```

C++20 还引入了`std::construct_at()`，它使得可以用它来替换`std::uninitialized_fill_n()`的调用：

```cpp
std::construct_at(user_ptr, User{"john"});        // C++20 
```

请记住，我们展示这些裸露的低级内存设施是为了更好地理解 C++中的内存管理。在 C++代码库中，使用`reinterpret_cast`和这里演示的内存实用程序应该保持绝对最低限度。

接下来，您将看到当我们使用`new`和`delete`表达式时调用了哪些操作符。

### new 和 delete 操作符

函数 `operator new` 负责在调用 `new` 表达式时分配内存。`new` 运算符可以是全局定义的函数，也可以是类的静态成员函数。可以重载全局运算符 `new` 和 `delete`。在本章后面，我们将看到在分析内存使用情况时，这可能是有用的。

以下是如何做到这一点：

```cpp
auto operator new(size_t size) -> void* { 
  void* p = std::malloc(size); 
  std::cout << "allocated " << size << " byte(s)\n"; 
  return p; 
} 

auto operator delete(void* p) noexcept -> void { 
  std::cout << "deleted memory\n"; 
  return std::free(p); 
} 
```

我们可以验证我们重载的运算符在创建和删除 `char` 对象时是否真的被使用：

```cpp
auto* p = new char{'a'}; // Outputs "allocated 1 byte(s)"
delete p;                // Outputs "deleted memory" 
```

使用 `new[]` 和 `delete[]` 表达式创建和删除对象数组时，还使用了另一对运算符，即 `operator new[]` 和 `operator delete[]`。我们可以以相同的方式重载这些运算符：

```cpp
auto operator new[](size_t size) -> void* {
  void* p = std::malloc(size); 
  std::cout << "allocated " << size << " byte(s) with new[]\n"; 
  return p; 
} 

auto operator delete[](void* p) noexcept -> void { 
  std::cout << "deleted memory with delete[]\n"; 
  return std::free(p); 
} 
```

请记住，如果重载了 `operator new`，还应该重载 `operator delete`。分配和释放内存的函数是成对出现的。内存应该由分配该内存的分配器释放。例如，使用 `std::malloc()` 分配的内存应始终使用 `std::free()` 释放，而使用 `operator new[]` 分配的内存应使用 `operator delete[]` 释放。

还可以覆盖特定于类的 `operator new` 或 `operator delete`。这可能比重载全局运算符更有用，因为更有可能需要为特定类使用自定义动态内存分配器。

在这里，我们正在为 `Document` 类重载 `operator new` 和 `operator delete`：

```cpp
class Document { 
// ...
public:  
  auto operator new(size_t size) -> void* {
    return ::operator new(size);
  } 
  auto operator delete(void* p) -> void {
    ::operator delete(p); 
  } 
}; 
```

当我们创建新的动态分配的 `Document` 对象时，将使用特定于类的 `new` 版本：

```cpp
auto* p = new Document{}; // Uses class-specific operator new
delete p; 
```

如果我们希望使用全局 `new` 和 `delete`，仍然可以通过使用全局作用域 (`::`) 来实现：

```cpp
auto* p = ::new Document{}; // Uses global operator new
::delete p; 
```

我们将在本章后面讨论内存分配器，然后我们将看到重载的 `new` 和 `delete` 运算符的使用。

迄今为止，总结一下，`new`表达式涉及两个方面：分配和构造。`operator new`分配内存，您可以全局或按类重载它以自定义动态内存管理。放置 new 可用于在已分配的内存区域中构造对象。

另一个重要但相当低级的主题是我们需要了解以有效使用内存的**内存对齐**。

## 内存对齐

CPU 每次从内存中读取一个字时，将其读入寄存器。64 位架构上的字大小为 64 位，32 位架构上为 32 位，依此类推。为了使 CPU 在处理不同数据类型时能够高效工作，它对不同类型的对象所在的地址有限制。C++ 中的每种类型都有一个对齐要求，定义了内存中应该位于某种类型对象的地址。

如果类型的对齐方式为 1，则表示该类型的对象可以位于任何字节地址。如果类型的对齐方式为 2，则表示允许地址之间的字节数为 2。或者引用 C++ 标准的说法：

> "对齐是一个实现定义的整数值，表示给定对象可以分配的连续地址之间的字节数。"

我们可以使用 `alignof` 来查找类型的对齐方式：

```cpp
// Possible output is 4  
std::cout << alignof(int) << '\n'; 
```

当我运行此代码时，输出为 `4`，这意味着在我的平台上，类型 `int` 的对齐要求为 4 字节。

以下图示显示了来自具有 64 位字的系统的内存的两个示例。上排包含三个 4 字节整数，它们位于 4 字节对齐的地址上。CPU 可以以高效的方式将这些整数加载到寄存器中，并且在访问其中一个 `int` 成员时永远不需要读取多个字。将其与第二排进行比较，其中包含两个 `int` 成员，它们位于不对齐的地址上。第二个 `int` 甚至跨越了两个字的边界。在最好的情况下，这只是低效，但在某些平台上，程序将崩溃：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_06.png)

图 7.6：包含整数的内存的两个示例，分别位于对齐和不对齐的内存地址

假设我们有一个对齐要求为 2 的类型。C++标准没有规定有效地址是 1、3、5、7...还是 0、2、4、6...。我们所知道的所有平台都是从 0 开始计算地址，因此实际上我们可以通过使用取模运算符（`%`）来检查对象是否正确对齐。

但是，如果我们想编写完全可移植的 C++代码，我们需要使用`std::align()`而不是取模来检查对象的对齐。`std::align()`是来自`<memory>`的一个函数，它将根据我们传递的对齐方式调整指针。如果我们传递给它的内存地址已经对齐，指针将不会被调整。因此，我们可以使用`std::align()`来实现一个名为`is_aligned()`的小型实用程序函数，如下所示：

```cpp
bool is_aligned(void* ptr, std::size_t alignment) {
  assert(ptr != nullptr);
  assert(std::has_single_bit(alignment)); // Power of 2
  auto s = std::numeric_limits<std::size_t>::max();
  auto aligned_ptr = ptr;
  std::align(alignment, 1, aligned_ptr, s);
  return ptr == aligned_ptr;
} 
```

首先，我们确保`ptr`参数不为空，并且`alignment`是 2 的幂，这是 C++标准中规定的要求。我们使用 C++20 `<bit>`头文件中的`std::has_single_bit()`来检查这一点。接下来，我们调用`std::align()`。`std::align()`的典型用法是当我们有一定大小的内存缓冲区，我们想要在其中存储具有一定对齐要求的对象。在这种情况下，我们没有缓冲区，也不关心对象的大小，因此我们说对象的大小为 1，缓冲区是`std::size_t`的最大值。然后，我们可以比较原始的`ptr`和调整后的`aligned_ptr`，以查看原始指针是否已经对齐。我们将在接下来的示例中使用这个实用程序。

使用`new`或`std::malloc()`分配内存时，我们获得的内存应正确对齐为我们指定的类型。以下代码显示，为`int`分配的内存在我的平台上至少是 4 字节对齐的：

```cpp
auto* p = new int{};
assert(is_aligned(p, 4ul)); // True 
```

实际上，`new`和`malloc()`保证始终返回适合任何标量类型的内存（如果它成功返回内存的话）。`<cstddef>`头文件为我们提供了一个名为`std::max_align_t`的类型，其对齐要求至少与所有标量类型一样严格。稍后，我们将看到在编写自定义内存分配器时，这种类型是有用的。因此，即使我们只请求自由存储器上的`char`内存，它也将适合于`std::max_align_t`。

以下代码显示，从`new`返回的内存对于`std::max_align_t`和任何标量类型都是正确对齐的：

```cpp
auto* p = new char{}; 
auto max_alignment = alignof(std::max_align_t);
assert(is_aligned(p, max_alignment)); // True 
```

让我们使用`new`连续两次分配`char`：

```cpp
auto* p1 = new char{'a'};
auto* p2 = new char{'b'}; 
```

然后，内存可能看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_07.png)

图 7.7：分配两个单独的 char 后的内存布局

`p1`和`p2`之间的空间取决于`std::max_align_t`的对齐要求。在我的系统上，它是`16`字节，因此每个`char`实例之间有 15 个字节，即使`char`的对齐只有 1。

在使用`alignas`指定符声明变量时，可以指定比默认对齐更严格的自定义对齐要求。假设我们的缓存行大小为 64 字节，并且出于某种原因，我们希望确保两个变量位于不同的缓存行上。我们可以这样做：

```cpp
alignas(64) int x{};
alignas(64) int y{};
// x and y will be placed on different cache lines 
```

在定义类型时，也可以指定自定义对齐。以下是一个在使用时将占用一整个缓存行的结构体：

```cpp
struct alignas(64) CacheLine {
    std::byte data[64];
}; 
```

现在，如果我们创建一个类型为`CacheLine`的栈变量，它将根据 64 字节的自定义对齐进行对齐：

```cpp
int main() {
  auto x = CacheLine{};
  auto y = CacheLine{};
  assert(is_aligned(&x, 64));
  assert(is_aligned(&y, 64));
  // ...
} 
```

在堆上分配对象时，也满足了更严格的对齐要求。为了支持具有非默认对齐要求的类型的动态分配，C++17 引入了`operator new()`和`operator delete()`的新重载，它们接受`std::align_val_t`类型的对齐参数。在`<cstdlib>`中还定义了一个`aligned_alloc()`函数，可以用于手动分配对齐的堆内存。

以下是一个示例，我们在其中分配一个应该占用一个内存页面的堆内存块。在这种情况下，使用`new`和`delete`时将调用对齐感知版本的`operator new()`和`operator delete()`：

```cpp
constexpr auto ps = std::size_t{4096};      // Page size
struct alignas(ps) Page {
    std::byte data_[ps];
};
auto* page = new Page{};                    // Memory page
assert(is_aligned(page, ps));               // True
// Use page ...
delete page; 
```

内存页面不是 C++抽象机器的一部分，因此没有可移植的方法来以编程方式获取当前运行系统的页面大小。但是，您可以在 Unix 系统上使用`boost::mapped_region::get_page_size()`或特定于平台的系统调用，如`getpagesize()`。

要注意的最后一个警告是，支持的对齐集由您使用的标准库的实现定义，而不是 C++标准。

## 填充

编译器有时需要为我们定义的用户定义类型添加额外的字节，**填充**。当我们在类或结构中定义数据成员时，编译器被迫按照我们定义它们的顺序放置成员。

然而，编译器还必须确保类内的数据成员具有正确的对齐方式；因此，如果需要，它需要在数据成员之间添加填充。例如，假设我们有一个如下所示的类：

```cpp
class Document { 
  bool is_cached_{}; 
  double rank_{}; 
  int id_{}; 
};
std::cout << sizeof(Document) << '\n'; // Possible output is 24 
```

可能输出为 24 的原因是，编译器在`bool`和`int`之后插入填充，以满足各个数据成员和整个类的对齐要求。编译器将`Document`类转换为类似于这样的形式：

```cpp
class Document {
  bool is_cached_{};
  std::byte padding1[7]; // Invisible padding inserted by compiler
  double rank_{};
  int id_{};
  std::byte padding2[4]; // Invisible padding inserted by compiler
}; 
```

`bool`和`double`之间的第一个填充为 7 字节，因为`double`类型的`rank_`数据成员具有 8 字节的对齐。在`int`之后添加的第二个填充为 4 字节。这是为了满足`Document`类本身的对齐要求。具有最大对齐要求的成员也决定了整个数据结构的对齐要求。在我们的示例中，这意味着`Document`类的总大小必须是 8 的倍数，因为它包含一个 8 字节对齐的`double`值。

我们现在意识到，我们可以重新排列`Document`类中数据成员的顺序，以最小化编译器插入的填充，方法是从具有最大对齐要求的类型开始。让我们创建`Document`类的新版本：

```cpp
// Version 2 of Document class
class Document {
  double rank_{}; // Rearranged data members
  int id_{};
  bool is_cached_{};
}; 
```

通过重新排列成员，编译器现在只需要在`is_cached_`数据成员之后填充，以调整`Document`的对齐方式。这是填充后类的样子：

```cpp
// Version 2 of Document class after padding
class Document { 
  double rank_{}; 
  int id_{}; 
  bool is_cached_{}; 
  std::byte padding[3]; // Invisible padding inserted by compiler 
}; 
```

新的`Document`类的大小现在只有 16 字节，而第一个版本为 24 字节。这里的见解应该是，对象的大小可以通过更改成员声明的顺序而改变。我们还可以通过在我们更新的`Document`版本上再次使用`sizeof`运算符来验证这一点：

```cpp
std::cout << sizeof(Document) << '\n'; // Possible output is 16 
```

以下图片显示了`Document`类版本 1 和版本 2 的内存布局：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_08.png)

图 7.8：`Document`类的两个版本的内存布局。对象的大小可以通过更改成员声明的顺序而改变。

一般规则是，将最大的数据成员放在开头，最小的成员放在末尾。这样，您可以最小化填充引起的内存开销。稍后，我们将看到，在将对象放置在我们已分配的内存区域时，我们需要考虑对齐，然后才能知道我们正在创建的对象的对齐方式。

从性能的角度来看，也可能存在一些情况，你希望将对象对齐到缓存行，以最小化对象跨越的缓存行数量。在谈论缓存友好性时，还应该提到，将频繁一起使用的多个数据成员放在一起可能是有益的。

保持数据结构紧凑对性能很重要。许多应用程序受到内存访问时间的限制。内存管理的另一个重要方面是永远不要泄漏或浪费不再需要的对象的内存。通过清晰和明确地表达资源的所有权，我们可以有效地避免各种资源泄漏。这是接下来章节的主题。

# 内存所有权

资源的所有权是编程时需要考虑的基本方面。资源的所有者负责在不再需要资源时释放资源。资源通常是一块内存，但也可能是数据库连接、文件句柄等。无论使用哪种编程语言，所有权都很重要。然而，在诸如 C 和 C++之类的语言中更为明显，因为动态内存不会默认进行垃圾回收。每当我们在 C++中分配动态内存时，都必须考虑该内存的所有权。幸运的是，语言中现在有非常好的支持，可以通过使用智能指针来表达各种所有权类型，我们将在本节后面介绍。

标准库中的智能指针帮助我们指定动态变量的所有权。其他类型的变量已经有了定义的所有权。例如，局部变量由当前作用域拥有。当作用域结束时，在作用域内创建的对象将被自动销毁：

```cpp
{
  auto user = User{};
} // user automatically destroys when it goes out of scope 
```

静态和全局变量由程序拥有，并将在程序终止时被销毁：

```cpp
static auto user = User{}; 
```

数据成员由它们所属的类的实例拥有：

```cpp
class Game {
  User user; // A Game object owns the User object
  // ...
}; 
```

只有动态变量没有默认所有者，程序员需要确保所有动态分配的变量都有一个所有者来控制变量的生命周期：

```cpp
auto* user = new User{}; // Who owns user now? 
```

在现代 C++中，我们可以在大部分代码中不显式调用`new`和`delete`，这是一件好事。手动跟踪`new`和`delete`的调用很容易成为内存泄漏、双重删除和其他令人讨厌的错误的问题。原始指针不表达任何所有权，如果我们只使用原始指针引用动态内存，所有权很难跟踪。

我建议你清晰和明确地表达所有权，但努力最小化手动内存管理。通过遵循一些相当简单的规则来处理内存的所有权，你将增加代码干净和正确的可能性，而不会泄漏资源。接下来的章节将指导你通过一些最佳实践来实现这一目的。

## 隐式处理资源

首先，使你的对象隐式处理动态内存的分配/释放：

```cpp
auto func() {
  auto v = std::vector<int>{1, 2, 3, 4, 5};
} 
```

在前面的例子中，我们同时使用了栈和动态内存，但我们不必显式调用`new`和`delete`。我们创建的`std::vector`对象是一个自动对象，将存储在栈上。由于它由作用域拥有，当函数返回时将自动销毁。`std::vector`对象本身使用动态内存来存储整数元素。当`v`超出作用域时，它的析构函数可以安全地释放动态内存。让析构函数释放动态内存的这种模式使得避免内存泄漏相当容易。

当我们谈论释放资源时，我认为提到 RAII 是有意义的。**RAII**是一个众所周知的 C++技术，缩写为**Resource Acquisition Is Initialization**，其中资源的生命周期由对象的生命周期控制。这种模式简单但对于处理资源（包括内存）非常有用。但是，假设我们需要的资源是用于发送请求的某种连接。每当我们使用连接完成后，我们（所有者）必须记得关闭它。以下是我们手动打开和关闭连接以发送请求时的示例：

```cpp
auto send_request(const std::string& request) { 
  auto connection = open_connection("http://www.example.com/"); 
  send_request(connection, request); 
  close(connection); 
} 
```

正如你所看到的，我们必须记得在使用完连接后关闭它，否则连接将保持打开（泄漏）。在这个例子中，似乎很难忘记，但一旦代码在插入适当的错误处理和多个退出路径后变得更加复杂，就很难保证连接总是关闭。RAII 通过依赖自动变量的生命周期以可预测的方式处理这个问题。我们需要的是一个对象，它的生命周期与我们从`open_connection()`调用中获得的连接相同。我们可以为此创建一个名为`RAIIConnection`的类：

```cpp
class RAIIConnection { 
public: 
  explicit RAIIConnection(const std::string& url) 
      : connection_{open_connection(url)} {} 
  ~RAIIConnection() { 
    try { 
      close(connection_);       
    } 
    catch (const std::exception&) { 
      // Handle error, but never throw from a destructor 
    } 
  }
  auto& get() { return connection_; } 

private:  
  Connection connection_; 
}; 
```

`Connection`对象现在被包装在一个控制连接（资源）生命周期的类中。现在我们可以让`RAIIConnection`来处理关闭连接，而不是手动关闭连接：

```cpp
auto send_request(const std::string& request) { 
  auto connection = RAIIConnection("http://www.example.com/"); 
  send_request(connection.get(), request); 
  // No need to close the connection, it is automatically handled 
  // by the RAIIConnection destructor 
} 
```

RAII 使我们的代码更安全。即使`send_request()`在这里抛出异常，连接对象仍然会被销毁并关闭连接。我们可以将 RAII 用于许多类型的资源，不仅仅是内存、文件句柄和连接。另一个例子是来自 C++标准库的`std::scoped_lock`。它在创建时尝试获取锁（互斥锁），然后在销毁时释放锁。您可以在*第十一章* *并发*中了解更多关于`std::scoped_lock`的信息。

现在，我们将探索更多使内存所有权在 C++中变得明确的方法。

## 容器

您可以使用标准容器来处理对象的集合。您使用的容器将拥有存储在其中的对象所需的动态内存。这是一种在代码中最小化手动`new`和`delete`表达式的非常有效的方法。

还可以使用`std::optional`来处理可能存在或可能不存在的对象的生命周期。`std::optional`可以被视为一个最大大小为 1 的容器。

我们不会在这里再讨论容器，因为它们已经在*第四章* *数据结构*中涵盖过了。

## 智能指针

标准库中的智能指针包装了一个原始指针，并明确了对象的所有权。当正确使用时，没有疑问谁负责删除动态对象。三种智能指针类型是：`std::unique_ptr`、`std::shared_ptr`和`std::weak_ptr`。正如它们的名称所暗示的那样，它们代表对象的三种所有权类型：

+   独占所有权表示我，只有我，拥有这个对象。当我使用完它后，我会删除它。

+   共享所有权表示我和其他人共同拥有对象。当没有人再需要这个对象时，它将被删除。

+   弱所有权表示如果对象存在，我会使用它，但不会仅仅为了我而保持它的生存。

我们将分别在以下各节中处理这些类型。

### 独占指针

最安全和最不复杂的所有权是独占所有权，当考虑智能指针时，应该首先想到的是独占所有权。独占指针表示独占所有权；也就是说，一个资源只被一个实体拥有。独占所有权可以转移给其他人，但不能被复制，因为那样会破坏其独特性。以下是如何使用`std::unique_ptr`：

```cpp
auto owner = std::make_unique<User>("John");
auto new_owner = std::move(owner); // Transfer ownership 
```

独占指针也非常高效，因为与普通原始指针相比，它们几乎没有性能开销。轻微的开销是由于`std::unique_ptr`具有非平凡的析构函数，这意味着（与原始指针不同）在传递给函数时无法将其传递到 CPU 寄存器中。这使它们比原始指针慢。

### 共享指针

共享所有权意味着一个对象可以有多个所有者。当最后一个所有者不存在时，对象将被删除。这是一种非常有用的指针类型，但也比独占指针更复杂。

`std::shared_ptr`对象使用引用计数来跟踪对象的所有者数量。当计数器达到 0 时，对象将被删除。计数器需要存储在某个地方，因此与独占指针相比，它确实具有一些内存开销。此外，`std::shared_ptr`在内部是线程安全的，因此需要原子方式更新计数器以防止竞争条件。

创建由共享指针拥有的对象的推荐方式是使用`std::make_shared<T>()`。这既更安全（从异常安全性的角度来看），也比手动使用`new`创建对象，然后将其传递给`std::shared_ptr`构造函数更有效。通过再次重载`operator new()`和`operator delete()`来跟踪分配，我们可以进行实验，找出为什么使用`std::make_shared<T>()`更有效：

```cpp
auto operator new(size_t size) -> void* { 
  void* p = std::malloc(size); 
  std::cout << "allocated " << size << " byte(s)" << '\n'; 
  return p; 
} 
auto operator delete(void* p) noexcept -> void { 
  std::cout << "deleted memory\n"; 
  return std::free(p); 
} 
```

现在，让我们首先尝试推荐的方式，使用`std::make_shared()`：

```cpp
int main() { 
  auto i = std::make_shared<double>(42.0); 
  return 0; 
} 
```

运行程序时的输出如下：

```cpp
allocated 32 bytes 
deleted memory 
```

现在，让我们通过使用`new`显式分配`int`值，然后将其传递给`std::shared_ptr`构造函数：

```cpp
int main() { 
  auto i = std::shared_ptr<double>{new double{42.0}}; 
  return 0; 
} 
```

程序将生成以下输出：

```cpp
allocated 4 bytes 
allocated 32 bytes 
deleted memory 
deleted memory 
```

我们可以得出结论，第二个版本需要两次分配，一次是为`double`，一次是为`std::shared_ptr`，而第一个版本只需要一次分配。这也意味着，通过使用`std::make_shared()`，我们的代码将更加友好地利用缓存，因为具有空间局部性。

### 弱指针

弱所有权不会保持任何对象存活；它只允许我们在其他人拥有对象时使用对象。为什么要使用这种模糊的弱所有权？使用弱指针的一个常见原因是打破引用循环。引用循环发生在两个或多个对象使用共享指针相互引用时。即使所有外部`std::shared_ptr`构造函数都消失了，对象仍然通过相互引用而保持存活。

为什么不只使用原始指针？弱指针难道不就是原始指针已经是的东西吗？一点也不是。弱指针是安全的，因为除非对象实际存在，否则我们无法引用该对象，而悬空的原始指针并非如此。一个例子将澄清这一点：

```cpp
auto i = std::make_shared<int>(10); 
auto weak_i = std::weak_ptr<int>{i};

// Maybe i.reset() happens here so that the int is deleted... 
if (auto shared_i = weak_i.lock()) { 
  // We managed to convert our weak pointer to a shared pointer 
  std::cout << *shared_i << '\n'; 
} 
else { 
  std::cout << "weak_i has expired, shared_ptr was nullptr\n"; 
} 
```

每当我们尝试使用弱指针时，我们需要首先使用成员函数`lock()`将其转换为共享指针。如果对象尚未过期，共享指针将是指向该对象的有效指针；否则，我们将得到一个空的`std::shared_ptr`。这样，我们可以避免在使用`std::weak_ptr`时出现悬空指针，而不是使用原始指针。

这将结束我们关于内存中对象的部分。C++在处理内存方面提供了出色的支持，无论是关于低级概念，如对齐和填充，还是高级概念，如对象所有权。

对所有权、RAII 和引用计数有着清晰的理解在使用 C++时非常重要。对于新手来说，如果之前没有接触过这些概念，可能需要一些时间才能完全掌握。与此同时，这些概念并不是 C++独有的。在大多数语言中，它们更加普遍，但在其他一些语言中，它们甚至更加突出（Rust 就是后者的一个例子）。因此，一旦掌握，它将提高您在其他语言中的编程技能。思考对象所有权将对您编写的程序的设计和架构产生积极影响。

现在，我们将继续介绍一种优化技术，它将减少动态内存分配的使用，并在可能的情况下使用堆栈。

# 小对象优化

像`std::vector`这样的容器的一个很大的优点是，它们在需要时会自动分配动态内存。然而，有时为只包含少量小元素的容器对象使用动态内存会影响性能。将元素保留在容器本身，并且只使用堆栈内存，而不是在堆上分配小的内存区域，会更有效率。大多数现代的`std::string`实现都会利用这样一个事实：在正常程序中，很多字符串都很短，而且短字符串在不使用堆内存的情况下更有效率。

一种选择是在字符串类本身中保留一个小的单独缓冲区，当字符串的内容很短时可以使用。即使短缓冲区没有被使用，这也会增加字符串类的大小。

因此，一个更节省内存的解决方案是使用一个联合，当字符串处于短模式时可以容纳一个短缓冲区，否则，它将容纳它需要处理动态分配缓冲区的数据成员。用于优化处理小数据的容器的技术通常被称为字符串的小字符串优化，或者其他类型的小对象优化和小缓冲区优化。我们对我们喜欢的事物有很多名称。

一个简短的代码示例将演示在我的 64 位系统上，来自 LLVM 的 libc++中的`std::string`的行为：

```cpp
auto allocated = size_t{0}; 
// Overload operator new and delete to track allocations 
void* operator new(size_t size) {  
  void* p = std::malloc(size); 
  allocated += size; 
  return p; 
} 

void operator delete(void* p) noexcept { 
  return std::free(p); 
} 

int main() { 
  allocated = 0; 
  auto s = std::string{""}; // Elaborate with different string sizes 

  std::cout << "stack space = " << sizeof(s) 
    << ", heap space = " << allocated 
    << ", capacity = " << s.capacity() << '\n'; 
} 
```

代码首先通过重载全局的`operator new`和`operator delete`来跟踪动态内存分配。现在我们可以开始测试不同大小的字符串`s`，看看`std::string`的行为。在我的系统上以发布模式构建和运行前面的示例时，它生成了以下输出：

```cpp
stack space = 24, heap space = 0, capacity = 22 
```

这个输出告诉我们，`std::string`在堆栈上占用 24 个字节，并且在不使用任何堆内存的情况下，它的容量为 22 个字符。让我们通过用一个包含 22 个字符的字符串来验证这一点：

```cpp
auto s = std::string{"1234567890123456789012"}; 
```

程序仍然产生相同的输出，并验证没有分配动态内存。但是当我们增加字符串以容纳 23 个字符时会发生什么呢？

```cpp
auto s = std::string{"12345678901234567890123"}; 
```

现在运行程序会产生以下输出：

```cpp
stack space = 24, heap space = 32, capacity = 31 
```

`std::string`类现在被强制使用堆来存储字符串。它分配了 32 个字节，并报告容量为 31。这是因为 libc++总是在内部存储一个以空字符结尾的字符串，因此需要在末尾额外的一个字节来存储空字符。令人惊讶的是，字符串类可以只占用 24 个字节，并且可以容纳长度为 22 个字符的字符串而不分配任何内存。它是如何做到的呢？如前所述，通常通过使用具有两种不同布局的联合来节省内存：一种用于短模式，一种用于长模式。在真正的 libc++实现中有很多巧妙之处，以充分利用可用的 24 个字节。这里的代码是为了演示这个概念而简化的。长模式的布局如下：

```cpp
struct Long { 
  size_t capacity_{}; 
  size_t size_{}; 
  char* data_{}; 
}; 
```

长布局中的每个成员占用 8 个字节，因此总大小为 24 个字节。`data_`指针是指向将容纳长字符串的动态分配内存的指针。短模式的布局看起来像这样：

```cpp
struct Short { 
  unsigned char size_{};
  char data_[23]{}; 
}; 
```

在短模式下，不需要使用一个变量来存储容量，因为它是一个编译时常量。在这种布局中，`size_`数据成员也可以使用更小的类型，因为我们知道如果是短字符串，字符串的长度只能在 0 到 22 之间。

这两种布局使用一个联合结合起来：

```cpp
union u_ { 
  Short short_layout_; 
  Long long_layout_; 
}; 
```

然而，还有一个缺失的部分：字符串类如何知道它当前是存储短字符串还是长字符串？需要一个标志来指示这一点，但它存储在哪里？事实证明，libc++在长模式下使用`capacity_`数据成员的最低有效位，而在短模式下使用`size_`数据成员的最低有效位。对于长模式，这个位是多余的，因为字符串总是分配 2 的倍数的内存大小。在短模式下，可以只使用 7 位来存储大小，以便一个位可以用于标志。当编写此代码以处理大端字节顺序时，情况变得更加复杂，因为无论我们使用联合的短结构还是长结构，位都需要放置在内存的相同位置。您可以在[`github.com/llvm/llvm-project/tree/master/libcxx`](https://github.com/llvm/llvm-project/tree/master/libcxx)上查看 libc++实现的详细信息。

*图 7.9*总结了我们简化的（但仍然相当复杂）内存布局，该布局由高效实现小字符串优化的联合使用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_09.png)

图 7.9：用于处理短字符串和长字符串的两种不同布局的并集

像这样的巧妙技巧是您应该在尝试自己编写之前，努力使用标准库提供的高效且经过充分测试的类的原因。然而，了解这些优化以及它们的工作原理是重要且有用的，即使您永远不需要自己编写一个。

# 自定义内存管理

在本章中，我们已经走了很长的路。我们已经介绍了虚拟内存、堆栈和堆、`new`和`delete`表达式、内存所有权以及对齐和填充的基础知识。但在结束本章之前，我们将展示如何在 C++中自定义内存管理。我们将看到，在编写自定义内存分配器时，本章前面介绍的部分将会派上用场。

但首先，什么是自定义内存管理器，为什么我们需要它？

使用`new`或`malloc()`来分配内存时，我们使用 C++中的内置内存管理系统。大多数`operator new`的实现都使用`malloc()`，这是一个通用的内存分配器。设计和构建通用内存管理器是一项复杂的任务，已经有许多人花了很多时间研究这个主题。然而，有几个原因可能会导致您想要编写自定义内存管理器。以下是一些例子：

+   **调试和诊断**：在本章中，我们已经几次通过重载`operator new`和`operator delete`来打印一些调试信息。

+   **沙盒**：自定义内存管理器可以为不允许分配不受限制内存的代码提供一个沙盒。沙盒还可以跟踪内存分配，并在沙盒代码执行完毕时释放内存。

+   **性能**：如果我们需要动态内存并且无法避免分配，可能需要编写一个针对特定需求性能更好的自定义内存管理器。稍后，我们将介绍一些情况，我们可以利用它们来超越`malloc()`。

尽管如此，许多有经验的 C++程序员从未遇到过实际需要定制系统提供的标准内存管理器的问题。这表明了通用内存管理器实际上有多么好，尽管它们必须在不了解我们的具体用例的情况下满足所有要求。我们对应用程序中的内存使用模式了解得越多，我们就越有可能编写比`malloc()`更有效的东西。例如，记得堆栈吗？与堆相比，从堆栈分配和释放内存非常快，这要归功于它不需要处理多个线程，而且释放总是保证以相反的顺序发生。

构建自定义内存管理器通常始于分析确切的内存使用模式，然后实现一个竞技场。

## 建立一个竞技场

在使用内存分配器时经常使用的两个术语是**竞技场**和**内存池**。在本书中，我们不会区分这些术语。我所说的竞技场是指一块连续的内存，包括分配和稍后回收该内存的策略。

竞技场在技术上也可以被称为*内存资源*或*分配器*，但这些术语将用于指代标准库中的抽象。我们稍后将开发的自定义分配器将使用我们在这里创建的竞技场。

在设计一个竞技场时，有一些通用策略可以使分配和释放内存的性能优于`malloc()`和`free()`：

+   单线程：如果我们知道一个竞技场只会从一个线程使用，就不需要用同步原语（如锁或原子操作）保护数据。客户端使用竞技场不会被其他线程阻塞的风险，这在实时环境中很重要。

+   固定大小的分配：如果竞技场只分配固定大小的内存块，那么使用自由列表可以相对容易地高效地回收内存，避免内存碎片化。

+   有限的生命周期：如果你知道从竞技场分配的对象只需要在有限且明确定义的生命周期内存在，竞技场可以推迟回收并一次性释放所有内存。一个例子可能是在服务器应用程序中处理请求时创建的对象。当请求完成时，可以一次性回收在请求期间分配的所有内存。当然，竞技场需要足够大，以便在不断回收内存的情况下处理请求期间的所有分配；否则，这种策略将不起作用。

我不会详细介绍这些策略，但在寻找改进程序中的内存管理方法时，了解可能性是很好的。与优化软件一样，关键是了解程序运行的环境，并分析特定的内存使用模式。我们这样做是为了找到比通用内存管理器更有效的自定义内存管理器的方法。

接下来，我们将看一个简单的竞技场类模板，它可以用于需要动态存储期的小型或少量对象，但它通常需要的内存量很小，可以放在堆栈上。这段代码基于 Howard Hinnant 的`short_alloc`，发布在[`howardhinnant.github.io/stack_alloc.html`](https://howardhinnant.github.io/stack_alloc.html)。如果你想深入了解自定义内存管理，这是一个很好的起点。我认为这是一个很好的示例，因为它可以处理需要正确对齐的多种大小的对象。

但是，请记住，这只是一个简化版本，用于演示概念，而不是为您提供生产就绪的代码：

```cpp
template <size_t N> 
class Arena { 
  static constexpr size_t alignment = alignof(std::max_align_t); 
public: 
  Arena() noexcept : ptr_(buffer_) {} 
  Arena(const Arena&) = delete; 
  Arena& operator=(const Arena&) = delete; 

  auto reset() noexcept { ptr_ = buffer_; } 
  static constexpr auto size() noexcept { return N; } 
  auto used() const noexcept {
    return static_cast<size_t>(ptr_ - buffer_); 
  } 
  auto allocate(size_t n) -> std::byte*; 
  auto deallocate(std::byte* p, size_t n) noexcept -> void; 

private: 
  static auto align_up(size_t n) noexcept -> size_t { 
    return (n + (alignment-1)) & ~(alignment-1); 
  } 
  auto pointer_in_buffer(const std::byte* p) const noexcept -> bool {
    return std::uintptr_t(p) >= std::uintptr_t(buffer_) &&
           std::uintptr_t(p) < std::uintptr_t(buffer_) + N;
  } 
  alignas(alignment) std::byte buffer_[N]; 
  std::byte* ptr_{}; 
}; 
```

区域包含一个`std::byte`缓冲区，其大小在编译时确定。这使得可以在堆栈上或作为具有静态或线程局部存储期的变量创建区域对象。对于除`char`之外的类型，对齐可能在堆栈上分配；因此，除非我们对数组应用`alignas`说明符，否则不能保证它对齐。如果你不习惯位操作，辅助函数`align_up()`可能看起来很复杂。然而，它基本上只是将其舍入到我们使用的对齐要求。这个版本分配的内存将与使用`malloc()`时一样，适用于任何类型。如果我们使用区域来处理具有较小对齐要求的小类型，这会有点浪费，但我们在这里忽略这一点。

在回收内存时，我们需要知道被要求回收的指针是否实际属于我们的区域。`pointer_in_buffer()`函数通过比较指针地址与区域的地址范围来检查这一点。顺便说一句，对不相交对象的原始指针进行关系比较是未定义行为；这可能被优化编译器使用，并导致意想不到的效果。为了避免这种情况，我们在比较地址之前将指针转换为`std::uintptr_t`。如果你对此背后的细节感兴趣，你可以在 Raymond Chen 的文章*如何检查指针是否在内存范围内*中找到详细的解释，链接为[`devblogs.microsoft.com/oldnewthing/20170927-00/?p=97095`](https://devblogs.microsoft.com/oldnewthing/20170927-00/?p=97095)。

接下来，我们需要实现分配和释放：

```cpp
template<size_t N> 
auto Arena<N>::allocate(size_t n) -> std::byte* { 
  const auto aligned_n = align_up(n); 
  const auto available_bytes =  
    static_cast<decltype(aligned_n)>(buffer_ + N - ptr_); 
  if (available_bytes >= aligned_n) { 
    auto* r = ptr_; 
    ptr_ += aligned_n; 
    return r; 
  } 
  return static_cast<std::byte*>(::operator new(n)); 
} 
```

`allocate()`函数返回一个指向指定大小`n`的正确对齐内存的指针。如果缓冲区中没有足够的空间来满足请求的大小，它将退而使用`operator new`。

以下的`deallocate()`函数首先检查要释放内存的指针是否来自缓冲区，或者是使用`operator new`分配的。如果不是来自缓冲区，我们就简单地使用`operator delete`删除它。否则，我们检查要释放的内存是否是我们从缓冲区分配的最后一块内存，然后通过移动当前的`ptr_`来回收它，就像栈一样。我们简单地忽略其他尝试回收内存的情况：

```cpp
template<size_t N> 
auto Arena<N>::deallocate(std::byte* p, size_t n) noexcept -> void { 
  if (pointer_in_buffer(p)) { 
    n = align_up(n); 
    if (p + n == ptr_) { 
      ptr_ = p; 
    } 
  } 
  else { 
    ::operator delete(p);
  }
} 
```

就是这样；我们的区域现在可以使用了。让我们在分配`User`对象时使用它：

```cpp
auto user_arena = Arena<1024>{}; 

class User { 
public: 
  auto operator new(size_t size) -> void* { 
    return user_arena.allocate(size); 
  } 
  auto operator delete(void* p) -> void { 
    user_arena.deallocate(static_cast<std::byte*>(p), sizeof(User)); 
  } 
  auto operator new[](size_t size) -> void* { 
    return user_arena.allocate(size); 
  } 
  auto operator delete[](void* p, size_t size) -> void { 
    user_arena.deallocate(static_cast<std::byte*>(p), size); 
  } 
private:
  int id_{};
}; 

int main() { 
  // No dynamic memory is allocated when we create the users 
  auto user1 = new User{}; 
  delete user1; 

  auto users = new User[10]; 
  delete [] users; 

  auto user2 = std::make_unique<User>(); 
  return 0; 
} 
```

在这个例子中创建的`User`对象都将驻留在`user_area`对象的缓冲区中。也就是说，当我们在这里调用`new`或`make_unique()`时，不会分配动态内存。但是在 C++中有其他创建`User`对象的方式，这个例子没有展示。我们将在下一节中介绍它们。

## 自定义内存分配器

当尝试使用特定类型的自定义内存管理器时，效果很好！但是有一个问题。事实证明，类特定的`operator new`并没有在我们可能期望的所有场合被调用。考虑以下代码：

```cpp
auto user = std::make_shared<User>(); 
```

当我们想要有一个包含 10 个用户的`std::vector`时会发生什么？

```cpp
auto users = std::vector<User>{};
users.reserve(10); 
```

在这两种情况下都没有使用我们的自定义内存管理器。为什么？从共享指针开始，我们必须回到之前的例子，我们在那里看到`std::make_shared()`实际上为引用计数数据和应该指向的对象分配内存。`std::make_shared()`无法使用诸如`new User()`这样的表达式来创建用户对象和只进行一次分配的计数器。相反，它分配内存并使用就地 new 构造用户对象。

`std::vector`对象也是类似的。当我们调用`reserve()`时，默认情况下它不会在数组中构造 10 个对象。这将需要所有类都有默认构造函数才能与向量一起使用。相反，它分配内存，可以用于添加 10 个用户对象时使用。再次，放置 new 是使这成为可能的工具。

幸运的是，我们可以为`std::vector`和`std::shared_ptr`提供自定义内存分配器，以便它们使用我们的自定义内存管理器。标准库中的其他容器也是如此。如果我们不提供自定义分配器，容器将使用默认的`std::allocator<T>`类。因此，为了使用我们的内存池，我们需要编写一个可以被容器使用的分配器。

自定义分配器在 C++社区中长期以来一直是一个备受争议的话题。许多自定义容器已经被实现，用于控制内存的管理，而不是使用具有自定义分配器的标准容器，这可能是有充分理由的。

然而，在 C++11 中，编写自定义分配器的支持和要求得到了改进，现在要好得多。在这里，我们将只关注 C++11 及以后的分配器。

C++11 中的最小分配器现在看起来是这样的：

```cpp
template<typename T> 
struct Alloc {  
  using value_type = T; 
  Alloc(); 
  template<typename U> Alloc(const Alloc<U>&); 
  T* allocate(size_t n); 
  auto deallocate(T*, size_t) const noexcept -> void; 
}; 
template<typename T> 
auto operator==(const Alloc<T>&, const Alloc<T>&) -> bool;   
template<typename T> 
auto operator!=(const Alloc<T>&, const Alloc<T>&) -> bool; 
```

由于 C++11 的改进，现在代码量确实不那么多了。使用分配器的容器实际上使用了`std::allocator_traits`，它提供了合理的默认值，如果分配器省略了它们。我建议您查看`std::allocator_traits`，看看可以配置哪些特性以及默认值是什么。

通过使用`malloc()`和`free()`，我们可以相当容易地实现一个最小的自定义分配器。在这里，我们将展示老式而著名的`Mallocator`，首次由 Stephan T. Lavavej 在博客文章中发布，以演示如何使用`malloc()`和`free()`编写一个最小的自定义分配器。自那时以来，它已经更新为 C++11，使其更加精简。它是这样的：

```cpp
template <class T>  
struct Mallocator { 

  using value_type = T; 
  Mallocator() = default;

  template <class U>  
  Mallocator(const Mallocator<U>&) noexcept {} 

  template <class U>  
  auto operator==(const Mallocator<U>&) const noexcept {  
    return true;  
  } 

  template <class U>  
  auto operator!=(const Mallocator<U>&) const noexcept {  
    return false;  
  } 

  auto allocate(size_t n) const -> T* { 
    if (n == 0) {  
      return nullptr;  
    } 
    if (n > std::numeric_limits<size_t>::max() / sizeof(T)) { 
      throw std::bad_array_new_length{}; 
    } 
    void* const pv = malloc(n * sizeof(T)); 
    if (pv == nullptr) {  
      throw std::bad_alloc{};  
    } 
    return static_cast<T*>(pv); 
  } 
  auto deallocate(T* p, size_t) const noexcept -> void { 
    free(p); 
  } 
}; 
```

`Mallocator`是一个**无状态的分配器**，这意味着分配器实例本身没有任何可变状态；相反，它使用全局函数进行分配和释放，即`malloc()`和`free()`。无状态的分配器应该始终与相同类型的分配器相等。这表明使用`Mallocator`分配的内存也应该使用`Mallocator`释放，而不管`Mallocator`实例如何。无状态的分配器是最简单的分配器，但也是有限的，因为它依赖于全局状态。

为了将我们的内存池作为一个栈分配的对象使用，我们将需要一个**有状态的分配器**，它可以引用内存池实例。在这里，我们实现的内存池类真正开始变得有意义。比如，假设我们想在一个函数中使用标准容器进行一些处理。我们知道，大多数情况下，我们处理的数据量非常小，可以放在栈上。但一旦我们使用标准库中的容器，它们将从堆中分配内存，这在这种情况下会影响我们的性能。

使用栈来管理数据并避免不必要的堆分配的替代方案是什么？一个替代方案是构建一个自定义容器，它使用了我们为`std::string`所研究的小对象优化的变体。

也可以使用 Boost 中的容器，比如`boost::container::small_vector`，它基于 LLVM 的小向量。如果您还没有使用过，我们建议您查看：[`www.boost.org/doc/libs/1_74_0/doc/html/container/non_standard_containers.html`](http://www.boost.org/doc/libs/1_74_0/doc/html/container/non_standard_containers.html)。

然而，另一种选择是使用自定义分配器，我们将在下面探讨。由于我们已经准备好了一个竞技场模板类，我们可以简单地在堆栈上创建一个竞技场实例，并让自定义分配器使用它进行分配。然后我们需要实现一个有状态的分配器，它可以持有对堆栈分配的竞技场对象的引用。

再次强调，我们将实现的这个自定义分配器是 Howard Hinnant 的`short_alloc`的简化版本：

```cpp
template <class T, size_t N> 
struct ShortAlloc { 

  using value_type = T; 
  using arena_type = Arena<N>; 

  ShortAlloc(const ShortAlloc&) = default; 
  ShortAlloc& operator=(const ShortAlloc&) = default; 

  ShortAlloc(arena_type& arena) noexcept : arena_{&arena} { }

  template <class U>
  ShortAlloc(const ShortAlloc<U, N>& other) noexcept
      : arena_{other.arena_} {}

  template <class U> struct rebind {
    using other = ShortAlloc<U, N>;
  };
  auto allocate(size_t n) -> T* {
    return reinterpret_cast<T*>(arena_->allocate(n*sizeof(T)));
  }
  auto deallocate(T* p, size_t n) noexcept -> void {
    arena_->deallocate(reinterpret_cast<std::byte*>(p), n*sizeof(T));
  }
  template <class U, size_t M>
  auto operator==(const ShortAlloc<U, M>& other) const noexcept {
    return N == M && arena_ == other.arena_;
  }
  template <class U, size_t M>
  auto operator!=(const ShortAlloc<U, M>& other) const noexcept {
    return !(*this == other);
  }
  template <class U, size_t M> friend struct ShortAlloc;
private:
  arena_type* arena_;
}; 
```

分配器持有对竞技场的引用。这是分配器唯一的状态。函数`allocate()`和`deallocate()`只是将它们的请求转发到竞技场。比较运算符确保`ShortAlloc`类型的两个实例使用相同的竞技场。

现在，我们实现的分配器和竞技场可以与标准容器一起使用，以避免动态内存分配。当我们使用小数据时，我们可以使用堆栈处理所有分配。让我们看一个使用`std::set`的例子：

```cpp
int main() { 

  using SmallSet =  
    std::set<int, std::less<int>, ShortAlloc<int, 512>>; 

  auto stack_arena = SmallSet::allocator_type::arena_type{}; 
  auto unique_numbers = SmallSet{stack_arena}; 

  // Read numbers from stdin 
  auto n = int{}; 
  while (std::cin >> n)
    unique_numbers.insert(n); 

  // Print unique numbers  
  for (const auto& number : unique_numbers)
    std::cout << number << '\n'; 
} 
```

该程序从标准输入读取整数，直到达到文件结尾（在类 Unix 系统上为 Ctrl + D，在 Windows 上为 Ctrl + Z）。然后按升序打印唯一的数字。根据从`stdin`读取的数字数量，程序将使用堆栈内存或动态内存，使用我们的`ShortAlloc`分配器。

## 使用多态内存分配器

如果您已经阅读了本章，现在您知道如何实现一个自定义分配器，可以与包括标准库在内的任意容器一起使用。假设我们想要在我们的代码库中使用我们的新分配器来处理`std::vector<int>`类型的缓冲区的一些代码，就像这样：

```cpp
void process(std::vector<int>& buffer) {
  // ...
}
auto some_func() {
  auto vec = std::vector<int>(64);
  process(vec); 
  // ...
} 
```

我们迫不及待地想尝试一下我们的新分配器，它正在利用堆栈内存，并尝试像这样注入它：

```cpp
using MyAlloc = ShortAlloc<int, 512>;  // Our custom allocator
auto some_func() {
  auto arena = MyAlloc::arena_type();
  auto vec = std::vector<int, MyAlloc>(64, arena);
  process(vec);
  // ...
} 
```

在编译时，我们痛苦地意识到`process()`是一个期望`std::vector<int>`的函数，而我们的`vec`变量现在是另一种类型。GCC 给了我们以下错误：

```cpp
error: invalid initialization of reference of type 'const std::vector<int>&' from expression of type 'std::vector<int, ShortAlloc<int, 512> > 
```

类型不匹配的原因是我们想要使用的自定义分配器`MyAlloc`作为模板参数传递给`std::vector`，因此成为我们实例化的类型的一部分。因此，`std::vector<int>`和`std::vector<int, MyAlloc>`不能互换。

这可能对您正在处理的用例有影响，您可以通过使`process()`函数接受`std::span`或使其成为使用范围而不是要求`std::vector`的通用函数来解决这个问题。无论如何，重要的是要意识到，当使用标准库中的支持分配器的模板类时，分配器实际上成为类型的一部分。

`std::vector<int>`使用的是什么分配器？答案是`std::vector<int>`使用默认模板参数`std::allocator`。因此，编写`std::vector<int>`等同于`std::vector<int, std::allocator<int>>`。模板类`std::allocator`是一个空类，当它满足容器的分配和释放请求时，它使用全局`new`和全局`delete`。这也意味着使用空分配器的容器的大小比使用自定义分配器的容器要小：

```cpp
std::cout << sizeof(std::vector<int>) << '\n';
// Possible output: 24
std::cout << sizeof(std::vector<int, MyAlloc>) << '\n';
// Possible output: 32 
```

检查来自 libc++的`std::vector`的实现，我们可以看到它使用了一个称为**compressed pair**的巧妙类型，这又基于*空基类优化*来摆脱通常由空类成员占用的不必要存储空间。我们不会在这里详细介绍，但如果您感兴趣，可以查看`compressed_pair`的 boost 版本，该版本在[`www.boost.org/doc/libs/1_74_0/libs/utility/doc/html/compressed_pair.html`](https://www.boost.org/doc/libs/1_74_0/libs/utility/doc/html/compressed_pair.html)中有文档。

在 C++17 中，使用不同的分配器时出现了不同类型的问题，通过引入额外的间接层来解决；在`std::pmr`命名空间下的所有标准容器都使用相同的分配器，即`std::pmr::polymorphic_allocator`，它将所有分配/释放请求分派给一个**内存资源**类。因此，我们可以使用通用的多态内存分配器`std::pmr::polymorphic_allocator`，而不是编写新的自定义内存分配器，并在构造过程中使用新的自定义内存资源。内存资源类似于我们的`Arena`类，而`polymorphic_allocator`是额外的间接层，其中包含指向资源的指针。

以下图表显示了向量委托给其分配器实例，然后分配器再委托给其指向的内存资源的控制流程。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_07_10.png)

图 7.10：使用多态分配器分配内存

要开始使用多态分配器，我们需要将命名空间从`std`更改为`std::pmr`：

```cpp
auto v1 = std::vector<int>{};             // Uses std::allocator
auto v2 = std::pmr::vector<int>{/*...*/}; // Uses polymorphic_allocator 
```

编写自定义内存资源相对比较简单，特别是对于了解内存分配器和区域的知识。但为了实现我们想要的功能，我们甚至可能不需要编写自定义内存资源。C++已经为我们提供了一些有用的实现，在编写自己的实现之前，我们应该考虑一下。所有内存资源都派生自基类`std::pmr::memory_resource`。以下内存资源位于`<memory_resource>`头文件中：

+   `std::pmr::monotonic_buffer_resource`: 这与我们的`Arena`类非常相似。在我们创建许多寿命短的对象时，这个类是首选。只有在`monotonic_buffer_resource`实例被销毁时，内存才会被释放，这使得分配非常快。

+   `std::pmr::unsynchronized_pool_resource`: 这使用包含固定大小内存块的内存池（也称为“slabs”），避免了每个池内的碎片。每个池为特定大小的对象分配内存。如果您正在创建多个不同大小的对象，这个类可以很有益。这个内存资源不是线程安全的，除非提供外部同步，否则不能从多个线程使用。

+   `std::pmr::synchronized_pool_resource`: 这是`unsynchronized_pool_resource`的线程安全版本。

内存资源可以被链接。在创建内存资源的实例时，我们可以为其提供一个**上游内存资源**。如果当前资源无法处理请求（类似于我们在`ShortAlloc`中使用`malloc()`一旦我们的小缓冲区已满），或者当资源本身需要分配内存时（例如当`monotonic_buffer_resource`需要分配其下一个缓冲区时），将使用此上游资源。`<memory_resource>`头文件为我们提供了一些自由函数，返回指向全局资源对象的指针，这些在指定上游资源时非常有用：

+   `std::pmr::new_delete_resource()`: 使用全局的`operator new`和`operator delete`。

+   `std::pmr::null_memory_resource()`: 一个资源，每当被要求分配内存时总是抛出`std::bad_alloc`。

+   `std::pmr::get_default_resource()`: 返回一个全局默认的内存资源，可以在运行时通过`set_default_resource()`进行设置。初始默认资源是`new_delete_resource()`。

让我们看看如何重新编写上一节中的示例，但这次使用`std::pmr::set`：

```cpp
int main() {
  auto buffer = std::array<std::byte, 512>{};
  auto resource = std::pmr::monotonic_buffer_resource{
    buffer.data(), buffer.size(), std::pmr::new_delete_resource()};
  auto unique_numbers = std::pmr::set<int>{&resource};
  auto n = int{};
  while (std::cin >> n) {
    unique_numbers.insert(n);
  }
  for (const auto& number : unique_numbers) {
    std::cout << number << '\n';
  }
} 
```

我们将一个栈分配的缓冲区传递给内存资源，然后为其提供从`new_delete_resource()`返回的对象作为上游资源，以便在缓冲区变满时使用。如果我们省略了上游资源，它将使用默认内存资源，在这种情况下，由于我们的代码不会更改默认内存资源，因此默认内存资源将是相同的。

## 实现自定义内存资源

实现自定义内存资源相当简单。我们需要公开继承自`std::pmr::memory_resource`，然后实现三个纯虚函数，这些函数将被基类（`std::pmr::memory_resource`）调用。让我们实现一个简单的内存资源，它打印分配和释放，然后将请求转发到默认内存资源：

```cpp
class PrintingResource : public std::pmr::memory_resource {
public:
  PrintingResource() : res_{std::pmr::get_default_resource()} {}
private:
  void* do_allocate(std::size_t bytes, std::size_t alignment)override {
    std::cout << "allocate: " << bytes << '\n';
    return res_->allocate(bytes, alignment);
  }
  void do_deallocate(void* p, std::size_t bytes,
                     std::size_t alignment) override {
    std::cout << "deallocate: " << bytes << '\n';
    return res_->deallocate(p, bytes, alignment);
  }
  bool do_is_equal(const std::pmr::memory_resource& other) 
    const noexcept override {
    return (this == &other);
  }
  std::pmr::memory_resource* res_;  // Default resource
}; 
```

请注意，我们在构造函数中保存了默认资源，而不是直接从`do_allocate()`和`do_deallocate()`中直接调用`get_default_resource()`。原因是在分配和释放之间的时间内，某人可能通过调用`set_default_resource()`来更改默认资源。

我们可以使用自定义内存资源来跟踪`std::pmr`容器所做的分配。以下是使用`std::pmr::vector`的示例：

```cpp
auto res = PrintingResource{};
auto vec = std::pmr::vector<int>{&res};
vec.emplace_back(1);
vec.emplace_back(2); 
```

运行程序时可能的输出是：

```cpp
allocate: 4
allocate: 8
deallocate: 4
deallocate: 8 
```

在使用多态分配器时需要非常小心的一点是，我们传递的是原始的非拥有指针到内存资源。这不是特定于多态分配器；我们在`Arena`类和`ShortAlloc`中也有同样的问题，但是在使用`std::pmr`容器时可能更容易忘记，因为这些容器使用相同的分配器类型。考虑以下示例：

```cpp
auto create_vec() -> std::pmr::vector<int> {
  auto resource = PrintingResource{};
  auto vec = std::pmr::vector<int>{&resource}; // Raw pointer
  return vec;                                  // Ops! resource
}                                              // destroyed here 
auto vec = create_vec();
vec.emplace_back(1);                           // Undefined behavior 
```

由于资源在`create_vec()`结束时超出范围而被销毁，我们新创建的`std::pmr::vector`是无用的，很可能在使用时崩溃。

这结束了我们关于自定义内存管理的部分。这是一个复杂的主题，如果您想要使用自定义内存分配器来提高性能，我鼓励您在使用和/或实现自定义分配器之前仔细测量和分析应用程序中的内存访问模式。通常，应用程序中只有一小部分类或对象真正需要使用自定义分配器进行调整。同时，在应用程序中减少动态内存分配的数量或将对象组合在一起，可以对性能产生显著影响。

# 总结

本章涵盖了很多内容，从虚拟内存的基础开始，最终实现了可以被标准库中的容器使用的自定义分配器。了解程序如何使用内存是很重要的。过度使用动态内存可能成为性能瓶颈，您可能需要优化掉它。

在开始实现自己的容器或自定义内存分配器之前，请记住，您之前可能有很多人面临过与您可能面临的非常相似的内存问题。因此，很有可能您的正确工具已经存在于某个库中。构建快速、安全和健壮的自定义内存管理器是一个挑战。

在下一章中，您将学习如何从 C++概念中受益，以及如何使用模板元编程让编译器为我们生成代码。


# 第八章：编译时编程

C++具有在编译时评估表达式的能力，这意味着值在程序执行时已经计算出来。尽管自 C++98 以来就一直可以进行元编程，但由于其复杂的基于模板的语法，最初非常复杂。随着`constexpr`、`if constexpr`的引入，以及最近的 C++ *概念*，元编程变得更类似于编写常规代码。

本章将简要介绍 C++中的编译时表达式求值以及它们如何用于优化。

我们将涵盖以下主题：

+   使用 C++模板进行元编程以及如何在 C++20 中编写缩写函数模板

+   在编译时使用类型特征检查和操作类型

+   编译器评估的常量表达式

+   C++20 概念以及如何使用它们为我们的模板参数添加约束

+   元编程的一些真实例子

我们将从介绍模板元编程开始。

# 介绍模板元编程

在编写常规 C++代码时，最终会将其转换为机器代码。另一方面，**元编程**允许我们编写能够将自身转换为常规 C++代码的代码。更一般地说，元编程是一种技术，我们编写能够转换或生成其他代码的代码。通过使用元编程，我们可以避免重复使用仅基于我们使用的数据类型略有不同的代码，或者通过预先计算在最终程序执行之前就可以知道的值来最小化运行时成本。没有什么能阻止我们使用其他语言生成 C++代码。例如，我们可以通过广泛使用预处理器宏或编写一个生成或修改 C++文件的 Python 脚本来进行元编程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_08_01.png)

图 8.1：一个元程序生成将被编译成机器代码的常规 C++代码

尽管我们可以使用任何语言来生成常规代码，但是使用 C++，我们有特权在语言本身内部使用**模板**和**常量表达式**编写元程序。C++编译器可以执行我们的元程序，并生成编译器将进一步转换为机器代码的常规 C++代码。

在 C++中直接使用模板和常量表达式进行元编程，而不是使用其他技术，有许多优势：

+   我们不必解析 C++代码（编译器会为我们做这个工作）。

+   在使用 C++模板元编程时，对分析和操作 C++类型有很好的支持。

+   元程序的代码和常规非通用代码混合在 C++源代码中。有时，这可能使人难以理解哪些部分分别在运行时和编译时执行。然而，总的来说，这是使 C++元编程有效使用的一个非常重要的方面。

在其最简单和最常见的形式中，C++中的模板元编程用于生成接受不同类型的函数、值和类。当编译器使用模板生成类或函数时，称模板被**实例化**。编译器通过**评估**常量表达式来生成常量值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_08_02.png)

图 8.2：C++中的编译时编程。将生成常规 C++代码的元程序是用 C++本身编写的。

这是一个相对简化的观点；没有什么规定 C++编译器必须以这种方式执行转换。然而，将 C++元编程视为在这两个不同阶段进行的是很有用的：

+   初始阶段，模板和常量表达式生成函数、类和常量值的常规 C++代码。这个阶段通常被称为**常量评估**。

+   第二阶段，编译器最终将常规 C++代码编译成机器代码。

在本章后面，我将把从元编程生成的 C++代码称为*常规 C++代码*。

在使用元编程时，重要的是要记住它的主要用例是制作出色的库，并因此隐藏用户代码中的复杂构造/优化。请注意，无论代码的内部多么复杂，都很重要将其隐藏在良好的接口后面，以便用户代码库易于阅读和使用。

让我们继续创建我们的第一个用于生成函数和类的模板。

## 创建模板

让我们看一个简单的`pow()`函数和一个`Rectangle`类。通过使用**类型模板参数**，`pow()`函数和`Rectangle`类可以与任何整数或浮点类型一起使用。没有模板，我们将不得不为每种基本类型创建一个单独的函数/类。

编写元编程代码可能非常复杂；使其变得更容易的一点是想象预期的常规 C++代码的意图。

下面是一个简单函数模板的示例：

```cpp
// pow_n accepts any number type 
template <typename T> 
auto pow_n(const T& v, int n) { 
  auto product = T{1}; 
  for (int i = 0; i < n; ++i) { 
    product *= v; 
  }
  return product; 
} 
```

使用此函数将生成一个返回类型取决于模板参数类型的函数：

```cpp
auto x = pow_n<float>(2.0f, 3); // x is a float 
auto y = pow_n<int>(3, 3);      // y is an int 
```

显式模板参数类型（在这种情况下为`float`和`int`）可以（最好）省略，而编译器可以自行解决这个问题。这种机制称为**模板参数推断**，因为编译器*推断*模板参数。以下示例将导致与先前显示的相同的模板实例化：

```cpp
auto x = pow_n(2.0f, 3);  // x is a float 
auto y = pow_n(3, 3);     // y is an int 
```

相应地，可以定义一个简单的类模板如下：

```cpp
// Rectangle can be of any type 
template <typename T> 
class Rectangle { 
public: 
  Rectangle(T x, T y, T w, T h) : x_{x}, y_{y}, w_{w}, h_{h} {} 
  auto area() const { return w_ * h_; } 
  auto width() const { return w_; } 
  auto height() const { return h_; } 
private:
  T x_{}, y_{}, w_{}, h_{}; 
}; 
```

当使用类模板时，我们可以明确指定模板应为其生成代码的类型，如下所示：

```cpp
auto r1 = Rectangle<float>{2.0f, 2.0f, 4.0f, 4.0f}; 
```

但也可以从**类模板参数推断**（**CTAD**）中受益，并让编译器为我们推断参数类型。以下代码将实例化一个`Rectangle<int>`：

```cpp
auto r2 = Rectangle{-2, -2, 4, 4};   // Rectangle<int> 
```

然后，函数模板可以接受一个`Rectangle`对象，其中矩形的尺寸是使用任意类型`T`定义的，如下所示：

```cpp
template <typename T> 
auto is_square(const Rectangle<T>& r) { 
  return r.width() == r.height(); 
} 
```

类型模板参数是最常见的模板参数。接下来，您将看到如何使用数值参数而不是类型参数。

## 使用整数作为模板参数

除了一般类型，模板还可以是其他类型，例如整数类型和浮点类型。在下面的示例中，我们将在模板中使用`int`，这意味着编译器将为每个唯一的整数传递的模板参数生成一个新函数：

```cpp
template <int N, typename T> 
auto const_pow_n(const T& v) { 
  auto product = T{1}; 
  for (int i = 0; i < N; ++i) { 
    product *= v; 
  }
  return product; 
} 
```

以下代码将强制编译器实例化两个不同的函数：一个平方值，一个立方值：

```cpp
auto x2 = const_pow_n<2>(4.0f);   // Square
auto x3 = const_pow_n<3>(4.0f);   // Cube 
```

请注意模板参数`N`和函数参数`v`之间的差异。对于每个`N`的值，编译器都会生成一个新函数。但是，`v`作为常规参数传递，因此不会导致生成新函数。

## 提供模板的特化

默认情况下，每当我们使用新参数的模板时，编译器将生成常规的 C++代码。但也可以为模板参数的某些值提供自定义实现。例如，假设我们希望在使用整数并且`N`的值为`2`时，提供我们的`const_pow_n()`函数的常规 C++代码。我们可以为这种情况编写一个**模板特化**，如下所示：

```cpp
template<>
auto const_pow_n<2, int>(const int& v) {
  return v * v;
} 
```

对于函数模板，当编写特化时，我们需要固定*所有*模板参数。例如，不可能只指定`N`的值，而让类型参数`T`未指定。但是，对于类模板，可以只指定模板参数的子集。这称为**部分模板特化**。编译器将首先选择最具体的模板。

我们不能对函数应用部分模板特化的原因是函数可以重载（而类不能）。如果允许混合重载和部分特化，那将很难理解。

## 编译器如何处理模板函数

当编译器处理模板函数时，它会构造一个展开了模板参数的常规函数。以下代码将使编译器生成常规函数，因为它使用了模板：

```cpp
auto a = pow_n(42, 3);          // 1\. Generate new function
auto b = pow_n(42.f, 2);        // 2\. Generate new function
auto c = pow_n(17.f, 5);        // 3.
auto d = const_pow_n<2>(42.f);  // 4\. Generate new function
auto e = const_pow_n<2>(99.f);  // 5.
auto f = const_pow_n<3>(42.f);  // 6\. Generate new function 
```

因此，当编译时，与常规函数不同，编译器将为每组唯一的*模板参数*生成新函数。这意味着它相当于手动创建了四个不同的函数，看起来像这样：

```cpp
auto pow_n__float(float v, int n) {/*...*/}   // Used by: 1
auto pow_n__int(int v, int n) {/*...*/}       // Used by: 2 and 3
auto const_pow_n__2_float (float v) {/*...*/} // Used by: 4 and 5
auto const_pow_n__3_float(float v) {/*...*/}  // Used by: 6 
```

这对于理解元编程的工作原理非常重要。模板代码生成非模板化的 C++代码，然后作为常规代码执行。如果生成的 C++代码无法编译，错误将在编译时被捕获。

## 缩写函数模板

C++20 引入了一种新的缩写语法，用于编写函数模板，采用了通用 lambda 使用的相同风格。通过使用`auto`作为函数参数类型，我们实际上创建的是一个函数模板，而不是一个常规函数。回想一下我们最初的`pow_n()`模板，它是这样声明的：

```cpp
template <typename T>
auto pow_n(const T& v, int n) { 
  // ... 
```

使用缩写的函数模板语法，我们可以使用`auto`来声明它：

```cpp
auto pow_n(const auto& v, int n) { // Declares a function template
  // ... 
```

这两个版本之间的区别在于缩写版本没有变量`v`的显式占位符。由于我们在实现中使用了占位符`T`，这段代码将不幸地无法编译：

```cpp
auto pow_n(const auto& v, int n) {
  auto product = T{1}; // Error: What is T?
  for (int i = 0; i < n; ++i) { 
    product *= v; 
  } 
  return product;
} 
```

为了解决这个问题，我们可以使用`decltype`指定符。

## 使用 decltype 接收变量的类型

`decltype`指定符用于检索变量的类型，并且在没有显式类型名称可用时使用。

有时，我们需要一个显式的类型占位符，但没有可用的，只有变量名。这在我们之前实现`pow_n()`函数时发生过，当使用缩写的函数模板语法时。

让我们通过修复`pow_n()`的实现来看一个使用`decltype`的例子：

```cpp
auto pow_n(const auto& v, int n) {
  auto product = decltype(v){1};   // Instead of T{1}
  for (int i = 0; i < n; ++i) { product *= v; } 
  return product;
} 
```

尽管这段代码编译并工作，但我们有点幸运，因为`v`的类型实际上是一个`const`引用，而不是我们想要的变量`product`的类型。我们可以通过使用从左到右的声明样式来解决这个问题。但是，试图将定义产品的行重写为看起来相同的东西会揭示一个问题：

```cpp
auto pow_n(const auto& v, int n) {
  decltype(v) product{1};
  for (int i = 0; i < n; ++i) { product *= v; } // Error!
  return product;
} 
```

现在，我们得到了一个编译错误，因为`product`是一个`const`引用，可能无法分配新值。

我们真正想要的是从变量`v`的类型中去掉`const`引用，当定义变量`product`时。我们可以使用一个方便的模板`std::remove_cvref`来实现这个目的。我们的`product`的定义将如下所示：

```cpp
typename std::remove_cvref<decltype(v)>::type product{1}; 
```

哦！在这种特殊情况下，也许最好还是坚持最初的`template <typename T>`语法。但现在，您已经学会了在编写通用 C++代码时如何使用`std::remove_cvref`和`decltype`，这是一个常见的模式。

在 C++20 之前，在通用 lambda 的主体中经常看到`decltype`。然而，现在可以通过向通用 lambda 添加显式模板参数来避免相当不方便的`decltype`：

```cpp
auto pow_n = []<class T>(const T& v, int n) { 
  auto product = T{1};
  for (int i = 0; i < n; ++i) { product *= v; }
  return product;
}; 
```

在 lambda 的定义中，我们写`<class T>`以获取一个可以在函数体内使用的参数类型的标识符。

也许需要一些时间来习惯使用`decltype`和操纵类型的工具。也许`std::remove_cvref`一开始看起来有点神秘。它是`<type_traits>`头文件中的一个模板，我们将在下一节中进一步了解它。

# 类型特征

在进行模板元编程时，您可能经常会发现自己处于需要在编译时获取有关您正在处理的类型的信息的情况。在编写常规（非泛型）C++代码时，我们使用完全了解的具体类型，但在编写模板时情况并非如此；具体类型直到编译器实例化模板时才确定。类型特征允许我们提取有关我们模板处理的类型的信息，以生成高效和正确的 C++代码。

为了提取有关模板类型的信息，标准库提供了一个类型特征库，该库在`<type_traits>`头文件中可用。所有类型特征都在编译时评估。

## 类型特征类别

有两类类型特征：

+   返回关于类型信息的类型特征，作为布尔值或整数值。

+   返回新类型的类型特征。这些类型特征也被称为元函数。

第一类返回`true`或`false`，取决于输入，并以`_v`结尾（代表值）。

`_v`后缀是在 C++17 中添加的。如果您的库实现不提供类型特征的`_v`后缀，则可以使用旧版本`std::is_floating_point<float>::value`。换句话说，删除`_v`扩展并在末尾添加`::value`。

以下是使用类型特征对基本类型进行编译时类型检查的一些示例：

```cpp
auto same_type = std::is_same_v<uint8_t, unsigned char>; 
auto is_float_or_double = std::is_floating_point_v<decltype(3.f)>; 
```

类型特征也可以用于用户定义的类型：

```cpp
class Planet {};
class Mars : public Planet {};
class Sun {};
static_assert(std::is_base_of_v<Planet, Mars>);
static_assert(!std::is_base_of_v<Planet, Sun>); 
```

类型特征的第二类返回一个新类型，并以`_t`结尾（代表类型）。当处理指针和引用时，这些类型特征转换（或元函数）非常方便：

```cpp
// Examples of type traits which transforms types
using value_type = std::remove_pointer_t<int*>;  // -> int
using ptr_type = std::add_pointer_t<float>;      // -> float* 
```

我们之前使用的类型特征`std::remove_cvref`也属于这个类别。它从类型中移除引用部分（如果有）以及`const`和`volatile`限定符。`std::remove_cvref`是在 C++20 中引入的。在那之前，通常使用`std::decay`来执行此任务。

## 使用类型特征

如前所述，所有类型特征都在编译时评估。例如，以下函数如果值大于或等于零则返回`1`，否则返回`-1`，对于无符号整数可以立即返回`1`，如下所示：

```cpp
template<typename T>
auto sign_func(T v) -> int {
  if (std::is_unsigned_v<T>) { 
    return 1; 
  } 
  return v < 0 ? -1 : 1; 
} 
```

由于类型特征在编译时评估，因此当使用无符号整数和有符号整数调用时，编译器将生成下表中显示的代码：

| 与无符号整数一起使用... | ...生成的函数： |
| --- | --- |

|

```cpp
auto unsigned_v = uint32_t{42};
auto sign = sign_func(unsigned_v); 
```

|

```cpp
int sign_func(uint32_t v) {
  if (true) { 
    return 1; 
  } 
  return v < 0 ? -1 : 1; 
} 
```

|

| 与有符号整数一起使用... | ...生成的函数： |
| --- | --- |

|

```cpp
auto signed_v = int32_t{-42}; 
auto sign = sign_func(signed_v); 
```

|

```cpp
int sign_func(int32_t v) {
  if (false) { 
    return 1; 
  } 
  return v < 0 ? -1 : 1; 
} 
```

|

表 8.1：基于我们传递给`sign_func()`的类型（在左列），编译器生成不同的函数（在右列）。

接下来，让我们谈谈常量表达式。

# 使用常量表达式进行编程

使用`constexpr`关键字前缀的表达式告诉编译器应在编译时评估该表达式：

```cpp
constexpr auto v = 43 + 12; // Constant expression 
```

`constexpr`关键字也可以与函数一起使用。在这种情况下，它告诉编译器某个函数打算在编译时评估，如果满足所有允许进行编译时评估的条件，则会在运行时执行，就像常规函数一样。

`constexpr`函数有一些限制；不允许执行以下操作：

+   处理本地静态变量

+   处理`thread_local`变量

+   调用任何函数，本身不是`constexpr`函数

使用`constexpr`关键字，编写编译时评估的函数与编写常规函数一样容易，因为它的参数是常规参数而不是模板参数。

考虑以下`constexpr`函数：

```cpp
constexpr auto sum(int x, int y, int z) { return x + y + z; } 
```

让我们这样调用函数：

```cpp
constexpr auto value = sum(3, 4, 5); 
```

由于`sum()`的结果用于常量表达式，并且其所有参数都可以在编译时确定，因此编译器将生成以下常规的 C++代码：

```cpp
const auto value = 12; 
```

然后像往常一样将其编译成机器代码。换句话说，编译器评估`constexpr`函数并生成常规的 C++代码，其中计算结果。

如果我们调用`sum()`并将结果存储在未标记为`constexpr`的变量中，编译器可能（很可能）在编译时评估`sum()`：

```cpp
auto value = sum(3, 4, 5); // value is not constexpr 
```

总之，如果从常量表达式调用`constexpr`函数，并且其所有参数都是常量表达式，那么它保证在编译时评估。

## 运行时上下文中的 Constexpr 函数

在前面的例子中，编译器在编译时已知的值（`3`、`4`、`5`）是已知的，但是`constexpr`函数如何处理直到运行时才知道值的变量？如前一节所述，`constexpr`是编译器的指示，表明在某些条件下，函数可以在编译时评估。如果直到运行时调用时才知道值的变量，它们将像常规函数一样被评估。

在下面的例子中，`x`、`y`和`z`的值是在运行时由用户提供的，因此编译器无法在编译时计算总和：

```cpp
int x, y, z; 
std::cin >> x >> y >> z;      // Get user input
auto value = sum(x, y, z); 
```

如果我们根本不打算在运行时使用`sum()`，我们可以通过将其设置为立即函数来禁止这种用法。

## 使用`consteval`声明立即函数

`constexpr`函数可以在运行时或编译时调用。如果我们想限制函数的使用，使其只在编译时调用，我们可以使用关键字`consteval`而不是`constexpr`。假设我们想禁止在运行时使用`sum()`。使用 C++20，我们可以通过以下代码实现：

```cpp
consteval auto sum(int x, int y, int z) { return x + y + z; } 
```

使用`consteval`声明的函数称为**立即函数**，只能生成常量。如果我们想调用`sum()`，我们需要在常量表达式中调用它，否则编译将失败：

```cpp
constexpr auto s = sum(1, 2, 3); // OK
auto x = 10;
auto s = sum(x, 2, 3);           // Error, expression is not const 
```

如果我们尝试在编译时使用参数不明确的`sum()`，编译器也会报错：

```cpp
int x, y, z; 
std::cin >> x >> y >> z; 
constexpr auto s = sum(x, y, z); // Error 
```

接下来讨论`if` `constexpr`语句。

## if constexpr 语句

`if constexpr`语句允许模板函数在同一函数中在编译时评估不同的作用域（也称为编译时多态）。看看下面的例子，其中一个名为`speak()`的函数模板尝试根据类型区分成员函数：

```cpp
struct Bear { auto roar() const { std::cout << "roar\n"; } }; 
struct Duck { auto quack() const { std::cout << "quack\n"; } }; 
template <typename Animal> 
auto speak(const Animal& a) { 
  if (std::is_same_v<Animal, Bear>) { a.roar(); } 
  else if (std::is_same_v<Animal, Duck>) { a.quack(); } 
} 
```

假设我们编译以下行：

```cpp
auto bear = Bear{};
speak(bear); 
```

然后编译器将生成一个类似于这样的`speak()`函数：

```cpp
auto speak(const Bear& a) {
  if (true) { a.roar(); }
  else if (false) { a.quack(); } // This line will not compile
} 
```

如您所见，编译器将保留对成员函数`quack()`的调用，然后由于`Bear`不包含`quack()`成员函数而无法编译。这甚至会发生在`quack()`成员函数由于`else if (false)`语句而永远不会被执行的情况下。

为了使`speak()`函数无论类型如何都能编译，我们需要告诉编译器，如果`if`语句为`false`，我们希望完全忽略作用域。方便的是，这正是`if constexpr`所做的。

以下是我们如何编写`speak()`函数，以便处理`Bear`和`Duck`，即使它们没有共同的接口：

```cpp
template <typename Animal> 
auto speak(const Animal& a) { 
  if constexpr (std::is_same_v<Animal, Bear>) { a.roar(); } 
  else if constexpr (std::is_same_v<Animal, Duck>) { a.quack(); } 
} 
```

当使用`Animal == Bear`调用`speak()`时，如下所示：

```cpp
auto bear = Bear{};
speak(bear); 
```

编译器生成以下函数：

```cpp
auto speak(const Bear& animal) { animal.roar(); } 
```

当使用`Animal == Duck`调用`speak()`时，如下所示：

```cpp
auto duck = Duck{};
speak(duck); 
```

编译器生成以下函数：

```cpp
auto speak(const Duck& animal) { animal.quack(); } 
```

如果使用任何其他原始类型调用`speak()`，例如`Animal == int`，如下所示：

```cpp
speak(42); 
```

编译器生成一个空函数：

```cpp
auto speak(const int& animal) {} 
```

与常规的`if`语句不同，编译器现在能够生成多个不同的函数：一个使用`Bear`，另一个使用`Duck`，如果类型既不是`Bear`也不是`Duck`，则生成最后一个。如果我们想让这第三种情况成为编译错误，我们可以通过添加一个带有`static_assert`的`else`语句来实现：

```cpp
template <typename Animal> 
auto speak(const Animal& a) { 
  if constexpr (std::is_same_v<Animal, Bear>) { a.roar(); } 
  else if constexpr (std::is_same_v<Animal, Duck>) { a.quack(); }
  else { static_assert(false); } // Trig compilation error
} 
```

我们稍后会更多地讨论`static_assert`的用处。

如前所述，这里使用`constexpr`的方式可以称为编译时多态。那么，它与运行时多态有什么关系呢？

### 与运行时多态的比较

顺便说一句，如果我们使用传统的运行时多态来实现前面的例子，使用继承和虚函数来实现相同的功能，实现将如下所示：

```cpp
struct AnimalBase {
  virtual ~AnimalBase() {}
  virtual auto speak() const -> void {}
};
struct Bear : public AnimalBase {
  auto roar() const { std::cout << "roar\n"; } 
  auto speak() const -> void override { roar(); }
};
struct Duck : public AnimalBase {
  auto quack() const { std::cout << "quack\n"; }
  auto speak() const -> void override { quack(); }
}; 
auto speak(const AnimalBase& a) { 
  a.speak();
} 
```

对象必须使用指针或引用进行访问，并且类型在*运行时*推断，这导致性能损失与编译时版本相比，其中应用程序执行时一切都是可用的。下面的图像显示了 C++中两种多态类型之间的区别：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_08_03.png)

图 8.3：运行时多态由虚函数支持，而编译时多态由函数/操作符重载和 if constexpr 支持。

现在，我们将继续看看如何使用`if constexpr`来做一些更有用的事情。

### 使用 if constexpr 的通用模数函数示例

这个例子将向您展示如何使用`if constexpr`来区分运算符和全局函数。在 C++中，`%`运算符用于获取整数的模，而`std::fmod()`用于浮点类型。假设我们想要将我们的代码库泛化，并创建一个名为`generic_mod()`的通用模数函数。

如果我们使用常规的`if`语句来实现`generic_mod()`，如下所示：

```cpp
template <typename T> 
auto generic_mod(const T& v, const T& n) -> T {
  assert(n != 0);
  if (std::is_floating_point_v<T>) { return std::fmod(v, n); }
  else { return v % n; }
} 
```

如果以`T == float`调用它，它将失败，因为编译器将生成以下函数，这将无法编译通过：

```cpp
auto generic_mod(const float& v, const float& n) -> float {
  assert(n != 0);
  if (true) { return std::fmod(v, n); }
  else { return v % n; } // Will not compile
} 
```

尽管应用程序无法到达它，编译器将生成`return v % n;`这一行，这与`float`不兼容。编译器不在乎应用程序是否能到达它——因为它无法为其生成汇编代码，所以它将无法编译通过。

与前面的例子一样，我们将`if`语句更改为`if constexpr`语句：

```cpp
template <typename T> 
auto generic_mod(const T& v, const T& n) -> T { 
  assert(n != 0);
  if constexpr (std::is_floating_point_v<T>) {
    return std::fmod(v, n);
  } else {                 // If T is a floating point,
    return v % n;          // this code is eradicated
  }
} 
```

现在，当使用浮点类型调用函数时，它将生成以下函数，其中`v % n`操作被消除：

```cpp
auto generic_mod(const float& v, const float& n) -> float { 
  assert(n != 0);
  return std::fmod(v, n); 
} 
```

运行时的`assert()`告诉我们，如果第二个参数为 0，我们不能调用这个函数。

## 在编译时检查编程错误

Assert 语句是验证代码库中调用者和被调用者之间不变性和契约的简单但非常强大的工具（见*第二章*，*Essential C++ Techniques*）。使用`assert()`可以在执行程序时检查编程错误。但我们应该始终努力尽早检测错误，如果有常量表达式，我们可以使用`static_assert()`在编译程序时捕获编程错误。

### 使用 assert 在运行时触发错误

回顾`pow_n()`的模板版本。假设我们想要阻止它使用负指数（`n`值）进行调用。在运行时版本中，其中`n`是一个常规参数，我们可以添加一个运行时断言来阻止这种情况：

```cpp
template <typename T> 
auto pow_n(const T& v, int n) { 
  assert(n >= 0); // Only works for positive numbers 
  auto product = T{1}; 
  for (int i = 0; i < n; ++i) {
    product *= v; 
  }
  return product; 
} 
```

如果函数被调用时`n`的值为负数，程序将中断并告知我们应该从哪里开始寻找错误。这很好，但如果我们能在编译时而不是运行时跟踪这个错误会更好。

### 使用`static_assert`在编译时触发错误

如果我们对模板版本做同样的事情，我们可以利用`static_assert()`。与常规的 assert 不同，`static_assert()`声明如果条件不满足将拒绝编译。因此，最好是在编译时中断构建，而不是在运行时中断程序。在下面的例子中，如果模板参数`N`是一个负数，`static_assert()`将阻止函数编译：

```cpp
template <int N, typename T>
auto const_pow_n(const T& v) {
  static_assert(N >= 0, "N must be positive"); 
  auto product = T{1}; 
  for (int i = 0; i < N; ++i) { 
    product *= v; 
  } 
  return product; 
}
auto x = const_pow_n<5>(2);  // Compiles, N is positive
auto y = const_pow_n<-1>(2); // Does not compile, N is negative 
```

换句话说，对于常规变量，编译器只知道类型，不知道它包含什么。对于编译时值，编译器既知道类型又知道值。这使得编译器能够计算其他编译时值。

我们可以（应该）使用无符号整数而不是使用`int`并断言它是非负的。在这个例子中，我们只是使用有符号的`int`来演示`assert()`和`static_assert()`的使用。

使用编译时断言是一种在编译时检查约束的方法。这是一个简单但非常有用的工具。在过去几年中，C++的编译时编程支持取得了一些非常令人兴奋的进展。现在，我们将继续介绍 C++20 中的一个最重要的特性，将约束检查提升到一个新的水平。

# 约束和概念

到目前为止，我们已经涵盖了写 C++元编程的一些重要技术。您已经看到模板如何利用类型特征库为我们生成具体的类和函数。此外，您已经看到了`constexpr`、`consteval`和`if constexpr`的使用可以帮助我们将计算从运行时移动到编译时。通过这种方式，我们可以在编译时检测编程错误，并编写具有较低运行时成本的程序。这很棒，但在编写和使用 C++中的通用代码方面仍有很大的改进空间。我们尚未解决的一些问题包括：

1.  接口太通用。当使用具有任意类型的模板时，很难知道该类型的要求是什么。如果我们只检查模板接口，这使得模板难以使用。相反，我们必须依赖文档或深入到模板的实现中。

1.  类型错误由编译器晚期捕获。编译器最终会在编译常规 C++代码时检查类型，但错误消息通常很难解释。相反，我们希望在实例化阶段捕获类型错误。

1.  无约束的模板参数使元编程变得困难。到目前为止，在本章中我们编写的代码都使用了无约束的模板参数，除了一些静态断言。这对于小例子来说是可以管理的，但如果我们能够像类型系统帮助我们编写正确的非通用 C++代码一样，获得更有意义的类型，那么编写和推理我们的元编程将会更容易。

1.  使用`if constexpr`可以进行条件代码生成（编译时多态），但在较大规模上很快变得难以阅读和编写。

正如您将在本节中看到的，C++概念以一种优雅而有效的方式解决了这些问题，引入了两个新关键字：`concept`和`requires`。在探讨约束和概念之前，我们将花一些时间考虑没有概念的模板元编程的缺点。然后，我们将使用约束和概念来加强我们的代码。

## Point2D 模板的无约束版本

假设我们正在编写一个处理二维坐标系的程序。我们有一个类模板，表示具有`x`和`y`坐标的点，如下所示：

```cpp
template <typename T>
class Point2D {
public:
  Point2D(T x, T y) : x_{x}, y_{y} {}
  auto x() { return x_; }
  auto y() { return y_; }
  // ...
private:
  T x_{};
  T y_{};
}; 
```

假设我们需要找到两点**p1**和**p2**之间的欧几里德距离，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_08_04.png)

图 8.4：找到 p1 和 p2 之间的欧几里得距离

为了计算距离，我们实现了一个接受两个点并使用勾股定理的自由函数（这里实际的数学并不重要）：

```cpp
auto dist(auto p1, auto p2) {
  auto a = p1.x() - p2.x();
  auto b = p1.y() - p2.y();
  return std::sqrt(a*a + b*b);
} 
```

一个小的测试程序验证了我们可以用整数实例化`Point2D`模板，并计算两点之间的距离：

```cpp
int main() {
  auto p1 = Point2D{2, 2};
  auto p2 = Point2D{6, 5};
  auto d = dist(p1, p2);
  std::cout << d;
} 
```

这段代码编译和运行都很好，并在控制台输出`5`。

### 通用接口和糟糕的错误消息

在继续之前，让我们稍微偏离一下，对函数模板`dist()`进行一段时间的反思。假设我们无法轻松访问`dist()`的实现，只能读取接口：

```cpp
auto dist(auto p1, auto p2) // Interface part 
```

我们可以说返回类型和`p1`和`p2`的类型有什么？实际上几乎没有——因为`p1`和`p2`完全*未受约束*，`dist()`的接口对我们来说没有透露任何信息。这并不意味着我们可以将任何东西传递给`dist()`，因为最终生成的常规 C++代码必须编译。

例如，如果我们尝试用两个整数而不是`Point2D`对象来实例化我们的`dist()`模板，就像这样：

```cpp
 auto d = dist(3, 4); 
```

编译器将很乐意生成一个常规的 C++函数，类似于这样：

```cpp
auto dist(int p1, int p2) {
  auto a = p1.x() – p2.x();  // Will generate an error:
  auto b = p1.y() – p2.y();  // int does not have x() and y()
  return std::sqrt(a*a + b*b);
} 
```

当编译器检查常规的 C++代码时，错误将在稍后被捕获。当尝试用两个整数实例化`dist()`时，Clang 生成以下错误消息：

```cpp
error: member reference base type 'int' is not a structure or union
auto a = p1.x() – p2.y(); 
```

这个错误消息是指`dist()`的*实现*，这是调用函数`dist()`的调用者不需要知道的东西。这是一个微不足道的例子，但是尝试解释由于向复杂的模板库提供错误类型而引起的错误消息可能是一个真正的挑战。

更糟糕的是，如果我们真的很不幸，通过提供根本没有意义的类型来完成整个编译。在这种情况下，我们正在用`const char*`实例化`Point2D`：

```cpp
int main() {
  auto from = Point2D{"2.0", "2.0"}; // Ouch!
  auto to = Point2D{"6.0", "5.0"};   // Point2D<const char*>
  auto d = dist(from, to);
  std::cout << d;
} 
```

它编译并运行，但输出可能不是我们所期望的。我们希望在过程的早期阶段捕获这些类型的错误，这是我们可以通过使用约束和概念来实现的，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-hiperf/img/B15619_08_05.png)

图 8.5：使用约束和概念可以在实例化阶段捕获类型错误

稍后，您将看到如何使此代码更具表现力，以便更容易正确使用并更难滥用。我们将通过向我们的代码添加概念和约束来实现这一点。但首先，我将快速概述如何定义和使用概念。

## 约束和概念的语法概述

本节是对约束和概念的简要介绍。我们不会在本书中完全覆盖它们，但我会为您提供足够的材料来提高生产力。

### 定义新概念

使用您已经熟悉的类型特征，可以轻松地定义新概念。以下示例使用关键字`concept`定义了概念`FloatingPoint`：

```cpp
template <typename T>
concept FloatingPoint = std::is_floating_point_v<T>; 
```

赋值表达式的右侧是我们可以指定类型`T`的约束的地方。还可以使用`||`（逻辑或）和`&&`（逻辑与）来组合多个约束。以下示例使用`||`将浮点数和整数组合成`Number`概念：

```cpp
template <typename T>
concept Number = FloatingPoint<T> || std::is_integral_v<T>; 
```

您将注意到，还可以使用右侧已定义的概念构建概念。标准库包含一个`<concepts>`头文件，其中定义了许多有用的概念，例如`std::floating_point`（我们应该使用它而不是定义自己的）。

此外，我们可以使用`requires`关键字来添加一组语句，这些语句应该添加到我们的概念定义中。例如，这是来自 Ranges 库的概念`std::range`的定义：

```cpp
template<typename T>
concept range = requires(T& t) {
  ranges::begin(t);
  ranges::end(t);
}; 
```

简而言之，这个概念说明了范围是我们可以传递给`std::ranges::begin()`和`std::ranges::end()`的东西。

可以编写比这更复杂的`requires`子句，稍后您将看到更多内容。

### 使用概念约束类型

我们可以通过使用`requires`关键字向模板参数类型添加约束。以下模板只能使用`std::integral`概念实例化整数类型的参数：

```cpp
template <typename T>
requires std::integral<T>
auto mod(T v, T n) { 
  return v % n;
} 
```

在定义类模板时也可以使用相同的技术：

```cpp
template <typename T>
requires std::integral<T>
struct Foo {
  T value;
}; 
```

另一种语法允许我们以更紧凑的方式编写，通过直接用概念替换`typename`：

```cpp
template <std::integral T>
auto mod(T v, T n) { 
  return v % n;
} 
```

这种形式也可以用于类模板：

```cpp
template <std::integral T>
struct Foo {
  T value;
}; 
```

如果我们想在定义函数模板时使用缩写的函数模板形式，我们可以在`auto`关键字前面添加概念：

```cpp
auto mod(std::integral auto v, std::integral auto n) {
  return v % n;
} 
```

返回类型也可以通过使用概念来约束：

```cpp
std::integral auto mod(std::integral auto v, std::integral auto n) {
  return v % n;
} 
```

正如你所看到的，有许多方法可以指定相同的事情。缩写形式与概念的结合确实使有限函数模板的阅读和编写变得非常容易。C++概念的另一个强大特性是以清晰和表达性的方式重载函数。

### 函数重载

回想一下我们之前使用`if constexpr`实现的`generic_mod()`函数。它看起来像这样：

```cpp
template <typename T> 
auto generic_mod(T v, T n) -> T { 
  if constexpr (std::is_floating_point_v<T>) {
    return std::fmod(v, n);
  } else {
    return v % n;
  } 
} 
```

通过使用概念，我们可以重载一个函数模板，类似于我们如果编写了一个常规的 C++函数：

```cpp
template <std::integral T>
auto generic_mod(T v, T n) -> T {             // Integral version
  return v % n;
}
template <std::floating_point T>
auto generic_mod(T v, T n) -> T {             // Floating point version
  return std::fmod(v, n);
} 
```

有了你对约束和概念的新知识，现在是时候回到我们的`Point2D`模板的例子，看看它如何改进。

## Point2D 模板的约束版本

现在你知道如何定义和使用概念了，让我们通过编写一个更好的模板`Point2D`和`dist()`来使用它们。记住，我们的目标是一个更具表现力的接口，并且使由无关参数类型引起的错误在模板实例化时出现。

我们将首先创建一个算术类型的概念：

```cpp
template <typename T>
concept Arithmetic = std::is_arithmetic_v<T>; 
```

接下来，我们将创建一个名为`Point`的概念，它定义了一个点应该具有成员函数`x()`和`y()`返回相同类型，并且这个类型应该支持算术操作：

```cpp
template <typename T>
concept Point = requires(T p) {
  requires std::is_same_v<decltype(p.x()), decltype(p.y())>;
  requires Arithmetic<decltype(p.x())>;
}; 
```

这个概念现在可以通过显式约束使`dist()`的接口更好：

```cpp
auto dist(Point auto p1, Point auto p2) {
  // Same as before ... 
```

这看起来真的很有希望，所以让我们也对我们的返回类型添加一个约束。虽然`Point2D`可能被实例化为整数类型，但我们知道距离可以是浮点数。标准库中的概念`std::floating_point`非常适合这个。这是`dist()`的最终版本：

```cpp
std::floating_point auto dist(Point auto p1, Point auto p2) { 
  auto a = p1.x() - p2.x();
  auto b = p1.y() - p2.y();
  return std::sqrt(a*a + b*b);
} 
```

我们的接口现在更加描述性，当我们尝试用错误的参数类型实例化它时，我们将在实例化阶段而不是最终编译阶段获得错误。

现在我们应该对我们的`Point2D`模板做同样的事情，以避免有人意外地用它实例化它不打算处理的类型。例如，我们希望阻止有人用`const char*`实例化`Point2D`类，就像这样：

```cpp
auto p1 = Point2D{"2.0", "2.0"}; // How can we prevent this? 
```

我们已经创建了`Arithmetic`概念，我们可以在这里使用它来在`Point2D`的模板参数中放置约束。这是我们如何做到的：

```cpp
template <Arithmetic T> // T is now constrained!
class Point2D {
public:
  Point2D(T x, T y) : x_{x}, y_{y} {}
  auto x() { return x_; }
  auto y() { return y_; }
  // ...
private:
  T x_{};
  T y_{};
}; 
```

我们唯一需要改变的是指定类型`T`应该支持概念`Arithmetic`指定的操作。尝试使用`const char*`实例化模板现在将生成一个直接的错误消息，而编译器尝试实例化`Point2D<const char*>`类。

## 向你的代码添加约束

概念的实用性远远超出了模板元编程。这是 C++20 的一个基本特性，改变了我们使用概念而不是具体类型或完全无约束的变量声明`auto`来编写和推理代码的方式。

概念非常类似于类型（如`int`、`float`或`Plot2D<int>`）。类型和概念都指定了对象上支持的一组操作。通过检查类型或概念，我们可以确定某些对象如何构造、移动、比较和通过成员函数访问等。然而，一个重大的区别是，概念并不说任何关于对象如何存储在内存中，而类型除了其支持的操作集之外还提供了这些信息。例如，我们可以在类型上使用`sizeof`运算符，但不能在概念上使用。

通过概念和`auto`，我们可以声明变量而无需明确指出确切的类型，但仍然非常清楚地表达我们的意图。看一下以下代码片段：

```cpp
const auto& v = get_by_id(42); // What can I do with v? 
```

大多数时候，当我们遇到这样的代码时，我们更感兴趣的是我们可以在`v`上执行哪些操作，而不是知道确切的类型。在`auto`前面添加一个概念会产生不同的效果：

```cpp
const Person auto& v = get_by_id(42);
v.get_name(); 
```

几乎可以在几乎所有可以使用关键字 `auto` 的上下文中使用概念：局部变量、返回值、函数参数等等。在我们的代码中使用概念使得阅读更加容易。在撰写本书时（2020 年中），已经建立的 C++ IDE 中目前还没有对概念的额外支持。然而，代码补全以及其他基于概念的有用编辑器功能很快就会可用，使得 C++ 编码更加有趣和安全。

## 标准库中的概念

C++20 还包括一个新的 `<concepts>` 头文件，其中包含预定义的概念。您已经看到其中一些概念的作用。许多概念都是基于类型特性库中的特性。然而，有一些基本概念以前没有用特性表达。其中最重要的是比较概念，如 `std::equality_comparable` 和 `std::totally_ordered`，以及对象概念，如 `std::movable`、`std::copyable`、`std::regular` 和 `std::semiregular`。我们不会在标准库的概念上花费更多时间，但在开始定义自己的概念之前，请记住将它们牢记在心。在正确的泛化级别上定义概念并不是件容易的事，通常明智的做法是基于已经存在的概念定义新的概念。

让我们通过查看 C++ 中一些实际的元编程示例来结束本章。

# 元编程的实际例子

高级元编程可能看起来非常学术化，因此为了展示其有用性，让我们看一些不仅演示元编程语法的例子，还演示它如何在实践中使用。

## 示例 1：创建一个通用的安全转换函数

在 C++ 中进行数据类型转换时，有多种不同的方式会出错：

+   如果将值转换为比特长度较低的整数类型，可能会丢失一个值。

+   如果将负值转换为无符号整数，可能会丢失一个值。

+   如果从指针转换为任何其他整数而不是 `uintptr_t`，正确的地址可能会变得不正确。这是因为 C++ 仅保证 `uintptr_t` 是唯一可以保存地址的整数类型。

+   如果从 `double` 转换为 `float`，结果可能是 `int`，如果 `double` 值太大，`float` 无法容纳。

+   如果使用 `static_cast()` 在指针之间进行转换，如果类型没有共同的基类，可能会得到未定义的行为。

为了使我们的代码更加健壮，我们可以创建一个通用的检查转换函数，在调试模式下验证我们的转换，并在发布模式下尽可能快地执行我们的转换。

根据被转换的类型，会执行不同的检查。如果我们尝试在未经验证的类型之间进行转换，它将无法编译。

这些是 `safe_cast()` 旨在处理的情况：

+   相同类型：显然，如果我们转换相同类型，我们只需返回输入值。

+   指针到指针：如果在指针之间进行转换，`safe_cast()` 在调试模式下执行动态转换以验证是否可转换。

+   双精度浮点数到浮点数：`safe_cast()` 在从 `double` 转换为 `float` 时接受精度损失，但有一个例外 - 如果从 `double` 转换为 `float`，则有可能 `double` 太大，使得 `float` 无法处理结果。

+   算术到算术：如果在算术类型之间进行转换，值将被转换回其原始类型以验证是否丢失精度。

+   指针到非指针：如果从指针转换为非指针类型，`safe_cast()` 验证目标类型是否为 `uintptr_t` 或 `intptr_t`，这是唯一保证能够保存地址的整数类型。

在任何其他情况下，`safe_cast()` 函数将无法编译。

让我们看看如何实现这一点。我们首先获取有关我们的转换操作的`constexpr`布尔值的信息。它们是`constexpr`布尔值而不是`const`布尔值的原因是，我们将在稍后的`if constexpr`表达式中使用它们，这些表达式需要`constexpr`条件：

```cpp
template <typename T> constexpr auto make_false() { return false; }
template <typename Dst, typename Src> 
auto safe_cast(const Src& v) -> Dst{ 
  using namespace std;
  constexpr auto is_same_type = is_same_v<Src, Dst>;
  constexpr auto is_pointer_to_pointer =  
    is_pointer_v<Src> && is_pointer_v<Dst>; 
  constexpr auto is_float_to_float =  
    is_floating_point_v<Src> && is_floating_point_v<Dst>; 
  constexpr auto is_number_to_number =  
    is_arithmetic_v<Src> && is_arithmetic_v<Dst>; 
  constexpr auto is_intptr_to_ptr = 
    (is_same_v<uintptr_t,Src> || is_same_v<intptr_t,Src>)
    && is_pointer_v<Dst>;
  constexpr auto is_ptr_to_intptr =
    is_pointer_v<Src> &&
    (is_same_v<uintptr_t,Dst> || is_same_v<intptr_t,Dst>); 
```

因此，现在我们已经获得了关于转换的所有必要信息，作为`constexpr`布尔值，我们在编译时断言我们可以执行转换。如前所述，如果条件不满足，`static_assert()`将无法编译通过（与常规 assert 不同，后者在运行时验证条件）。

请注意在`if`/`else`链的末尾使用了`static_assert()`和`make_false<T>`。我们不能只输入`static_assert(false)`，因为那样会完全阻止`safe_cast()`的编译；相反，我们利用模板函数`make_false<T>()`来推迟生成，直到需要时。

当执行实际的`static_cast()`时，我们将回到原始类型并验证结果是否等于未转换的参数，使用常规的运行时`assert()`。这样，我们可以确保`static_cast()`没有丢失任何数据：

```cpp
 if constexpr(is_same_type) { 
    return v; 
  }
  else if constexpr(is_intptr_to_ptr || is_ptr_to_intptr){
    return reinterpret_cast<Dst>(v); 
  } 
  else if constexpr(is_pointer_to_pointer) { 
    assert(dynamic_cast<Dst>(v) != nullptr); 
    return static_cast<Dst>(v); 
  } 
  else if constexpr (is_float_to_float) { 
    auto casted = static_cast<Dst>(v); 
    auto casted_back = static_cast<Src>(v); 
    assert(!isnan(casted_back) && !isinf(casted_back)); 
    return casted; 
  }  
  else if constexpr (is_number_to_number) { 
    auto casted = static_cast<Dst>(v); 
    auto casted_back = static_cast<Src>(casted); 
    assert(casted == casted_back); 
    return casted; 
  } 
  else {
    static_assert(make_false<Src>(),"CastError");
    return Dst{}; // This can never happen, 
    // the static_assert should have failed 
  }
} 
```

请注意我们如何使用`if constexpr`来使函数有条件地编译。如果我们使用普通的`if`语句，函数将无法编译通过。

```cpp
auto x = safe_cast<int>(42.0f); 
```

这是因为编译器将尝试编译以下行，而`dynamic_cast`只接受指针：

```cpp
// type To is an integer
assert(dynamic_cast<int>(v) != nullptr); // Does not compile 
```

然而，由于`if constexpr`和`safe_cast<int>(42.0f)`的构造，以下函数可以正确编译：

```cpp
auto safe_cast(const float& v) -> int {
  constexpr auto is_same_type = false;
  constexpr auto is_pointer_to_pointer = false;
  constexpr auto is_float_to_float = false;
  constexpr auto is_number_to_number = true;
  constexpr auto is_intptr_to_ptr = false;
  constexpr auto is_ptr_to_intptr = false
  if constexpr(is_same_type) { /* Eradicated */ }
  else if constexpr(is_intptr_to_ptr||is_ptr_to_intptr){/* Eradicated */}
  else if constexpr(is_pointer_to_pointer) {/* Eradicated */}
  else if constexpr(is_float_to_float) {/* Eradicated */}
  else if constexpr(is_number_to_number) {
    auto casted = static_cast<int>(v);
    auto casted_back = static_cast<float>(casted);
    assert(casted == casted_back);
    return casted;
  }
  else { /* Eradicated */ }
} 
```

如你所见，除了`is_number_to_number`子句之外，在`if constexpr`语句之间的所有内容都已经被完全消除，从而使函数能够编译。

## 示例 2：在编译时对字符串进行哈希处理

假设我们有一个资源系统，其中包含一个无序映射的字符串，用于标识位图。如果位图已经加载，系统将返回已加载的位图；否则，它将加载位图并返回：

```cpp
// External function which loads a bitmap from the filesystem
auto load_bitmap_from_filesystem(const char* path) -> Bitmap {/* ... */}
// Bitmap cache 
auto get_bitmap_resource(const std::string& path) -> const Bitmap& { 
  // Static storage of all loaded bitmaps
  static auto loaded = std::unordered_map<std::string, Bitmap>{};
  // If the bitmap is already in loaded_bitmaps, return it
  if (loaded.count(path) > 0) {
    return loaded.at(path);
  } 
  // The bitmap isn't already loaded, load and return it 
  auto bitmap = load_bitmap_from_filesystem(path.c_str());
  loaded.emplace(path, std::move(bitmap)); 
  return loaded.at(path); 
} 
```

然后在需要位图资源的地方使用位图缓存：

+   如果尚未加载，`get_bitmap_resource()`函数将加载并返回它

+   如果已经在其他地方加载过，`get_bitmap_resource()`将简单地返回已加载的函数。

因此，无论哪个绘制函数先执行，第二个函数都不必从磁盘加载位图：

```cpp
auto draw_something() {
  const auto& bm = get_bitmap_resource("my_bitmap.png");
  draw_bitmap(bm);
}
auto draw_something_again() {
  const auto& bm = get_bitmap_resource("my_bitmap.png");
  draw_bitmap(bm);
} 
```

由于我们使用了无序映射，每当我们检查位图资源时都需要计算哈希值。现在您将看到我们如何通过将计算移动到编译时来优化运行时代码。

### 编译时哈希值计算的优势

我们将尝试解决的问题是，每次执行`get_bitmap_resource("my_bitmap.png")`这一行时，应用程序都会在运行时计算字符串`"my_bitmap.png"`的哈希值。我们希望在编译时执行这个计算，这样当应用程序执行时，哈希值已经被计算出来。换句话说，就像你们学习使用元编程在编译时生成函数和类一样，我们现在要让它在编译时生成哈希值。

你可能已经得出结论，这是所谓的*微优化*：计算一个小字符串的哈希值不会对应用程序的性能产生任何影响，因为这是一个非常小的操作。这可能完全正确；这只是一个将计算从运行时移动到编译时的示例，可能还有其他情况下这可能会产生显著的性能影响。

顺便说一句，当为弱硬件编写软件时，字符串哈希是一种纯粹的奢侈，但在编译时对字符串进行哈希处理可以让我们在任何平台上都享受到这种奢侈，因为一切都是在编译时计算的。

### 实现和验证编译时哈希函数

为了使编译器能够在编译时计算哈希和，我们重写`hash_function()`，使其以一个高级类（如`std::string`）的原始空终止`char`字符串作为参数，这在编译时无法计算。现在，我们可以将`hash_function()`标记为`constexpr`：

```cpp
constexpr auto hash_function(const char* str) -> size_t {
  auto sum = size_t{0};
  for (auto ptr = str; *ptr != '\0'; ++ptr)
    sum += *ptr;
  return sum;
} 
```

现在，让我们使用在编译时已知的原始字面字符串调用它：

```cpp
auto hash = hash_function("abc"); 
```

编译器将生成以下代码片段，这是与`a`，`b`和`c`对应的 ASCII 值的总和（`97`，`98`和`99`）：

```cpp
auto hash = size_t{294}; 
```

只是累积单个值是一个非常糟糕的哈希函数；在实际应用中不要这样做。这里只是因为它容易理解。一个更好的哈希函数是将所有单个字符与`boost::hash_combine()`结合起来，如*第四章*，*数据结构*中所解释的那样。

`hash_function()`只有在编译器在编译时知道字符串时才会在编译时计算；如果不知道，编译器将像任何其他表达式一样在运行时执行`constexpr`。

既然我们已经有了哈希函数，现在是时候创建一个使用它的字符串类了。

### 构造一个 PrehashedString 类

我们现在准备实现一个用于预哈希字符串的类，它将使用我们创建的哈希函数。这个类包括以下内容：

+   一个以原始字符串作为参数并在构造时计算哈希的构造函数。

+   比较运算符。

+   一个`get_hash()`成员函数，返回哈希值。

+   `std::hash()`的重载，简单地返回哈希值。这个重载被`std::unordered_map`，`std::unordered_set`或标准库中使用哈希值的任何其他类使用。简单地说，这使得容器意识到`PrehashedString`存在一个哈希函数。

这是`PrehashedString`类的基本实现：

```cpp
class PrehashedString {
public:
  template <size_t N>
  constexpr PrehashedString(const char(&str)[N])
      : hash_{hash_function(&str[0])}, size_{N - 1},
      // The subtraction is to avoid null at end
        strptr_{&str[0]} {}
  auto operator==(const PrehashedString& s) const {
    return
      size_ == s.size_ &&
      std::equal(c_str(), c_str() + size_, s.c_str());
  }
  auto operator!=(const PrehashedString& s) const {
    return !(*this == s); }
  constexpr auto size()const{ return size_; }
  constexpr auto get_hash()const{ return hash_; }
  constexpr auto c_str()const->const char*{ return strptr_; }
private:
  size_t hash_{};
  size_t size_{};
  const char* strptr_{nullptr};
};
namespace std {
template <>
struct hash<PrehashedString> {
  constexpr auto operator()(const PrehashedString& s) const {
    return s.get_hash();
  }
};
} // namespace std 
```

请注意构造函数中的模板技巧。这迫使`PrehashedString`只接受编译时字符串字面值。这样做的原因是`PrehashedString`类不拥有`const char* ptr`，因此我们只能在编译时使用它创建的字符串字面值：

```cpp
// This compiles
auto prehashed_string = PrehashedString{"my_string"};
// This does not compile
// The prehashed_string object would be broken if the str is modified
auto str = std::string{"my_string"};
auto prehashed_string = PrehashedString{str.c_str()};
// This does not compile.
// The prehashed_string object would be broken if the strptr is deleted
auto* strptr = new char[5];
auto prehashed_string = PrehashedString{strptr}; 
```

所以，既然我们已经准备就绪，让我们看看编译器如何处理`PrehashedString`。

### 评估 PrehashedString

这是一个简单的测试函数，返回字符串`"abc"`的哈希值（为了简单起见）：

```cpp
auto test_prehashed_string() {
  const auto& hash_fn = std::hash<PrehashedString>{};
  const auto& str = PrehashedString("abc");
  return hash_fn(str);
} 
```

由于我们的哈希函数只是对值求和，而`"abc"`中的字母具有 ASCII 值*a* = 97，*b* = 98，*c* = 99，由 Clang 生成的汇编代码应该输出和为 97 + 98 + 99 = 294。检查汇编代码，我们可以看到`test_prehashed_string()`函数编译成了一个`return`语句，返回`294`：

```cpp
mov eax, 294
ret 
```

这意味着整个`test_prehashed_string()`函数已经在编译时执行；当应用程序执行时，哈希和已经被计算！

### 使用 PrehashedString 评估 get_bitmap_resource()

让我们回到最初的`get_bitmap_resource()`函数，最初使用的`std::string`已经被替换为`PrehashedString`：

```cpp
// Bitmap cache
auto get_bitmap_resource(const PrehashedString& path) -> const Bitmap& 
{
  // Static storage of all loaded bitmaps
  static auto loaded_bitmaps =
    std::unordered_map<PrehashedString, Bitmap>{};
  // If the bitmap is already in loaded_bitmaps, return it
  if (loaded_bitmaps.count(path) > 0) {
    return loaded_bitmaps.at(path);
  }
  // The bitmap isn't already loaded, load and return it
  auto bitmap = load_bitmap_from_filesystem(path.c_str());
  loaded_bitmaps.emplace(path, std::move(bitmap));
  return loaded_bitmaps.at(path);
} 
```

我们还需要一个测试函数：

```cpp
auto test_get_bitmap_resource() { return get_bitmap_resource("abc"); } 
```

我们想知道的是这个函数是否预先计算了哈希和。由于`get_bitmap_resource()`做了很多事情（构造静态`std::unordered_map`，检查映射等），生成的汇编代码大约有 500 行。尽管如此，如果我们的魔术哈希和在汇编代码中找到，这意味着我们成功了。

当检查由 Clang 生成的汇编代码时，我们将找到一行对应于我们的哈希和，`294`：

```cpp
.quad   294                     # 0x126 
```

为了确认这一点，我们将字符串从`"abc"`改为`"aaa"`，这应该将汇编代码中的这一行改为 97 * 3 = 291，但其他一切应该完全相同。

我们这样做是为了确保这不只是一些其他与哈希和毫不相关的魔术数字。

检查生成的汇编代码，我们将找到期望的结果：

```cpp
.quad   291                     # 0x123 
```

除了这一行之外，其他都是相同的，因此我们可以安全地假设哈希是在编译时计算的。

我们所看到的示例表明，我们可以将编译时编程用于非常不同的事情。添加可以在编译时验证的安全检查，使我们能够在不运行程序并通过覆盖测试搜索错误的情况下找到错误。并且将昂贵的运行时操作转移到编译时可以使我们的最终程序更快。

# 总结

在本章中，您已经学会了如何使用元编程来在编译时而不是运行时生成函数和值。您还发现了如何以现代 C++的方式使用模板、`constexpr`、`static_assert()`和`if constexpr`、类型特征和概念来实现这一点。此外，通过常量字符串哈希，您看到了如何在实际环境中使用编译时评估。

在下一章中，您将学习如何进一步扩展您的 C++工具箱，以便您可以通过构建隐藏的代理对象来创建库。
