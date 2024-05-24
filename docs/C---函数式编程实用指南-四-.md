# C++ 函数式编程实用指南（四）

> 原文：[`annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f`](https://annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：基于属性的测试

我们已经看到纯函数有一个重要的属性——它们对于相同的输入返回相同的输出。我们也看到这个属性使我们能够轻松地为纯函数编写基于示例的单元测试。此外，我们可以编写数据驱动的测试，允许一个测试函数被多个输入和输出重复使用。

事实证明，我们甚至可以做得更好。除了编写许多行的数据驱动测试之外，我们还可以利用纯函数的数学属性。这种技术是由函数式编程启用的数据生成器所实现的。这些测试被误导地称为**基于属性的测试**；您必须记住，这个名称来自纯函数的数学属性，而不是来自类或对象中实现的属性。

本章将涵盖以下主题：

+   理解基于属性的测试的概念

+   如何编写生成器并利用它们

+   如何从基于示例的测试转向基于属性的测试

+   如何编写良好的属性

# 技术要求

您将需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.4.0。

代码可以在 GitHub 上找到，网址为[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)，位于`Chapter11`文件夹中。它包括并使用了`doctest`，这是一个单头开源单元测试库。您可以在其 GitHub 存储库上找到它，网址为[https:/​/github.com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# 基于属性的测试

单元测试是一种非常有用的软件开发技术。一套良好的单元测试可以做到以下几点：

+   通过自动化回归测试的繁琐部分来加快部署速度。

+   使专业测试人员能够发现隐藏的问题，而不是一遍又一遍地运行相同的测试计划。

+   在开发过程的早期消除错误，从而减少查找和修复错误的成本。

+   通过提供反馈来改进软件设计，作为代码结构的第一个客户端（如果测试复杂，很可能您的设计也很复杂），只要开发人员知道如何看到和解释反馈。

+   增加对代码的信任，从而允许更多的更改，从而促进加速开发或消除代码中的风险。

我喜欢编写单元测试。我喜欢找出有趣的测试用例，我喜欢使用测试驱动我的代码——正如您在第九章中所看到的，*函数式编程的测试驱动开发*。与此同时，我一直在寻找更好的编写测试的方法，因为如果我们能加快这个过程，那将是很棒的。

我们已经在第九章中看到，纯函数使我们更容易识别测试用例，因为根据定义，它们的输出是受限制的。事实证明，如果我们涉足与这些纯函数相关的数学属性领域，我们可以走得更远。

如果您已经写了一段时间的单元测试，您可能会觉得其中一些测试有点多余。如果我们能够编写这样的测试——对于一定范围内的输入，预期输出必须具有某种属性，那将是很好的。事实证明，借助数据生成器和一点抽象思维，我们可以做到这一点。

让我们比较一下方法。

# 基于示例的测试与基于属性的测试

让我们以`power`函数为例：

```cpp
function<int(int, int)> power = [](auto first, auto second){
    return pow(first, second);
};
```

如何使用基于示例的测试来测试它？我们需要找出一些有趣的值作为第一个和第二个，并将它们组合。对于这个练习的目标，我们将限制自己只使用正整数。一般来说，整数的有趣值是`0`，`1`，很多，和最大值。这导致了以下可能的情况：

+   *0⁰ -> 未定义*（在 C++的 pow 实现中，除非启用了特定错误，否则返回`1`）

+   *0^(0 到 max 之间的任何整数) -> 0*

+   *1^(任何整数) -> 1*

+   *(除了 0 之外的任何整数)⁰ -> 1*

+   *2² -> 4*

+   *2^(不会溢出的最大整数) -> 要计算的值*

+   *10⁵ -> 100000*

+   *10^(不会溢出的最大整数) -> 要计算的值*

这个清单当然并不完整，但它展示了对问题的有趣分析。因此，让我们写下这些测试：

```cpp
TEST_CASE("Power"){
    int maxInt = numeric_limits<int>::max();
    CHECK_EQ(1, power(0, 0));
    CHECK_EQ(0, power(0, 1));
    CHECK_EQ(0, power(0, maxInt));
    CHECK_EQ(1, power(1, 1));
    CHECK_EQ(1, power(1, 2));
    CHECK_EQ(1, power(1, maxInt));
    CHECK_EQ(1, power(2, 0));
    CHECK_EQ(2, power(2, 1));
    CHECK_EQ(4, power(2, 2));
    CHECK_EQ(maxInt, power(2, 31) - 1);
    CHECK_EQ(1, power(3, 0));
    CHECK_EQ(3, power(3, 1));
    CHECK_EQ(9, power(3, 2));
    CHECK_EQ(1, power(maxInt, 0));
    CHECK_EQ(maxInt, power(maxInt, 1));
}
```

这显然不是我们需要检查以确保幂函数有效的所有测试的完整清单，但这是一个很好的开始。看着这个清单，我在想，你认为——你会写更多还是更少的测试？我肯定想写更多，但在这个过程中我失去了动力。当然，其中一个问题是我是在编写代码之后才写这些测试；我更有动力的是在编写代码的同时编写测试，就像**测试驱动开发**（**TDD**）一样。但也许有更好的方法？

让我们换个角度思考一下。有没有一些我们可以测试的属性，适用于一些或所有的预期输出？让我们写一个清单：

+   *0⁰ -> 未定义（在 C++的 pow 函数中默认为 1）*

+   *0^([1 .. maxInt]) -> 0*

+   *值：[1 .. maxInt]⁰ -> 1*

+   *值：[0 .. maxInt]¹ -> 值*

这些是一些明显的属性。然而，它们只涵盖了一小部分值。我们仍然需要涵盖*x**^y*的一般情况，其中*x*和*y*都不是`0`或`1`。我们能找到任何属性吗？好吧，想想整数幂的数学定义——它是重复的乘法。因此，我们可以推断，对于大于`1`的任何*x*和*y*值，以下成立：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/785b00f6-7df4-4d02-94ee-1e520377ed0c.png)

我们在这里有一个边界问题，因为计算可能会溢出。因此，需要选择*x*和*y*的值，使*x^y*小于`maxInt`。解决这个问题的一种方法是首先选择*x*，然后选择*y*在*y=2*和`maxy=floor(log[x]maxInt)`之间。为了尽可能接近边界，我们应该始终选择`maxy`作为一个值。要检查溢出情况，我们只需要测试*x*的`maxy + 1`次方是否溢出。

前面的方法当然意味着我们信任标准库中对数函数的结果。如果你的“测试者偏执狂”比我更大，我建议使用经过验证的对数表，包括从`2`到`maxInt`和值`maxInt`的所有基数。然而，我会使用 STL 对数函数。

现在我们有了幂函数的数学属性清单。但我们想要像之前看到的那样，使用区间来实现它们。我们能做到吗？这就是数据生成器的作用。

# 生成器

生成器是函数式编程语言的一个重要特性。它们通常通过 lambda 和惰性求值的组合来实现，允许编写以下代码：

```cpp
// pseudocode
vector<int> values = generate(1, maxInt, [](){/*generatorCode*/}).pick(100)
```

生成器函数通常会生成无限数量的值，但由于它是惰性求值的，只有在调用`pick`时，这`100`个值才会实现。

C++目前还没有标准支持惰性求值和数据生成器，因此我们必须实现自己的生成器。值得注意的是，C++ 20 已经采纳了在标准中包含了令人敬畏的 ranges 库，该库可以实现这两个功能。对于本章的目标，我们将坚持使用今天可用的标准，但你将在本书的最后几章中找到 ranges 库的基本用法。

首先，我们如何生成数据？STL 为我们提供了一种生成均匀分布的随机整数的好方法，使用`uniform_int_distribution`类。让我们先看看代码；我已经添加了注释来解释发生了什么：

```cpp
auto generate_ints = [](const int min, const int max){
    random_device rd; // use for generating the seed
    mt19937 generator(rd()); // used for generating pseudo-random 
        numbers
    uniform_int_distribution<int> distribution(min, max); // used to 
        generate uniformly distributed numbers between min and max
    auto values = transformAll<vector<int>>(range(0, 98), // generates 
        the range [0..98]
            &distribution, &generator{
                return distribution(generator); // generate the random 
                    numbers
            });
    values.push_back(min); // ensure that min and max values are 
        included
    values.push_back(max);
    return values;
};
```

这个函数将从`min`到`max`生成均匀分布的数字。我倾向于始终包括区间的边缘，因为这些对于测试来说总是有趣的值。

我们还使用了一个名为`range`的函数，您还没有看到。它的目标是用`minValue`到`maxValue`的值填充一个向量，以便进行简单的转换。在这里：

```cpp
auto range = [](const int minValue, const int maxValue){
    vector<int> range(maxValue - minValue + 1);
    iota(range.begin(), range.end(), minValue);
    return range;
};
```

值得注意的是，在函数式编程语言中，范围通常是惰性求值的，这大大减少了它们的内存占用。不过，对于我们的示例目标来说，这也很好用。

先前的`generator`函数允许我们为我们的测试创建输入数据，这些数据在 1 和最大整数值之间均匀分布。它只需要一个简单的绑定：

```cpp
auto generate_ints_greater_than_1 = bind(generate_ints, 1, numeric_limits<int>::max());
```

让我们将其用于我们的属性测试。

# 将属性放到测试中

让我们再次看看我们想要检查的属性列表：

+   *0⁰ -> 未定义（在 C++的 pow 函数中默认为 1）*

+   *0^([1 .. maxInt]) -> 0*

+   *值：[1 .. maxInt]⁰ -> 1*

+   *值：[0 .. maxInt]¹ -> 值*

+   *x^y = x^(y-1) * x*

现在我们将依次实现每个属性。对于每个属性，我们将使用基于示例的测试或受`generate_ints_greater_than_1`函数启发的数据生成器。让我们从最简单的属性开始——*0⁰*应该是未定义的——或者实际上是其标准实现中的`1`。

# 属性：00 -> 未定义

第一个问题使用基于示例的测试非常容易实现。出于一致性考虑，我们将其提取到一个函数中：

```cpp
auto property_0_to_power_0_is_1 = [](){
    return power(0, 0) == 1;
};
```

在我们的测试中，我们还将编写属性的描述，以便获得信息丰富的输出：

```cpp
TEST_CASE("Properties"){
    cout << "Property: 0 to power 0 is 1" << endl;
    CHECK(property_0_to_power_0_is_1);
 }
```

当运行时，会产生以下输出，通过测试：

```cpp
g++ -std=c++17 propertyBasedTests.cpp -o out/propertyBasedTests
./out/propertyBasedTests
[doctest] doctest version is "2.0.1"
[doctest] run with "--help" for options
Property: 0 to power 0 is 1
===============================================================================
[doctest] test cases:      1 |      1 passed |      0 failed |      0 skipped
[doctest] assertions:      1 |      1 passed |      0 failed |
[doctest] Status: SUCCESS!
```

这很容易！我们现在有了一个基本的属性测试结构。下一个测试将需要一个数据生成器，但我们已经有了。让我们看看它如何适用于`0`属性到任何幂，除了`0`等于`0`。

# 属性：0[1 .. maxInt] -> 0

我们需要我们的数字生成器从`1`到`maxInt`，这已经实现了。然后我们需要一个属性函数，检查对于从`1`到`maxInt`的任何指数，`0`的指数等于`0`。代码编写起来相当容易：

```cpp
auto prop_0_to_any_nonzero_int_is_0= [](const int exponent){
    CHECK(exponent > 0); // checking the contract just to be sure
    return power(0, exponent) == 0;
};
```

接下来，我们需要检查这个属性。由于我们有一个生成的值列表，我们可以使用`all_of`函数来检查所有这些值是否符合属性。为了使事情更加信息丰富，我决定显示我们正在使用的值列表：

```cpp
auto printGeneratedValues = [](const string& generatorName, const auto& 
    values){
        cout << "Check generator " << generatorName << endl;
        for_each(values.begin(), values.end(), [](auto value) { cout << 
            value << ", ";});
        cout << endl;
 };

auto check_property = [](const auto& generator, const auto& property, const string& generatorName){
    auto values = generator();
    printGeneratedValues(generatorName, values);
    CHECK(all_of_collection(values, property));
};
```

最后，我们可以编写我们的测试。我们将再次在测试之前显示属性名称：

```cpp
TEST_CASE("Properties"){
    cout << "Property: 0 to power 0 is 1" << endl;
    CHECK(property_0_to_power_0_is_1);

    cout << "Property: 0 to [1..maxInt] is 0" << endl;
    check_property(generate_ints_greater_than_1,  
        prop_0_to_any_nonzero_int_is_0, "generate ints");
}
```

运行测试会产生以下输出：

```cpp
Property: 0 to power 0 is 1
Property: 0 to [1..maxInt] is 0
Check generator generate ints
1073496375, 263661517, 1090774655, 590994005, 168796979, 1988143371, 1411998804, 1276384966, 252406124, 111200955, 775255151, 1669887756, 1426286501, 1264685577, 1409478643, 944131269, 1688339800, 192256171, 1406363728, 1624573054, 2654328, 1025851283, 1113062216, 1099035394, 624703362, 1523770105, 1243308926, 104279226, 1330992269, 1964576789, 789398651, 453897783, 1041935696, 561917028, 1379973023, 643316376, 1983422999, 1559294692, 2097139875, 384327588, 867142643, 1394240860, 2137873266, 2103542389, 1385608621, 2058924659, 1092474161, 1071910908, 1041001035, 582615293, 1911217125, 1383545491, 410712068, 1161330888, 1939114509, 1395243657, 427165959, 28574042, 1391025789, 224683120, 1222884936, 523039771, 1539230457, 2114587312, 2069325876, 166181790, 1504124934, 1817094271, 328329837, 442231460, 2123558414, 411757963, 1883062671, 1529993763, 1645210705, 866071861, 305821973, 1015936684, 2081548159, 1216448456, 2032167679, 351064479, 1818390045, 858994762, 2073835547, 755252854, 2010595753, 1882881401, 741339006, 1080861523, 1845108795, 362033992, 680848942, 728181713, 1252227588, 125901168, 1212171311, 2110298117, 946911655, 1, 2147483647, 
===============================================================================
[doctest] test cases:      1 |      1 passed |      0 failed |      0 skipped
[doctest] assertions:    103 |    103 passed |      0 failed |
[doctest] Status: SUCCESS!
```

正如您所看到的，一堆随机值被用于测试，最后两个值是`1`和`maxInt`。

现在是时候停下来思考一分钟了。这些测试是不寻常的。单元测试的一个关键思想是进行可重复的测试，但在这里，我们有一堆随机值。这些算不算？当一个值导致失败时我们该怎么办？

这些都是很好的问题！首先，使用基于属性的测试并不排除基于示例的测试。实际上，我们现在正在混合使用这两种——*0⁰*是一个示例，而不是一个属性。因此，在有意义时，不要犹豫检查任何特定值。

其次，支持属性测试的库允许收集特定失败值并自动重新测试这些值。很简单——每当有失败时，将值保存在某个地方，并在下次运行测试时包含它们。这不仅可以让您进行更彻底的测试，还可以发现代码的行为。

因此，我们必须将基于示例的测试和基于属性的测试视为互补的技术。第一个帮助您使用**测试驱动开发**（**TDD**）来驱动代码，并检查有趣的案例。第二个允许您找到您尚未考虑的案例，并重新测试相同的错误。两者都有用，只是方式不同。

让我们回到编写我们的属性。接下来的一个属性是任何数的零次幂等于`1`。

# 属性：value: [1 .. maxInt]0 -> 1

我们已经准备就绪，我们只需要写下来：

```cpp
auto prop_anyIntToPower0Is1 = [](const int base){
    CHECK(base > 0);
    return power(base, 0) == 1;
};
```

测试变成了以下内容：

```cpp
TEST_CASE("Properties"){
    cout << "Property: 0 to power 0 is 1" << endl;
    CHECK(property_0_to_power_0_is_1);

    cout << "Property: 0 to [1..maxInt] is 0" << endl;
    check_property(generate_ints_greater_than_1, 
        prop_0_to_any_nonzero_int_is_0, "generate ints");

    cout << "Property: any int to power 0 is 1" << endl;
    check_property(generate_ints_greater_than_1, 
        prop_anyIntToPower0Is1, "generate ints");
}
```

运行测试会得到以下输出（为简洁起见，省略了几行）：

```cpp
Property: 0 to power 0 is 1
Check generator generate ints
1673741664, 1132665648, 342304077, 936735303, 917238554, 1081591838, 743969276, 1981329112, 127389617, 
...
 1, 2147483647, 
Property: any int to power 0 is 1
Check generator generate ints
736268029, 1304281720, 416541658, 2060514167, 1695305196, 1479818034, 699224013, 1309218505, 302388654, 765083344, 430385474, 648548788, 1986457895, 794974983, 1797109305, 1131764785, 1221836230, 802640954,
...
1543181200, 1, 2147483647, 
===============================================================================
[doctest] test cases:      1 |      1 passed |      0 failed |      0 skipped
[doctest] assertions:    205 |    205 passed |      0 failed |
[doctest] Status: SUCCESS!
```

从前面的示例中可以看出，这些数字确实是随机的，同时始终包括`1`和`maxInt`。

我们已经掌握了这个！下一个属性是任何值的 1 次幂就是这个值。

# 属性：value: [0 .. maxInt]1 -> value

我们需要另一个生成方法，从`0`开始。我们只需要再次使用 bind 魔术来获得所需的结果：

```cpp
auto generate_ints_greater_than_0 = bind(generate_ints, 0, numeric_limits<int>::max());
```

这个属性写起来很容易：

```cpp
auto prop_any_int_to_power_1_is_the_value = [](const int base){
    return power(base, 1) == base;
};
```

测试很明显：

```cpp
TEST_CASE("Properties"){
    cout << "Property: 0 to power 0 is 1" << endl;
    CHECK(property_0_to_power_0_is_1);

    cout << "Property: 0 to any non-zero power is 0" << endl;
    check_property(generate_ints_greater_than_1, 
        prop_0_to_any_nonzero_int_is_0, "generate ints");

    cout << "Property: any int to power 0 is 1" << endl;
    check_property(generate_ints_greater_than_1, 
        prop_anyIntToPower0Is1, "generate ints");

    cout << "Property: any int to power 1 is the value" << endl;
    check_property(generate_ints_greater_than_0, 
        prop_any_int_to_power_1_is_the_value, "generate ints");
}
```

再次运行测试，结果再次通过。

让我们再次反思一下：

+   我们要检查多少个值？答案是`301`。

+   测试代码有多少行？测试代码只有 23 行代码，而我们用于测试的*库*函数大约有 40 行代码。

这不是很神奇吗？这不是对你的测试值得投资吗？

我们知道如何做到这一点。是时候来看我们的练习中最复杂的属性了——任何数的 y 次幂等于 y-1 次幂乘以这个数。

# 属性：xy = xy-1 * x

这将要求我们生成两组值，*x*和*y*，以便*x^y < maxInt*。我花了一些时间与数据生成器一起摸索，但我发现任何大于![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/26c14df0-ec8d-4ebe-96a3-b44950f3df7c.png)的*x*只能测试*y=1*。因此，我将使用两个生成器；第一个将生成`2`和![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/11ab32f9-a191-4287-803b-b8c1f5457f18.png)之间的数字，而第二个将生成大于![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/5406f9ba-b514-4cb4-9a41-d1d3813e3745.png)且小于`maxInt`的数字：

```cpp
auto generate_ints_greater_than_2_less_sqrt_maxInt = bind(generate_ints, 2, sqrt(numeric_limits<int>::max()));
```

属性的第一部分变成了以下内容：

```cpp
cout << "Property: next power of x is previous power of x multiplied by  
    x" << endl;
check_property(generate_ints_greater_than_2_less_sqrt_maxInt, 
    prop_nextPowerOfXIsPreviousPowerOfXMultipliedByX, "generate greater 
        than 2 and less than sqrt of maxInt");
```

为了实现属性，我们还需要生成`x`基数的指数，这样我们就可以将属性写成如下形式：

```cpp
auto prop_nextPowerOfXIsPreviousPowerOfXMultipliedByX = [](const int x){
    auto exponents = bind(generate_exponent_less_than_log_maxInt, x);
    return check_property(exponents, x{ return power(x, y) ==  
      power(x, y - 1) * x;}, "generate exponents for " + to_string(x));
};
```

从生成函数的名称中可以看出，我们需要生成在`1`和*log[x]maxInt*之间的数字。超过这个值的任何数字在计算 x^y 时都会溢出。由于 STL 中没有通用对数函数，我们需要实现一个。为了计算*log[x]maxInt*，我们只需要使用一个数学等式：

```cpp
auto logMaxIntBaseX = [](const int x) -> int{
    auto maxInt = numeric_limits<int>::max() ;
    return floor(log(maxInt) / log(x));
};
```

我们的生成函数变成了以下内容：

```cpp
auto generate_exponent_less_than_log_maxInt = [](const int x){
    return generate_ints(1, logMaxIntBaseX(x));
};
```

有了这个，我们可以运行我们的测试。以下是输出的简要部分：

```cpp
Check generator generate exponents for 43740
1, 2, 
Check generator generate exponents for 9320
1, 2, 
Check generator generate exponents for 2
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 
Check generator generate exponents for 46340
1, 2,
```

测试的最后一部分是添加从![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/11ab32f9-a191-4287-803b-b8c1f5457f18.png) + 1 到`maxInt`的区间：

```cpp
check_property(generate_ints_greater_than_sqrt_maxInt,  
    prop_nextPowerOfXIsPreviousPowerOfXMultipliedByX, "generate greater    
    than sqrt of maxInt");
```

这也导致了生成函数的更新，以支持一些边缘情况；请参考以下代码中的注释以获取解释：

```cpp
auto generate_ints = [](const int min, const int max){
    if(min > max) { // when lower range is larger than upper range, 
        just return empty vector
            return vector<int>();
    }
    if(min == max){ // if min and max are equal, just return {min}
        return range(min, min);
    }

    if(max - min <= 100){ // if there not enough int values in the 
        range, just return it fully
            return range(min, max);
    }
    ...
}
```

我们已经实现了我们的最终属性！

# 结论

现在我们只需用几行代码来检查所有以下内容：

+   *0⁰ -> undefined (1 by default in pow function in C++)*

+   *0^([1 .. maxInt]) -> 0*

+   *value: [1 .. maxInt]⁰ -> 1*

+   *value: [0 .. maxInt]¹ -> value*

+   *x^y = x^(y-1) * x*

这与更常用的基于示例的测试方法相比如何？我们用更少的代码进行更多的测试。我们可以发现代码中隐藏的问题。但是属性比示例更难识别。我们还确定了基于属性的测试与基于示例的测试非常有效地配合使用。

因此，让我们现在解决找到属性的问题。这需要一些分析，我们将探讨一种实际的方式，通过数据驱动测试从示例中演变出属性。

# 从示例到数据驱动测试到属性

当我第一次听说基于属性的测试时，我有两个问题。首先，我以为它们是用来替代示例测试的——现在我们知道它们并不是；只需将这两种技术并行使用。其次，我不知道如何提出好的属性。

然而，我对如何提出好的示例和如何消除测试之间的重复有了一个好主意。我们已经看到了如何为幂函数提出好的示例；让我们回顾一下：

+   *0⁰ -> 未定义（C++中的 pow 实现返回 1，除非启用了特定错误）*

+   0^(0 到最大的任何整数) -> 0

+   *1^(任何整数) -> 1*

+   （除 0 外的任何整数）⁰ -> 1

+   *2² -> 4*

+   *2^(不会溢出的最大整数) -> 要计算的值*

+   *10⁵ -> 100000*

+   *10^(不会溢出的最大整数) -> 要计算的值*

我们还看到了为这些情况编写基于示例的测试非常容易：

```cpp
TEST_CASE("Power"){
    int maxInt = numeric_limits<int>::max();
    CHECK_EQ(1, power(0, 0));
    CHECK_EQ(0, power(0, 1));
    CHECK_EQ(0, power(0, maxInt));
    CHECK_EQ(1, power(1, 1));
    CHECK_EQ(1, power(1, 2));
    CHECK_EQ(1, power(1, maxInt));
    CHECK_EQ(1, power(2, 0));
    CHECK_EQ(2, power(2, 1));
    CHECK_EQ(4, power(2, 2));
    CHECK_EQ(maxInt, power(2, 31) - 1);
    CHECK_EQ(1, power(3, 0));
    CHECK_EQ(3, power(3, 1));
    CHECK_EQ(9, power(3, 2));
    CHECK_EQ(1, power(maxInt, 0));
    CHECK_EQ(maxInt, power(maxInt, 1));
}
```

这些示例展示了代码的相似之处。`0`、`1`、`2`和`3`的基数重复了多次。我们在第九章中已经看到，*函数式编程的测试驱动开发*，我们可以通过指定多个输入值来使用数据驱动测试来消除这种相似性：

```cpp
TEST_CASE("1 raised to a power is 1"){
    int exponent;

    SUBCASE("0"){
        exponent = 0;
    }
    SUBCASE("1"){
        exponent = 1;
    }
    SUBCASE("2"){
        exponent = 1;
    }
    SUBCASE("maxInt"){
        exponent = maxInt;
    }

    CAPTURE(exponent);
    CHECK_EQ(1, power(1, exponent));
}
```

在我努力一段时间后消除这些相似性之后，我开始看到这些属性。在这种情况下，很明显，我们可以添加一个检查相同数学属性的测试，而不是使用特定示例。事实上，我们在上一节中写了它，它看起来像这样：

```cpp
cout << "Property: any int to power 1 is the value" << endl;
check_property(generate_ints_greater_than_0, 
    prop_any_int_to_power_1_is_the_value, "generate ints");
```

所以我的建议是——如果你花几分钟思考问题并找到要检查的数学属性，那太好了！（编写基于属性的测试，并添加尽可能多的基于示例的测试，以确保你已经涵盖了各种情况。）如果你看不到它们，别担心；继续添加基于示例的测试，通过使用数据驱动测试消除测试之间的重复，并最终你会发现这些属性。然后，添加基于属性的测试，并决定如何处理现有的基于示例的测试。

# 好的属性，坏的属性

由于属性比示例更抽象，因此很容易以混乱或不清晰的方式实现它们。你已经需要对基于示例的测试付出很多注意力；现在你需要加倍努力来处理基于属性的测试。

首先，好的属性就像好的单元测试。因此，我们希望有以下属性：

+   小

+   适当命名和清晰

+   在失败时提供非常清晰的消息

+   快速

+   可重复

不过，基于属性的测试有一个警告——由于我们使用随机值，我们是否应该期望随机失败？当基于属性的测试失败时，我们会对我们的代码有所了解，因此这是值得庆祝的。然而，我们应该期望随着时间的推移和错误的消除，失败次数会减少。如果你的基于属性的测试每天都失败，那肯定有问题——也许属性太大，或者实现中存在许多漏洞。如果你的基于属性的测试偶尔失败，并且显示代码中可能存在的错误——那太好了。

基于属性的测试的一个困难之处在于保持生成器和属性检查没有错误。这也是代码，任何代码都可能有错误。在基于示例的测试中，我们通过简化单元测试的方式来解决这个问题，使错误几乎不可能发生。请注意，属性更加复杂，因此可能需要更多的注意。旧的原则“保持简单，愚蠢”在基于属性的测试中更加有价值。因此，更偏爱小属性而不是大属性，进行分析，并与同事一起审查代码，包括名称和实现。

# 关于实现的一些建议

在本章中，我们使用了一组自定义函数来实现数据生成器，以保持代码标准为 C++ 17。然而，这些函数是为了学习技术而优化的，并不适用于生产环境。您可能已经注意到，它们并不针对内存占用或性能进行优化。我们可以通过巧妙地使用迭代器来改进它们，但还有更好的方法。

如果您可以使用范围库或使用 C++ 20 编译您的测试，那么实现无限数据生成器就会变得非常容易（由于惰性评估）。我还建议您搜索基于属性的测试库或生成器库，因为一些生成器已经被其他人编写，一旦您理解了概念，就可以更快地在您的代码中使用它们。

# 总结

基于属性的测试是我们多年来所知道和使用的基于示例的测试的一个受欢迎的补充。它向我们展示了如何将数据生成与一些分析相结合，以消除测试中的重复项并找到我们未考虑的情况。

基于属性的测试是通过非常容易使用纯函数实现的数据生成器来实现的。随着 C++ 20 中的惰性评估或范围库的到来，事情将变得更加容易。

但基于属性的测试的核心技术是识别属性。我们已经看到了两种方法来做到这一点——第一种是通过分析示例，第二种是通过编写基于示例的测试，消除重复项，将其转换为数据驱动测试，然后用属性替换数据行。

最后，请记住，基于属性的测试是代码，它们需要非常干净，易于更改和理解。尽可能偏爱小属性，并通过清晰命名使它们易于理解。

在下一章中，我们将看看如何使用纯函数来支持我们的重构工作，以及如何将设计模式实现为函数。


# 第十二章：重构到纯函数并通过纯函数

程序员经常遇到他们害怕改变的代码。通过提取纯函数，使用柯里化和组合，并利用编译器，你可以以更安全的方式重构现有代码。我们将看一个通过纯函数重构的例子，然后我们将看一些设计模式，以及它们在函数式编程中的实现，以及如何在重构中使用它们。

本章将涵盖以下主题：

+   如何思考遗留代码

+   如何使用编译器和纯函数来识别和分离依赖关系

+   如何从任何代码中提取 lambda

+   如何使用柯里化和组合消除 lambda 之间的重复，并将它们分组到类中

+   如何使用函数实现一些设计模式（策略、命令和依赖注入）

+   如何使用基于函数的设计模式来重构

# 技术要求

你将需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.4.0c。

代码在 GitHub 上的`Chapter12`文件夹中。它包括并使用`doctest`，这是一个单头文件的开源单元测试库。你可以在它的 GitHub 仓库上找到它[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# 重构到纯函数并通过纯函数

**重构**是软件开发的一个重要而持续的部分。主要原因是需求的持续变化，由我们构建的应用程序周围世界的变化所驱动。我们的客户不断了解产品所在的生态系统，并需要我们将这些产品适应他们发现的新现实。因此，我们的代码，即使结构完美，几乎总是落后于我们当前对所解决问题的理解。

完美地构建我们的代码也不容易。程序员是人，所以我们会犯错，失去焦点，有时找不到最佳解决方案。处理这种复杂情况的唯一方法是使用无情的重构；也就是说，在让事情运转后，我们改进代码结构，直到在我们拥有的约束下代码达到最佳状态。

只要我们很早就重构并编写测试，那就很容易说和做。但是如果我们继承了一个没有测试的代码库呢？那我们该怎么办？我们将讨论这个问题，以及后面将使用纯函数来重构遗留代码的一个有前途的想法。

首先，让我们定义我们的术语。什么是重构？

# 什么是重构？

重构是行业中普遍使用的术语之一，但并不被很好理解。不幸的是，这个术语经常被用来证明大的重设计。考虑以下关于给定项目的常见故事：

+   项目开始时，功能以快速的速度添加。

+   很快（几个月、一年，甚至几周），速度下降了，但需求是一样的。

+   多年后，添加新功能变得如此困难，以至于客户感到恼火并向团队施加压力。

+   最终，决定重写或改变代码的整体结构，希望能加快速度。

+   六个月后，重写或重设计（通常）失败，管理层面临着一个不可能的情况——我们应该尝试重设计、重新启动项目，还是做其他事情？

这个循环的**大重设计**阶段通常错误地被称为重构，但这并不是重构的含义。

相反，要理解重构的真正含义，让我们从思考对代码库可以做出的改变开始。我们通常可以将这些改变分类如下：

+   实施新要求

+   修复一个错误

+   以各种方式重新组织代码——重构、重工程、重设计和/或重架构

我们可以将这些更改大致分类为两大类，如下：

+   影响代码行为的更改

+   不影响代码行为的更改

当我们谈论行为时，我们谈论输入和输出，比如“当我在**用户界面**（UI）表单中输入这些值并单击此按钮时，然后我看到这个输出并保存这些东西”。我们通常不包括性能、可伸缩性或安全性等跨功能关注点在行为中。

有了这些明确的术语，我们可以定义重构——简单地对不影响程序外部行为的代码结构进行更改。大型重设计或重写很少符合这个定义，因为通常进行大型重设计的团队并不证明结果与原始代码具有相同的行为（包括已知的错误，因为有人可能依赖它们）。

对程序进行任何修改其行为的更改都不是重构。这包括修复错误或添加功能。然而，我们可以将这些更改分为两个阶段——首先重构以*为更改腾出空间*，然后进行行为更改。

这个定义引发了一些问题，如下：

+   我们如何证明我们没有改变行为？我们知道的唯一方法是：自动回归测试。如果我们有一套我们信任且足够快速的自动化测试，我们可以轻松地进行更改而不改变任何测试，并查看它们是否通过。

+   重构有多小？更改越大，证明没有受到影响就越困难，因为程序员是人类，会犯错误。我们更喜欢在重构中采取非常小的步骤。以下是一些保持行为的小代码更改的示例：重命名、向函数添加参数、更改函数的参数顺序以及将一组语句提取到函数中等。每个小更改都可以轻松进行，并运行测试以证明没有发生行为更改。每当我们需要进行更大的重构时，我们只需进行一系列这些小更改。

+   当我们没有测试时，我们如何证明我们没有改变代码的行为？这就是我们需要谈论遗留代码和遗留代码困境的时候。

# 遗留代码困境

编程可能是唯一一个“遗留”一词具有负面含义的领域。在任何其他情况下，“遗留”都意味着某人留下的东西，通常是某人引以为傲的东西。在编程中，遗留代码指的是我们继承的独占代码，维护起来很痛苦。

程序员经常认为遗留代码是不可避免的，对此无能为力。然而，我们可以做很多事情。首先是澄清我们所说的遗留代码是什么意思。迈克尔·菲瑟斯在他的遗留代码书中将其定义为没有测试的代码。然而，我更倾向于使用更一般的定义：*你害怕改变的代码*。你害怕改变的代码会减慢你的速度，减少你的选择，并使任何新的开发成为一场磨难。但这绝不是不可避免的：我们可以改变它，我们将看到如何做到这一点。

我们可以做的第二件事是了解遗留代码的困境。为了不那么害怕改变，我们需要对其进行重构，但为了重构代码，我们需要编写测试。要编写测试，我们需要调整代码使其可测试；这看起来像一个循环——为了改变代码，我们需要改变代码！如果我们一开始就害怕改变代码，我们该怎么办？

幸运的是，这个困境有一个解决办法。如果我们能够对代码进行安全的更改——这些更改几乎没有错误的机会，并且允许我们测试代码——那么我们就可以慢慢但肯定地改进代码。这些更改确实是重构，但它们甚至比重构步骤更小、更安全。它们的主要目标是打破代码中设计元素之间的依赖关系，使我们能够编写测试，以便在之后继续重构。

由于我们的重点是使用纯函数和函数构造来重构代码，我们不会查看完整的技术列表。我可以给出一个简单的例子，称为**提取和覆盖**。假设您需要为一个非常大的函数编写测试。如果我们只能为函数的一小部分编写测试，那将是理想的。我们可以通过将要测试的代码提取到另一个函数中来实现这一点。然而，新函数依赖于旧代码，因此我们将很难弄清所有的依赖关系。为了解决这个问题，我们可以创建一个派生类，用虚拟函数覆盖我们函数的所有依赖关系。在单元测试中，这称为*部分模拟*。这使我们能够用测试覆盖我们提取函数的所有代码，同时假设类的所有其他部分都按预期工作。一旦我们用测试覆盖了它，我们就可以开始重构；在这个练习结束时，我们经常会提取一个完全由模拟或存根的新类。

这些技术是在我们的语言中广泛支持函数式编程之前编写的。现在我们可以利用纯函数来安全地重构我们编写的代码。但是，为了做到这一点，我们需要了解依赖关系如何影响我们测试和更改代码的能力。

# 依赖和变更

我们的用户和客户希望项目成功的时间越长，就能获得越多的功能。然而，我们经常无法交付，因为随着时间的推移，代码往往变得越来越僵化。随着时间的推移，添加新功能变得越来越慢，而且在添加功能时会出现新的错误。

这引出了一个十分重要的问题——是什么使代码难以更改？我们如何编写能够保持变更速度甚至增加变更速度的代码？

这是一个复杂的问题，有许多方面和各种解决方案。其中一个在行业中基本上是一致的——依赖关系往往会减慢开发速度。具有较少依赖关系的代码结构通常更容易更改，从而更容易添加功能。

我们可以从许多层面来看依赖关系。在更高的层面上，我们可以谈论依赖于其他可执行文件的可执行文件；例如，直接调用另一个网络服务的网络服务。通过使用基于事件的系统而不是直接调用，可以减少这个层面上的依赖关系。在更低的层面上，我们可以谈论对库或操作系统例程的依赖；例如，一个网络服务依赖于特定文件夹或特定库版本的存在。

虽然其他所有层面都很有趣，但对于我们的目标，我们将专注于类/函数级别，特别是类和函数如何相互依赖。由于在任何非平凡的代码库中都不可能避免依赖关系，因此我们将专注于依赖关系的强度。

我们将以我编写的一小段代码作为示例，该代码根据员工列表和角色、资历、组织连续性和奖金水平等参数计算工资。它从 CSV 文件中读取员工列表，根据一些规则计算工资，并打印计算出的工资列表。代码的第一个版本是天真地编写的，只使用`main`函数，并将所有内容放在同一个文件中，如下面的代码示例所示。

```cpp
#include <iostream>
#include <fstream>
#include <string>
#include <cmath>

using namespace std;

int main(){
    string id;
    string employee_id;
    string first_name;
    string last_name;
    string seniority_level;
    string position;
    string years_worked_continuously;
    string special_bonus_level;

    ifstream employeesFile("./Employees.csv");
    while (getline(employeesFile, id, ',')) {
        getline(employeesFile, employee_id, ',') ;
        getline(employeesFile, first_name, ',') ;
        getline(employeesFile, last_name, ',') ;
        getline(employeesFile, seniority_level, ',') ;
        getline(employeesFile, position, ',') ;
        getline(employeesFile, years_worked_continuously, ',') ;
        getline(employeesFile, special_bonus_level);
        if(id == "id") continue;

        int baseSalary;
        if(position == "Tester") baseSalary= 1500;
        if(position == "Analyst") baseSalary = 1600;
        if(position == "Developer") baseSalary = 2000;
        if(position == "Team Leader") baseSalary = 3000;
        if(position == "Manager") baseSalary = 4000;

        double factor;
        if(seniority_level == "Entry") factor = 1;
        if(seniority_level == "Junior") factor = 1.2;
        if(seniority_level == "Senior") factor = 1.5;

        double continuityFactor;
        int continuity = stoi(years_worked_continuously);
        if(continuity < 3) continuityFactor = 1;
        if(continuity >= 3 && continuity < 5) continuityFactor = 1.2;
        if(continuity >= 5 && continuity < 10) continuityFactor = 1.5;
        if(continuity >=10 && continuity <= 20) continuityFactor = 1.7;
        if(continuity > 20) continuityFactor = 2;

        int specialBonusLevel = stoi(special_bonus_level);
        double specialBonusFactor = specialBonusLevel * 0.03;

        double currentSalary = baseSalary * factor * continuityFactor;
        double salary = currentSalary + specialBonusFactor * 
            currentSalary;

        int roundedSalary = ceil(salary);

        cout  << seniority_level << position << " " << first_name << " 
            " << last_name << " (" << years_worked_continuously << 
            "yrs)" <<  ", " << employee_id << ", has salary (bonus                 
            level  " << special_bonus_level << ") " << roundedSalary << 
            endl;
    }
}
```

输入文件是使用专门的工具生成的随机值，看起来像这样：

```cpp
id,employee_id,First_name,Last_name,Seniority_level,Position,Years_worked_continuously,Special_bonus_level
1,51ef10eb-8c3b-4129-b844-542afaba7eeb,Carmine,De Vuyst,Junior,Manager,4,3
2,171338c8-2377-4c70-bb66-9ad669319831,Gasper,Feast,Entry,Team Leader,10,5
3,807e1bc7-00db-494b-8f92-44acf141908b,Lin,Sunley,Medium,Manager,23,3
4,c9f18741-cd6c-4dee-a243-00c1f55fde3e,Leeland,Geraghty,Medium,Team Leader,7,4
5,5722a380-f869-400d-9a6a-918beb4acbe0,Wash,Van der Kruys,Junior,Developer,7,1
6,f26e94c5-1ced-467b-ac83-a94544735e27,Marjie,True,Senior,Tester,28,1

```

当我们运行程序时，为每个员工计算了`salary`，输出如下所示：

```cpp
JuniorManager Carmine De Vuyst (4yrs), 51ef10eb-8c3b-4129-b844-542afaba7eeb, has salary (bonus level  3) 6279
EntryTeam Leader Gasper Feast (10yrs), 171338c8-2377-4c70-bb66-9ad669319831, has salary (bonus level  5) 5865
MediumManager Lin Sunley (23yrs), 807e1bc7-00db-494b-8f92-44acf141908b, has salary (bonus level  3) 8720
MediumTeam Leader Leeland Geraghty (7yrs), c9f18741-cd6c-4dee-a243-00c1f55fde3e, has salary (bonus level  4) 5040
JuniorDeveloper Wash Van der Kruys (7yrs), 5722a380-f869-400d-9a6a-918beb4acbe0, has salary (bonus level  1) 3708
SeniorTester Marjie True (28yrs), f26e94c5-1ced-467b-ac83-a94544735e27, has salary (bonus level  1) 4635
EntryAnalyst Muriel Dorken (10yrs), f4934e00-9c01-45f9-bddc-2366e6ea070e, has salary (bonus level  8) 3373
SeniorTester Harrison Mawditt (17yrs), 66da352a-100c-4209-a13e-00ec12aa167e, has salary (bonus level  10) 4973
```

那么，这段代码有依赖关系吗？有，并且它们就在眼前。

查找依赖关系的一种方法是查找构造函数调用或全局变量。在我们的例子中，我们有一个对`ifstream`的构造函数调用，以及一个对`cout`的使用，如下例所示：

```cpp
ifstream employeesFile("./Employees.csv")
cout  << seniority_level << position << " " << first_name << " " << 
    last_name << " (" << years_worked_continuously << "yrs)" <<  ", " 
    << employee_id << ", has salary (bonus level  " << 
    special_bonus_level << ") " << roundedSalary << endl;
```

识别依赖的另一种方法是进行一种想象练习。想象一下什么要求可能会导致代码的变化。有几种情况。如果我们决定切换到员工数据库，我们将需要改变读取数据的方式。如果我们想要输出到文件，我们将需要改变打印工资的代码行。如果计算工资的规则发生变化，我们将需要更改计算`salary`的代码行。

这两种方法都得出了相同的结论；我们对文件系统和标准输出有依赖。让我们专注于标准输出，并提出一个问题；我们如何改变代码，以便将工资输出到标准输出和文件中？答案非常简单，由于**标准模板库**（**STL**）流的多态性，只需提取一个接收输出流并写入数据的函数。让我们看看这样一个函数会是什么样子；为了简单起见，我们还引入了一个名为`Employee`的结构，其中包含我们需要的所有字段，如下例所示：

```cpp
void printEmployee(const Employee& employee, ostream& stream, int 
    roundedSalary){
        stream << employee.seniority_level << employee.position << 
        " " << employee.first_name << " " << employee.last_name << 
        " (" << employee.years_worked_continuously << "yrs)" <<  ",             
        " << employee.employee_id << ", has salary (bonus level  " << 
        employee.special_bonus_level << ") " << roundedSalary << endl;
    }
```

这个函数不再依赖于标准输出。在依赖方面，我们可以说*我们打破了依赖关系*，即员工打印和标准输出之间的依赖关系。我们是如何做到的呢？嗯，我们将`cout`流作为函数的参数从调用者传递进来：

```cpp
        printEmployee(employee, cout, roundedSalary);
```

这个看似微小的改变使函数成为多态的。`printEmployee`的调用者现在控制函数的输出，而不需要改变函数内部的任何东西。

此外，我们现在可以为`printEmployee`函数编写测试，而不必触及文件系统。这很重要，因为文件系统访问速度慢，而且由于诸如磁盘空间不足或损坏部分等原因，在测试正常路径时可能会出现错误。我们如何编写这样的测试呢？嗯，我们只需要使用内存流调用该函数，然后将写入内存流的输出与我们期望的输出进行比较。

因此，打破这种依赖关系会极大地改善我们代码的可更改性和可测试性。这种机制非常有用且广泛，因此它得到了一个名字——**依赖注入**（**DI**）。在我们的情况下，`printEmployee`函数的调用者（`main`函数、`test`函数或另一个未来的调用者）将依赖注入到我们的函数中，从而控制其行为。

关于 DI 有一点很重要——它是一种设计模式，而不是一个库。许多现代库和 MVC 框架都支持 DI，但您不需要任何外部内容来注入依赖关系。您只需要将依赖项传递给构造函数、属性或函数参数，然后就可以了。

我们学会了如何识别依赖关系以及如何使用 DI 来打破它们。现在是时候看看我们如何利用纯函数来重构这段代码了。

# 纯函数和程序的结构

几年前，我学到了关于计算机程序的一个基本定律，这导致我研究如何在重构中使用纯函数：

*任何计算机程序都可以由两种类型的类/函数构建——一些进行 I/O，一些是纯函数。*

在之后寻找类似想法时，我发现 Gary Bernhardt 对这些结构的简洁命名：*functional core, imperative shell*（[`www.destroyallsoftware.com/screencasts/catalog/functional-core-imperative-shell`](https://www.destroyallsoftware.com/screencasts/catalog/functional-core-imperative-shell)）。

无论你如何称呼它，这个想法对重构的影响都是根本的。如果任何程序都可以被写成两种不同类型的类/函数，一些是不可变的，一些是 I/O，那么我们可以利用这个属性来重构遗留代码。高层次的过程看起来会像这样：

+   提取纯函数（我们将看到这些步骤识别依赖关系）。

+   测试和重构它们。

+   根据高内聚原则将它们重新分组为类。

我想在这个定律中添加一个公理。我相信我们可以在代码的任何级别应用这个定律，无论是函数、类、代码行组、类组还是整个模块，除了那些纯 I/O 的代码行。换句话说，这个定律是分形的；它适用于代码的任何级别，除了最基本的代码行。

这个公理的重要性是巨大的。它告诉我们的是，我们可以在代码的任何级别应用之前描述的相同方法，除了最基本的。换句话说，我们从哪里开始应用这个方法并不重要，因为它在任何地方都会起作用。

在接下来的几节中，我们将探讨该方法的每个步骤。首先，让我们提取一些纯函数。

# 使用编译器和纯函数来识别依赖关系。

尝试更改我们不理解且没有测试的代码可能会感到冒险。任何错误都可能导致丑陋的错误，任何更改都可能导致错误。

幸运的是，编译器和纯函数可以帮助揭示依赖关系。记住纯函数是什么——对于相同的输入返回相同输出的函数。这意味着，根据定义，纯函数的所有依赖关系都是可见的，通过参数、全局变量或变量捕获传递。

这引导我们以一种简单的方式来识别代码中的依赖关系：选择几行代码，将它们提取到一个函数中，使其成为纯函数，然后让编译器告诉你依赖关系是什么。此外，这些依赖关系将需要被注入，从而使我们得到一个可测试的函数。

让我们看几个例子。一个简单的开始是下面几行代码，根据公司员工的职位计算基本工资：

```cpp
        int baseSalary;
        if(position == "Tester") baseSalary = 1500;
        if(position == "Analyst") baseSalary = 1600;
        if(position == "Developer") baseSalary = 2000;
        if(position == "Team Leader") baseSalary = 3000;
        if(position == "Manager") baseSalary = 4000;
```

让我们将其提取为一个纯函数。现在名称并不重要，所以我们暂时称之为`doesSomething`，然后我将代码行复制粘贴到新函数中，而不是从旧函数中删除它们，如下例所示：

```cpp
auto doesSomething = [](){
        int baseSalary;
        if(position == "Tester") baseSalary = 1500;
        if(position == "Analyst") baseSalary = 1600;
        if(position == "Developer") baseSalary = 2000;
        if(position == "Team Leader") baseSalary = 3000;
        if(position == "Manager") baseSalary = 4000;
};
```

我的编译器立即抱怨说位置未定义，所以它帮我找出了依赖关系。让我们将其添加为一个参数，如下面的示例所示：

```cpp
auto doesSomething = [](const string& position){
        int baseSalary;
        if(position == "Tester") baseSalary = 1500;
        if(position == "Analyst") baseSalary = 1600;
        if(position == "Developer") baseSalary = 2000;
        if(position == "Team Leader") baseSalary = 3000;
        if(position == "Manager") baseSalary = 4000;
};
```

这个函数缺少一些东西；纯函数总是返回值，但这个函数没有。让我们添加`return`语句，如下面的代码示例所示：

```cpp
auto doesSomething = [](const string& position){
        int baseSalary;
        if(position == "Tester") baseSalary = 1500;
        if(position == "Analyst") baseSalary = 1600;
        if(position == "Developer") baseSalary = 2000;
        if(position == "Team Leader") baseSalary = 3000;
        if(position == "Manager") baseSalary = 4000;
        return baseSalary;
};
```

现在这个函数足够简单，可以独立测试了。但首先，我们需要将其提取到一个单独的`.h`文件中，并给它一个合适的名称。`baseSalaryForPosition`听起来不错；让我们在下面的代码中看看它的测试：

```cpp
TEST_CASE("Base salary"){
    CHECK_EQ(1500, baseSalaryForPosition("Tester"));
    CHECK_EQ(1600, baseSalaryForPosition("Analyst"));
    CHECK_EQ(2000, baseSalaryForPosition("Developer"));
    CHECK_EQ(3000, baseSalaryForPosition("Team Leader"));
    CHECK_EQ(4000, baseSalaryForPosition("Manager"));
    CHECK_EQ(0, baseSalaryForPosition("asdfasdfs"));
}
```

编写这些测试相当简单。它们也重复了许多来自函数的东西，包括位置字符串和薪水值。有更好的方法来组织代码，但这是预期的遗留代码。现在，我们很高兴我们用测试覆盖了初始代码的一部分。我们还可以向领域专家展示这些测试，并检查它们是否正确，但让我们继续进行重构。我们需要从`main()`开始调用新函数，如下所示：

```cpp
    while (getline(employeesFile, id, ',')) {
        getline(employeesFile, employee_id, ',') ;
        getline(employeesFile, first_name, ',') ;
        getline(employeesFile, last_name, ',') ;
        getline(employeesFile, seniority_level, ',') ;
        getline(employeesFile, position, ',') ;
        getline(employeesFile, years_worked_continuously, ',') ;
        getline(employeesFile, special_bonus_level);
        if(id == "id") continue;

 int baseSalary = baseSalaryForPosition(position);
        double factor;
        if(seniority_level == "Entry") factor = 1;
        if(seniority_level == "Junior") factor = 1.2;
        if(seniority_level == "Senior") factor = 1.5;
        ...
}

```

虽然这是一个简单的案例，但它展示了基本的过程，如下所示：

+   选择几行代码。

+   将它们提取到一个函数中。

+   使函数成为纯函数。

+   注入所有依赖。

+   为新的纯函数编写测试。

+   验证行为。

+   重复，直到整个代码都被测试覆盖。

如果您遵循这个过程，引入错误的风险将变得极小。根据我的经验，您需要最小心的是使函数成为纯函数。记住——如果它在一个类中，将其设为带有`const`参数的静态函数，但如果它在类外部，将所有参数作为`const`传递，并将其设为 lambda。

如果我们重复这个过程几次，我们最终会得到更多的纯函数。首先，`factorForSeniority`根据资历级别计算因子，如下例所示：

```cpp
auto factorForSeniority = [](const string& seniority_level){
    double factor;
    if(seniority_level == "Entry") factor = 1;
    if(seniority_level == "Junior") factor = 1.2;
    if(seniority_level == "Senior") factor = 1.5;
    return factor;
};
```

然后，`factorForContinuity`根据——你猜对了——连续性计算因子：

```cpp
auto factorForContinuity = [](const string& years_worked_continuously){
    double continuityFactor;
    int continuity = stoi(years_worked_continuously);
    if(continuity < 3) continuityFactor = 1;
    if(continuity >= 3 && continuity < 5) continuityFactor = 1.2;
    if(continuity >= 5 && continuity < 10) continuityFactor = 1.5;
    if(continuity >=10 && continuity <= 20) continuityFactor = 1.7;
    if(continuity > 20) continuityFactor = 2;
    return continuityFactor;
};

```

最后，`bonusLevel`函数读取奖金级别：

```cpp
auto bonusLevel = [](const string& special_bonus_level){
    return stoi(special_bonus_level);
};
```

这些函数中的每一个都可以很容易地通过基于示例的、数据驱动的或基于属性的测试进行测试。提取了所有这些函数后，我们的主要方法看起来像以下示例（为简洁起见，省略了几行）：

```cpp
int main(){
...
    ifstream employeesFile("./Employees.csv");
    while (getline(employeesFile, id, ',')) {
        getline(employeesFile, employee_id, ',') ;
...
        getline(employeesFile, special_bonus_level);
        if(id == "id") continue;

 int baseSalary = baseSalaryForPosition(position);
 double factor = factorForSeniority(seniority_level);

 double continuityFactor = 
            factorForContinuity(years_worked_continuously);

 int specialBonusLevel =  bonusLevel(special_bonus_level);
        double specialBonusFactor = specialBonusLevel * 0.03;

        double currentSalary = baseSalary * factor * continuityFactor;
        double salary = currentSalary + specialBonusFactor * 
            currentSalary;

        int roundedSalary = ceil(salary);

        cout  << seniority_level << position << " " << first_name << "           
          " << last_name << " (" << years_worked_continuously << "yrs)"     
          <<  ", " << employee_id << ", has salary (bonus level  " << 
          special_bonus_level << ") " << roundedSalary << endl;
    }
```

这样会更清晰，而且测试覆盖更好。然而，lambda 还可以用于更多的操作；让我们看看我们如何做到这一点。

# 从遗留代码到 lambda

除了纯度，lambda 还为我们提供了许多可以使用的操作：函数组合、部分应用、柯里化和高级函数。在重构遗留代码时，我们可以利用这些操作。

展示这一点最简单的方法是从`main`方法中提取整个`salary`计算。以下是计算`salary`的代码行：

```cpp
...        
        int baseSalary = baseSalaryForPosition(position);
        double factor = factorForSeniority(seniority_level);

        double continuityFactor = 
            factorForContinuity(years_worked_continuously);

        int specialBonusLevel =  bonusLevel(special_bonus_level);
        double specialBonusFactor = specialBonusLevel * 0.03;

        double currentSalary = baseSalary * factor * continuityFactor;
        double salary = currentSalary + specialBonusFactor * 
            currentSalary;

        int roundedSalary = ceil(salary);
...
```

我们可以以两种方式提取这个纯函数——一种是将需要的每个值作为参数传递，结果如下所示：

```cpp
auto computeSalary = [](const string& position, const string seniority_level, const string& years_worked_continuously, const string& special_bonus_level){
    int baseSalary = baseSalaryForPosition(position);
    double factor = factorForSeniority(seniority_level);

    double continuityFactor = 
        factorForContinuity(years_worked_continuously);

    int specialBonusLevel =  bonusLevel(special_bonus_level);
    double specialBonusFactor = specialBonusLevel * 0.03;

    double currentSalary = baseSalary * factor * continuityFactor;
    double salary = currentSalary + specialBonusFactor * currentSalary;

    int roundedSalary = ceil(salary);
    return roundedSalary;
};
```

第二个选项更有趣。与其传递变量，不如我们传递函数并事先将它们绑定到所需的变量？

这是一个有趣的想法。结果是一个接收多个函数作为参数的函数，每个函数都没有任何参数：

```cpp
auto computeSalary = [](auto baseSalaryForPosition, auto factorForSeniority, auto factorForContinuity, auto bonusLevel){
    int baseSalary = baseSalaryForPosition();
    double factor = factorForSeniority();
    double continuityFactor = factorForContinuity();
    int specialBonusLevel =  bonusLevel();

    double specialBonusFactor = specialBonusLevel * 0.03;

    double currentSalary = baseSalary * factor * continuityFactor;
    double salary = currentSalary + specialBonusFactor * currentSalary;

    int roundedSalary = ceil(salary);
    return roundedSalary;
};
```

`main`方法需要首先绑定这些函数，然后将它们注入到我们的方法中，如下所示：

```cpp
        auto roundedSalary = computeSalary(
                bind(baseSalaryForPosition, position), 
                bind(factorForSeniority, seniority_level),
        bind(factorForContinuity, years_worked_continuously),
        bind(bonusLevel, special_bonus_level));

        cout  << seniority_level << position << " " << first_name << " 
          " << last_name << " (" << years_worked_continuously << "yrs)"           
          <<  ", " << employee_id << ", has salary (bonus level  " <<              
          special_bonus_level << ") " << roundedSalary << endl;
```

为什么这种方法很有趣？好吧，让我们从软件设计的角度来看看。我们创建了小的纯函数，每个函数都有明确的责任。然后，我们将它们绑定到特定的值。之后，我们将它们作为参数传递给另一个 lambda，该 lambda 使用它们来计算我们需要的结果。

在**面向对象编程**（**OOP**）风格中，这意味着什么？好吧，函数将成为类的一部分。将函数绑定到值相当于调用类的构造函数。将对象传递给另一个函数称为 DI。

等一下！实际上我们正在分离责任并注入依赖项，只是使用纯函数而不是对象！因为我们使用纯函数，依赖关系由编译器明确表示。因此，我们有一种重构代码的方法，几乎没有错误的可能性，因为我们经常使用编译器。这是一个非常有用的重构过程。

我不得不承认，结果并不如我所希望的那样好。让我们重构我们的 lambda。

# 重构 lambda

我对我们提取出来的`computeSalary` lambda 的样子并不满意。由于接收了许多参数和多个责任，它相当复杂。让我们仔细看看它，看看我们如何可以改进它：

```cpp
auto computeSalary = [](auto baseSalaryForPosition, auto 
    factorForSeniority, auto factorForContinuity, auto bonusLevel){
        int baseSalary = baseSalaryForPosition();
        double factor = factorForSeniority();
        double continuityFactor = factorForContinuity();
        int specialBonusLevel =  bonusLevel();

        double specialBonusFactor = specialBonusLevel * 0.03;

        double currentSalary = baseSalary * factor * continuityFactor;
        double salary = currentSalary + specialBonusFactor * 
            currentSalary;

        int roundedSalary = ceil(salary);
         return roundedSalary;
};
```

所有迹象似乎表明这个函数有多个责任。如果我们从中提取更多的函数会怎样呢？让我们从`specialBonusFactor`计算开始：

```cpp
auto specialBonusFactor = [](auto bonusLevel){
    return bonusLevel() * 0.03;
};
auto computeSalary = [](auto baseSalaryForPosition, auto     
factorForSeniority, auto factorForContinuity, auto bonusLevel){
    int baseSalary = baseSalaryForPosition();
    double factor = factorForSeniority();
    double continuityFactor = factorForContinuity();

    double currentSalary = baseSalary * factor * continuityFactor;
    double salary = currentSalary + specialBonusFactor() * 
        currentSalary;

    int roundedSalary = ceil(salary);
    return roundedSalary;
};
```

现在我们可以注入`specialBonusFactor`。但是，请注意，`specialBonusFactor`是唯一需要`bonusLevel`的 lambda。这意味着我们可以将`bonusLevel` lambda 部分应用于`specialBonusFactor` lambda，如下例所示：

```cpp
int main(){
        ...
  auto bonusFactor = bind(specialBonusFactor, [&](){ return 
    bonusLevel(special_bonus_level); } );
  auto roundedSalary = computeSalary(
      bind(baseSalaryForPosition, position), 
      bind(factorForSeniority, seniority_level),
      bind(factorForContinuity, years_worked_continuously),
      bonusFactor
     );
 ...
}

auto computeSalary = [](auto baseSalaryForPosition, auto factorForSeniority, auto factorForContinuity, auto bonusFactor){
    int baseSalary = baseSalaryForPosition();
    double factor = factorForSeniority();
    double continuityFactor = factorForContinuity();

    double currentSalary = baseSalary * factor * continuityFactor;
    double salary = currentSalary + bonusFactor() * currentSalary;

    int roundedSalary = ceil(salary);
    return roundedSalary;
};
```

我们的`computeSalary` lambda 现在更小了。我们甚至可以通过内联临时变量使它更小：

```cpp
auto computeSalary = [](auto baseSalaryForPosition, auto 
    factorForSeniority, auto factorForContinuity, auto bonusFactor){
        double currentSalary = baseSalaryForPosition() * 
            factorForSeniority() * factorForContinuity();
    double salary = currentSalary + bonusFactor() * currentSalary;
    return ceil(salary);
};
```

这很不错！然而，我想让它更接近一个数学公式。首先，让我们重写计算`salary`的那一行（在代码中用粗体标出）：

```cpp
auto computeSalary = [](auto baseSalaryForPosition, auto 
    factorForSeniority, auto factorForContinuity, auto bonusFactor){
        double currentSalary = baseSalaryForPosition() * 
            factorForSeniority() * factorForContinuity();
 double salary = (1 + bonusFactor()) * currentSalary;
    return ceil(salary);
};
```

然后，让我们用函数替换变量。然后我们得到以下代码示例：

```cpp
auto computeSalary = [](auto baseSalaryForPosition, auto 
    factorForSeniority, auto factorForContinuity, auto bonusFactor){
        return ceil (
                (1 + bonusFactor()) * baseSalaryForPosition() *                             
                    factorForSeniority() * factorForContinuity()
    );
};
```

因此，我们有一个 lambda 函数，它接收多个 lambda 函数并使用它们来计算一个值。我们仍然可以对其他函数进行改进，但我们已经达到了一个有趣的点。

那么我们接下来该怎么办呢？我们已经注入了依赖关系，代码更加模块化，更容易更改，也更容易测试。我们可以从测试中注入 lambda 函数，返回我们想要的值，这实际上是单元测试中的一个 stub。虽然我们没有改进整个代码，但我们通过提取纯函数和使用函数操作来分离依赖关系和责任。如果我们愿意，我们可以把代码留在这样。或者，我们可以迈出另一步，将函数重新分组成类。

# 从 lambda 到类

在这本书中，我们已经多次指出，一个类只不过是一组具有内聚性的部分应用纯函数。到目前为止，我们使用的技术已经创建了一堆部分应用的纯函数。现在将它们转换成类是一项简单的任务。

让我们看一个`baseSalaryForPosition`函数的简单例子：

```cpp
auto baseSalaryForPosition = [](const string& position){
    int baseSalary;
    if(position == "Tester") baseSalary = 1500;
    if(position == "Analyst") baseSalary = 1600;
    if(position == "Developer") baseSalary = 2000;
    if(position == "Team Leader") baseSalary = 3000;
    if(position == "Manager") baseSalary = 4000;
    return baseSalary;
};
```

我们在`main()`中使用它，就像下面的例子一样：

```cpp
        auto roundedSalary = computeSalary(
 bind(baseSalaryForPosition, position), 
                bind(factorForSeniority, seniority_level),
                bind(factorForContinuity, years_worked_continuously),
                bonusFactor
            );
```

要将其转换成类，我们只需要创建一个接收`position`参数的构造函数，然后将其改为类方法。让我们在下面的示例中看一下：

```cpp
class BaseSalaryForPosition{
    private:
        const string& position;

    public:
        BaseSalaryForPosition(const string& position) : 
            position(position){};

        int baseSalaryForPosition() const{
            int baseSalary;
            if(position == "Tester") baseSalary = 1500;
            if(position == "Analyst") baseSalary = 1600;
            if(position == "Developer") baseSalary = 2000;
            if(position == "Team Leader") baseSalary = 3000;
            if(position == "Manager") baseSalary = 4000;
            return baseSalary;
        }
};
```

我们可以简单地将部分应用函数传递给`computeSalary` lambda，如下面的代码所示：

```cpp
 auto bonusFactor = bind(specialBonusFactor, [&](){ return 
            bonusLevel(special_bonus_level); } );
            auto roundedSalary = computeSalary(
                theBaseSalaryForPosition,
                bind(factorForSeniority, seniority_level),
                bind(factorForContinuity, years_worked_continuously),
                bonusFactor
            );
```

为了使其工作，我们还需要像这里所示的改变我们的`computeSalary` lambda：

```cpp
auto computeSalary = [](const BaseSalaryForPosition& 
    baseSalaryForPosition, auto factorForSeniority, auto     
        factorForContinuity, auto bonusFactor){
            return ceil (
                (1 + bonusFactor()) * 
                    baseSalaryForPosition.baseSalaryForPosition() *                             
                        factorForSeniority() * factorForContinuity()
            );
};
```

现在，为了允许注入不同的实现，我们实际上需要从`BaseSalaryForPosition`类中提取一个接口，并将其作为接口注入，而不是作为一个类。这对于从测试中注入 double 值非常有用，比如 stub 或 mock。

从现在开始，你可以根据自己的需要将函数重新分组成类。我会把这留给读者作为一个练习，因为我相信我们已经展示了如何使用纯函数来重构代码，即使我们最终想要得到面向对象的代码。

# 重温重构方法

到目前为止，我们学到了什么？嗯，我们经历了一个结构化的重构过程，可以在代码的任何级别使用，减少错误的概率，并实现可更改性和测试性。这个过程基于两个基本思想——任何程序都可以被写成不可变函数和 I/O 函数的组合，或者作为一个函数核心在一个命令式外壳中。此外，我们已经表明这个属性是分形的——我们可以将它应用到任何代码级别，从几行到整个模块。

由于不可变函数可以成为我们程序的核心，我们可以逐渐提取它们。我们写下新的函数名称，复制并粘贴函数体，并使用编译器将任何依赖项作为参数传递。当代码编译完成时，如果我们小心而缓慢地进行更改，我们可以相当确信代码仍然正常工作。这种提取揭示了我们函数的依赖关系，从而使我们能够做出设计决策。

接下来，我们将提取更多的函数，这些函数接收其他部分应用的纯函数作为参数。这导致了依赖关系和实际的破坏性依赖关系之间的明显区别。

最后，由于部分应用函数等同于类，我们可以根据内聚性轻松地封装一个或多个函数。这个过程无论我们是从类还是函数开始，都可以工作，而且无论我们最终想要以函数或类结束都没有关系。然而，它允许我们使用函数构造来打破依赖关系，并在我们的代码中分离责任。

由于我们正在改进设计，现在是时候看看设计模式如何应用于函数式编程以及如何向它们重构。我们将访问一些四人帮模式，以及我们已经在我们的代码中使用过的 DI。

# 设计模式

软件开发中的许多好东西都来自于那些注意到程序员工作方式并从中提取某些教训的人；换句话说，看待实际方法并提取共同和有用的教训，而不是推测解决方案。

所谓的四人帮（Erich Gamma，Richard Helm，Ralph Johnson 和 John Vlissides）在记录设计模式时采取了这种确切的方法，用精确的语言列出了一系列设计模式。在注意到更多程序员以类似的方式解决相同问题后，他们决定将这些模式写下来，并向编程世界介绍了在明确上下文中对特定问题的可重用解决方案的想法。

由于当时的设计范式是面向对象编程，他们出版的*设计模式*书籍展示了使用面向对象方法的这些解决方案。顺便说一句，有趣的是注意到他们在可能的情况下至少记录了两种类型的解决方案——一种基于继承，另一种基于对象组合。我花了很多时间研究设计模式书籍，我可以告诉你，这是一个非常有趣的软件设计课程。

我们将在下一节中探讨一些设计模式以及如何使用函数来实现它们。

# 策略模式，功能风格

策略模式可以简要描述为一种结构化代码的方式，它允许在运行时选择算法。面向对象编程的实现使用 DI，你可能已经熟悉 STL 中的面向对象和功能性设计。

让我们来看看 STL `sort`函数。其最复杂的形式需要一个函数对象，如下例所示：

```cpp
class Comparator{
    public: 
        bool operator() (int first, int second) { return (first < second);}
};

TEST_CASE("Strategy"){
    Comparator comparator;
    vector<int> values {23, 1, 42, 83, 52, 5, 72, 11};
    vector<int> expected {1, 5, 11, 23, 42, 52, 72, 83};

    sort(values.begin(), values.end(), comparator);

    CHECK_EQ(values, expected);
}
```

`sort`函数使用`comparator`对象来比较向量中的元素并对其进行排序。这是一种策略模式，因为我们可以用具有相同接口的任何东西来交换`comparator`；实际上，它只需要实现`operator()`函数。例如，我们可以想象一个用户在 UI 中选择比较函数并使用它对值列表进行排序；我们只需要在运行时创建正确的`comparator`实例并将其发送给`sort`函数。

你已经可以看到功能性解决方案的种子。事实上，`sort`函数允许一个更简单的版本，如下例所示：

```cpp
auto compare = [](auto first, auto second) { return first < second;};

TEST_CASE("Strategy"){
    vector<int> values {23, 1, 42, 83, 52, 5, 72, 11};
    vector<int> expected {1, 5, 11, 23, 42, 52, 72, 83};

    sort(values.begin(), values.end(), compare);

    CHECK_EQ(values, expected);
}
```

这一次，我们放弃了仪式感，直接开始实现我们需要的东西——一个可以插入`sort`的比较函数。不再有类，不再有运算符——策略只是一个函数。

让我们看看这在更复杂的情境中是如何工作的。我们将使用维基百科关于*策略模式*的页面上的问题，并使用功能性方法来编写它。

这里有个问题：我们需要为一家酒吧编写一个计费系统，可以在欢乐时光时应用折扣。这个问题适合使用策略模式，因为我们有两种计算账单最终价格的策略——一种返回全价，而另一种返回全账单的欢乐时光折扣（在我们的例子中使用 50%）。再次，解决方案就是简单地使用两个函数来实现这两种策略——`normalBilling`函数只返回它接收到的全价，而`happyHourBilling`函数返回它接收到的值的一半。让我们在下面的代码中看看这个解决方案（来自我的测试驱动开发（TDD）方法）：

```cpp
map<string, double> drinkPrices = {
    {"Westmalle Tripel", 15.50},
    {"Lagavulin 18y", 25.20},
};

auto happyHourBilling = [](auto price){
    return price / 2;
};

auto normalBilling = [](auto price){
    return price;
};

auto computeBill = [](auto drinks, auto billingStrategy){
    auto prices = transformAll<vector<double>>(drinks, [](auto drink){ 
    return drinkPrices[drink]; });
    auto sum = accumulateAll(prices, 0.0, std::plus<double>());
    return billingStrategy(sum);
};

TEST_CASE("Compute total bill from list of drinks, normal billing"){
   vector<string> drinks; 
   double expectedBill;

   SUBCASE("no drinks"){
       drinks = {};
       expectedBill = 0;
   };

   SUBCASE("one drink no discount"){
       drinks = {"Westmalle Tripel"};
       expectedBill = 15.50;
   };

   SUBCASE("one another drink no discount"){
       drinks = {"Lagavulin 18y"};
       expectedBill = 25.20;
   };

  double actualBill = computeBill(drinks, normalBilling);

   CHECK_EQ(expectedBill, actualBill);
}

TEST_CASE("Compute total bill from list of drinks, happy hour"){
   vector<string> drinks; 
   double expectedBill;

   SUBCASE("no drinks"){
       drinks = {};
       expectedBill = 0;
   };

   SUBCASE("one drink happy hour"){
       drinks = {"Lagavulin 18y"};
       expectedBill = 12.60;
   };

   double actualBill = computeBill(drinks, happyHourBilling);

   CHECK_EQ(expectedBill, actualBill);
}
```

我认为这表明，策略的最简单实现是一个函数。我个人喜欢这种模型为策略模式带来的简单性；编写最小的有用代码使事情正常运行是一种解放。

# 命令模式，函数式风格

命令模式是我在工作中广泛使用的一种模式。它与 MVC 网络框架完美契合，允许将控制器分离为多个功能片段，并同时允许与存储格式分离。它的意图是将请求与动作分离开来——这就是它如此多才多艺的原因，因为任何调用都可以被视为一个请求。

命令模式的一个简单用法示例是在支持多个控制器和更改键盘快捷键的游戏中。这些游戏不能直接将*W*键按下事件与移动角色向上的代码关联起来；相反，您将*W*键绑定到`MoveUpCommand`，从而将两者清晰地解耦。我们可以轻松地更改与命令关联的控制器事件或向上移动的代码，而不会干扰两者之间的关系。

当我们看命令在面向对象代码中是如何实现的时，函数式解决方案变得同样明显。`MoveUpCommand`类将如下例所示：

```cpp
class MoveUpCommand{
    public:
        MoveUpCommand(/*parameters*/){}
        void execute(){ /* implementation of the command */}
}
```

我说过这是显而易见的！我们实际上要做的是很容易用一个命名函数来完成，如下例所示：

```cpp
auto moveUpCommand = [](/*parameters*/{
/* implementation */
};
```

最简单的命令模式就是一个函数。谁会想到呢？

# 函数依赖注入

谈论广泛传播的设计模式时，不能不提及 DI。虽然没有在《四人组》的书中定义，但这种模式在现代代码中变得如此普遍，以至于许多程序员认为它是框架或库的一部分，而不是设计模式。

DI 模式的意图是将类或函数的依赖项的创建与其行为分离。为了理解它解决的问题，让我们看看这段代码：

```cpp
auto readFromFileAndAddTwoNumbers = [](){
    int first;
    int second;
    ifstream numbersFile("numbers.txt");
    numbersFile >> first;
    numbersFile >> second;
    numbersFile.close();
    return first + second;
};

TEST_CASE("Reads from file"){
    CHECK_EQ(30, readFromFileAndAddTwoNumbers());
}
```

如果您只需要从文件中读取两个数字并将它们相加，那么这是相当合理的代码。不幸的是，在现实世界中，我们的客户很可能需要更多的读取数字的来源，比如，如下所示，控制台：

```cpp
auto readFromConsoleAndAddTwoNumbers = [](){
    int first;
    int second;
    cout << "Input first number: ";
    cin >> first;
    cout << "Input second number: ";
    cin >> second;
    return first + second;
};

TEST_CASE("Reads from console"){
    CHECK_EQ(30, readFromConsoleAndAddTwoNumbers());
}
```

在继续之前，请注意，此函数的测试只有在您从控制台输入两个和为`30`的数字时才会通过。因为它们需要在每次运行时输入，所以测试用例在我们的代码示例中被注释了；请随意启用它并进行测试。

这两个函数看起来非常相似。为了解决这种相似之处，DI 可以帮助，如下例所示：

```cpp
auto readAndAddTwoNumbers = [](auto firstNumberReader, auto 
    secondNumberReader){
        int first = firstNumberReader();
        int second = secondNumberReader();
        return first + second;
};
```

现在我们可以实现使用文件的读取器：

```cpp

auto readFirstFromFile = [](){
    int number;
    ifstream numbersFile("numbers.txt");
    numbersFile >> number;
    numbersFile.close();
    return number;
};

auto readSecondFromFile = [](){
    int number;
    ifstream numbersFile("numbers.txt");
    numbersFile >> number;
    numbersFile >> number;
    numbersFile.close();
    return number;
};
```

我们还可以实现使用控制台的读取器：

```cpp

auto readFirstFromConsole = [](){
    int number;
    cout << "Input first number: ";
    cin >> number;
    return number;
};

auto readSecondFromConsole = [](){
    int number;
    cout << "Input second number: ";
    cin >> number;
    return number;
};
```

像往常一样，我们可以测试它们在各种组合中是否正确工作，如下所示：

```cpp
TEST_CASE("Reads using dependency injection and adds two numbers"){
    CHECK_EQ(30, readAndAddTwoNumbers(readFirstFromFile, 
        readSecondFromFile));
    CHECK_EQ(30, readAndAddTwoNumbers(readFirstFromConsole, 
        readSecondFromConsole));
    CHECK_EQ(30, readAndAddTwoNumbers(readFirstFromFile, 
        readSecondFromConsole));
}
```

我们通过 lambda 注入了读取数字的代码。请注意测试代码中使用此方法允许我们随心所欲地混合和匹配依赖项——最后一个检查从文件中读取第一个数字，而第二个数字从控制台中读取。

当然，我们通常在面向对象语言中实现 DI 的方式是使用接口和类。然而，正如我们所看到的，实现 DI 的最简单方式是使用函数。

# 纯函数式设计模式

到目前为止，我们已经看到了一些经典面向对象设计模式如何转变为函数变体。但我们能想象出源自函数式编程的设计模式吗？

嗯，我们实际上已经使用了其中一些。`map`/`reduce`（或 STL 中的`transform`/`accumulate`）就是一个例子。大多数高阶函数（如`filter`、`all_of`和`any_of`等）也是模式的例子。然而，我们甚至可以进一步探索一种常见但不透明的设计模式，它源自函数式编程。

理解它的最佳方法是从具体的问题开始。首先，我们将看看如何在不可变的上下文中保持状态。然后，我们将了解设计模式。最后，我们将在另一个上下文中看到它的应用。

# 保持状态

在函数式编程中如何保持状态？鉴于函数式编程背后的一个想法是不可变性，这似乎是一个奇怪的问题，因为不可变性似乎阻止了状态的改变。

然而，这种限制是一种幻觉。为了理解这一点，让我们想一想时间是如何流逝的。如果我戴上帽子，我就会从没戴帽子变成戴帽子。如果我能够一秒一秒地回顾过去，从我伸手拿帽子的那一刻到戴上它，我就能看到我的每一次动作是如何每秒向着这个目标前进的。但我无法改变任何过去的一秒。无论我们喜欢与否，过去是不可改变的（毕竟，也许我戴帽子看起来很傻，但我无法恢复它）。因此，自然使时间以这样的方式运行，过去是不可改变的，但我们可以改变状态。

我们如何在概念上对这进行建模？好吧，这样想一想——首先，我们有一个初始状态，亚历克斯没戴帽子，以及一个意图到达帽子并戴上的运动定义。在编程术语中，我们用一个函数来模拟运动。该函数接收手的位置和函数本身，并返回手的新位置加上函数。因此，通过模仿自然，我们得到了以下示例中的状态序列：

```cpp
Alex wants to put the hat on
Initial state: [InitialHandPosition, MovementFunction (HandPosition -> next HandPosition)]
State1 = [MovementFunction(InitialHandPosition), MovementFunction]
State2 = [MovementFunction(HandPosition at State1),MovementFunction]...
Staten = [MovementFunction(HandPosition at Staten-1), MovementFunction]
until Alex has hat on
```

通过反复应用`MovementFunction`，我们最终得到一系列状态。*每个状态都是不可变的，但我们可以存储状态*。

现在让我们看一个在 C++中的简单例子。我们可以使用的最简单的例子是一个自增索引。索引需要记住上次使用的值，并使用`increment`函数从索引返回下一个值。通常情况下，我们在尝试使用不可变代码实现这一点时会遇到麻烦，但我们可以用之前描述的方法做到吗？

让我们找出来。首先，我们需要用第一个值初始化自增索引——假设它是`1`。像往常一样，我想检查值是否初始化为我期望的值，如下所示：

```cpp
TEST_CASE("Id"){
    const auto autoIncrementIndex = initAutoIncrement(1);
    CHECK_EQ(1, value(autoIncrementIndex)); 
}
```

请注意，由于`autoIncrementIndex`不会改变，我们可以将其设为`const`。

我们如何实现`initAutoIncrement`？正如我们所说，我们需要初始化一个结构，其中包含当前值（在这种情况下为`1`）和增量函数。我将从这样的一对开始：

```cpp
auto initAutoIncrement = [](const int initialId){
    function<int(const int)> nextId = [](const int lastId){
        return lastId + 1;
    };

    return make_pair(initialId, nextId);
};
```

至于之前的`value`函数，它只是返回一对中的值；它是一对中的第一个元素，如下面的代码片段所示：

```cpp
auto value = [](const auto previous){
    return previous.first;
};
```

现在让我们计算一下我们的自增索引的下一个元素。我们初始化它，然后计算下一个值，并检查下一个值是否为`2`：

```cpp
TEST_CASE("Compute next auto increment index"){
    const auto autoIncrementIndex = initAutoIncrement(1);

    const auto nextAutoIncrementIndex = 
        computeNextAutoIncrement(autoIncrementIndex);

    CHECK_EQ(2, value(nextAutoIncrementIndex)); 
}
```

请再次注意，由于它们永远不会变化，所以两个`autoIncrementIndex`变量都是`const`。我们已经有了值函数，但`computeNextAutoIncrement`函数是什么样子的呢？好吧，它必须接受当前值和一对中的函数，将函数应用于当前值，并返回新值和函数之间的一对：

```cpp
auto computeNextAutoIncrement = [](pair<const int, function<int(const 
    int)>> current){
        const auto currentValue = value(current);
        const auto functionToApply = lambda(current);
        const int newValue = functionToApply(currentValue);
        return make_pair(newValue, functionToApply);
};
```

我们正在使用一个实用函数`lambda`，它返回一对中的 lambda：

```cpp
auto lambda = [](const auto previous){
    return previous.second;
};
```

这真的有效吗？让我们测试下一个值：

```cpp
TEST_CASE("Compute next auto increment index"){
    const auto autoIncrementIndex = initAutoIncrement(1);
    const auto nextAutoIncrementIndex = 
        computeNextAutoIncrement(autoIncrementIndex);
    CHECK_EQ(2, value(nextAutoIncrementIndex)); 

 const auto newAutoIncrementIndex = 
        computeNextAutoIncrement(nextAutoIncrementIndex);
 CHECK_EQ(3, value(newAutoIncrementIndex));
}
```

所有的测试都通过了，表明我们刚刚以不可变的方式存储了状态！

由于这个解决方案看起来非常简单，下一个问题是——我们能否将其概括化？让我们试试看。

首先，让我们用`struct`替换`pair`。结构需要有一个值和一个计算下一个值的函数作为数据成员。这将消除我们的`value()`和`lambda()`函数的需要：

```cpp
struct State{
    const int value;
    const function<int(const int)> computeNext;
};
```

`int`类型会重复出现，但为什么呢？状态可能比`int`更复杂，所以让我们把`struct`变成一个模板：

```cpp
template<typename ValueType>
struct State{
    const ValueType value;
    const function<ValueType(const ValueType)> computeNext;
};
```

有了这个，我们可以初始化一个自增索引并检查初始值：

```cpp
auto increment = [](const int current){
    return current + 1;
};

TEST_CASE("Initialize auto increment"){
    const auto autoIncrementIndex = State<int>{1, increment};

    CHECK_EQ(1, autoIncrementIndex.value); 
}
```

最后，我们需要一个计算下一个`State`的函数。该函数需要返回一个`State<ValueType>`，所以最好将其封装到`State`结构中。此外，它可以使用当前值，因此无需将值传递给它：

```cpp
template<typename ValueType>
struct State{
    const ValueType value;
    const function<ValueType(const ValueType)> computeNext;

 State<ValueType> nextState() const{
 return State<ValueType>{computeNext(value), computeNext};
 };
};

```

有了这个实现，我们现在可以检查我们的自动增量索引的下两个值：

```cpp
TEST_CASE("Compute next auto increment index"){
    const auto autoIncrementIndex = State<int>{1, increment};

    const auto nextAutoIncrementIndex = autoIncrementIndex.nextState();

    CHECK_EQ(2, nextAutoIncrementIndex.value); 

    const auto newAutoIncrementIndex = 
        nextAutoIncrementIndex.nextState();
    CHECK_EQ(3, newAutoIncrementIndex.value);
}
```

测试通过了，所以代码有效！现在让我们再玩一会儿。

假设我们正在实现一个简单的井字棋游戏。我们希望在移动后使用相同的模式来计算棋盘的下一个状态。

首先，我们需要一个可以容纳 TicTacToe 棋盘的结构。为简单起见，我将使用`vector<vector<Token>>`，其中`Token`是一个可以容纳`Blank`、`X`或`O`值的`enum`：

```cpp
enum Token {Blank, X, O};
typedef vector<vector<Token>> TicTacToeBoard;
```

然后，我们需要一个`Move`结构。`Move`结构需要包含移动的棋盘坐标和用于进行移动的标记：

```cpp
struct Move{
    const Token token;
    const int xCoord;
    const int yCoord;
};
```

我们还需要一个函数，它可以接受一个`TicTacToeBoard`，应用一个移动，并返回新的棋盘。为简单起见，我将使用本地变异来实现它，如下所示：

```cpp
auto makeMove = [](const TicTacToeBoard board, const Move move) -> 
    TicTacToeBoard {
        TicTacToeBoard nextBoard(board);
        nextBoard[move.xCoord][move.yCoord] = move.token;
         return nextBoard;
};
```

我们还需要一个空白的棋盘来初始化我们的`State`。让我们手工填充`Token::Blank`：

```cpp
const TicTacToeBoard EmptyBoard{
    {Token::Blank,Token::Blank, Token::Blank},
    {Token::Blank,Token::Blank, Token::Blank},
    {Token::Blank,Token::Blank, Token::Blank}
};
```

我们想要进行第一步移动。但是，我们的`makeMove`函数不符合`State`结构允许的签名；它需要一个额外的参数，`Move`。首先，我们可以将`Move`参数绑定到一个硬编码的值。假设`X`移动到左上角，坐标为*(0,0)*：

```cpp
TEST_CASE("TicTacToe compute next board after a move"){
    Move firstMove{Token::X, 0, 0};
    const function<TicTacToeBoard(const TicTacToeBoard)> makeFirstMove 
        = bind(makeMove, _1, firstMove);
    const auto emptyBoardState = State<TicTacToeBoard>{EmptyBoard, 
        makeFirstMove };
    CHECK_EQ(Token::Blank, emptyBoardState.value[0][0]); 

    const auto boardStateAfterFirstMove = emptyBoardState.nextState();
    CHECK_EQ(Token::X, boardStateAfterFirstMove.value[0][0]); 
}
```

如你所见，我们的`State`结构在这种情况下运行良好。但是，它有一个限制：它只允许一次移动。问题在于计算下一个阶段的函数不能更改。但是，如果我们将其作为参数传递给`nextState()`函数呢？我们最终得到了一个新的结构；让我们称之为`StateEvolved`。它保存一个值和一个`nextState()`函数，该函数接受计算下一个状态的函数，应用它，并返回下一个`StateEvolved`：

```cpp
template<typename ValueType>
struct StateEvolved{
    const ValueType value;
    StateEvolved<ValueType> nextState(function<ValueType(ValueType)> 
        computeNext) const{
            return StateEvolved<ValueType>{computeNext(value)};
    };
};
```

现在我们可以通过将`makeMove`函数与绑定到实际移动的`Move`参数一起传递给`nextState`来进行移动：

```cpp
TEST_CASE("TicTacToe compute next board after a move with 
    StateEvolved"){
    const auto emptyBoardState = StateEvolved<TicTacToeBoard>
        {EmptyBoard};
    CHECK_EQ(Token::Blank, emptyBoardState.value[0][0]); 
    auto xMove = bind(makeMove, _1, Move{Token::X, 0, 0});
    const auto boardStateAfterFirstMove = 
        emptyBoardState.nextState(xMove);
    CHECK_EQ(Token::X, boardStateAfterFirstMove.value[0][0]); 
}
```

我们现在可以进行第二步移动。假设`O`移动到坐标*(1,1)*的中心。让我们检查前后状态：

```cpp
    auto oMove = bind(makeMove, _1, Move{Token::O, 1, 1});
    const auto boardStateAfterSecondMove = 
        boardStateAfterFirstMove.nextState(oMove);
    CHECK_EQ(Token::Blank, boardStateAfterFirstMove.value[1][1]); 
    CHECK_EQ(Token::O, boardStateAfterSecondMove.value[1][1]); 
```

正如你所看到的，使用这种模式，我们可以以不可变的方式存储任何状态。

# 揭示

我们之前讨论的设计模式对函数式编程似乎非常有用，但你可能已经意识到我一直在避免命名它。

事实上，到目前为止我们讨论的模式是单子的一个例子，具体来说是`State`单子。我一直避免告诉你它的名字，因为单子在软件开发中是一个特别晦涩的话题。对于这本书，我观看了数小时的单子视频；我还阅读了博客文章和文章，但出于某种原因，它们都无法理解。由于单子是范畴论中的一个数学对象，我提到的一些资源采用数学方法，并使用定义和运算符来解释它们。其他资源尝试通过示例来解释，但它们是用具有对单子模式的本地支持的编程语言编写的。它们都不符合我们这本书的目标——对复杂概念的实际方法。

要更好地理解单子，我们需要看更多的例子。最简单的例子可能是`Maybe`单子。

# 也许

考虑尝试在 C++中计算以下表达式：

```cpp
2  + (3/0) * 5
```

可能会发生什么？通常会抛出异常，因为我们试图除以`0`。但是，有些情况下，我们希望看到一个值，比如`None`或`NaN`，或者某种消息。我们已经看到，我们可以使用`optional<int>`来存储可能是整数或值的数据；因此，我们可以实现一个返回`optional<int>`的除法函数，如下所示：

```cpp
    function<optional<int>(const int, const int)> divideEvenWith0 = []
      (const int first, const int second) -> optional<int>{
        return (second == 0) ? nullopt : make_optional(first / second);
    };
```

然而，当我们尝试在表达式中使用`divideEvenWith0`时，我们意识到我们还需要改变所有其他操作符。例如，我们可以实现一个`plusOptional`函数，当任一参数为`nullopt`时返回`nullopt`，否则返回值，如下例所示：

```cpp
    auto plusOptional = [](optional<int> first, optional<int> second) -
        > optional<int>{
            return (first == nullopt || second == nullopt) ? 
                nullopt :
            make_optional(first.value() + second.value());
    };
```

虽然它有效，但这需要编写更多的函数和大量的重复。但是，嘿，我们能写一个函数，它接受一个`function<int(int, int)>`并将其转换为`function<optional<int>(optional<int>, optional<int>)`吗？当然，让我们编写以下函数：

```cpp
    auto makeOptional = [](const function<int(int, int)> operation){
        return operation -> optional<int>{
            if(first == nullopt || second == nullopt) return nullopt;
            return make_optional(operation(first.value(), 
                second.value()));
        };
    };
```

这很好地运行了，如下所示通过了测试：

```cpp
    auto plusOptional = makeOptional(plus<int>());
    auto divideOptional = makeOptional(divides<int>());

    CHECK_EQ(optional{3}, plusOptional(optional{1}, optional{2}));
    CHECK_EQ(nullopt, plusOptional(nullopt, optional{2}));

    CHECK_EQ(optional{2}, divideOptional(optional{2}, optional{1}));
    CHECK_EQ(nullopt, divideOptional(nullopt, optional{1}));
```

然而，这并没有解决一个问题——当除以`0`时，我们仍然需要返回`nullopt`。因此，以下测试将失败如下：

```cpp
//    CHECK_EQ(nullopt, divideOptional(optional{2}, optional{0}));
//    cout << "Result of 2 / 0 = " << to_string(divideOptional
        (optional{2}, optional{0})) << endl;
```

我们可以通过使用我们自己的`divideEvenBy0`方法来解决这个问题，而不是使用标准的除法：

```cpp
    function<optional<int>(const int, const int)> divideEvenWith0 = []
      (const int first, const int second) -> optional<int>{
        return (second == 0) ? nullopt : make_optional(first / second);
    };

```

这次，测试通过了，如下所示：

```cpp
    auto divideOptional = makeOptional(divideEvenWith0);

    CHECK_EQ(nullopt, divideOptional(optional{2}, optional{0}));
    cout << "Result of 2 / 0 = " << to_string(divideOptional
        (optional{2}, optional{0})) << endl;
```

此外，运行测试后的显示如下：

```cpp
Result of 2 / 0 = None
```

我不得不说，摆脱除以`0`的暴政并得到一个结果有一种奇怪的满足感。也许这只是我。

无论如何，这引导我们来定义`Maybe`单子。它存储一个值和一个名为`apply`的函数。`apply`函数接受一个操作（`plus<int>()`，`minus<int>()`，`divideEvenWith0`，或`multiplies<int>()`），以及一个要应用操作的第二个值，并返回结果：

```cpp
template<typename ValueType>
struct Maybe{
    typedef function<optional<ValueType>(const ValueType, const 
        ValueType)> OperationType;
    const optional<ValueType> value;

    optional<ValueType> apply(const OperationType operation, const 
        optional<ValueType> second){
            if(value == nullopt || second == nullopt) return nullopt;
            return operation(value.value(), second.value());
    }
};
```

我们可以使用`Maybe`单子来进行计算如下：

```cpp
TEST_CASE("Compute with Maybe monad"){
    function<optional<int>(const int, const int)> divideEvenWith0 = []
      (const int first, const int second) -> optional<int>{
        return (second == 0) ? nullopt : make_optional(first / second);
    };

    CHECK_EQ(3, Maybe<int>{1}.apply(plus<int>(), 2));
    CHECK_EQ(nullopt, Maybe<int>{nullopt}.apply(plus<int>(), 2));
    CHECK_EQ(nullopt, Maybe<int>{1}.apply(plus<int>(), nullopt));

    CHECK_EQ(2, Maybe<int>{2}.apply(divideEvenWith0, 1));
    CHECK_EQ(nullopt, Maybe<int>{nullopt}.apply(divideEvenWith0, 1));
    CHECK_EQ(nullopt, Maybe<int>{2}.apply(divideEvenWith0, nullopt));
    CHECK_EQ(nullopt, Maybe<int>{2}.apply(divideEvenWith0, 0));
    cout << "Result of 2 / 0 = " << to_string(Maybe<int>
        {2}.apply(divideEvenWith0, 0)) << endl;
}
```

再次，我们可以计算表达式，即使有`nullopt`。

# 那么单子是什么？

**单子**是一种模拟计算的函数式设计模式。它来自数学；更确切地说，来自称为**范畴论**的领域。

什么是计算？基本计算是一个函数；但是，我们有兴趣为函数添加更多的行为。我们已经看到了维护状态和允许可选类型操作的两个例子，但是单子在软件设计中是相当普遍的。

单子基本上有一个值和一个高阶函数。为了理解它们的作用，让我们来比较以下代码中显示的`State`单子：

```cpp
template<typename ValueType>
struct StateEvolved{
    const ValueType value;

    StateEvolved<ValueType> nextState(function<ValueType(ValueType)> 
        computeNext) const{
            return StateEvolved<ValueType>{computeNext(value)};
    };
};
```

使用此处显示的`Maybe`单子：

```cpp
template<typename ValueType>
struct Maybe{
    typedef function<optional<ValueType>(const ValueType, const 
        ValueType)> OperationType;
    const optional<ValueType> value;

    optional<ValueType> apply(const OperationType operation, const 
        optional<ValueType> second) const {
            if(value == nullopt || second == nullopt) return nullopt;
            return operation(value.value(), second.value());
    }
};
```

它们都包含一个值。该值封装在单子结构中。它们都包含一个对该值进行计算的函数。`apply`/`nextState`（在文献中称为`bind`）函数本身接收一个封装计算的函数；但是，单子除了计算之外还做了一些其他事情。

单子还有更多的内容，不仅仅是这些简单的例子。但是，它们展示了如何封装某些计算以及如何消除某些类型的重复。

值得注意的是，C++中的`optional<>`类型实际上是受到了`Maybe`单子的启发，以及承诺，因此您可能已经在代码中使用了等待被发现的单子。

# 总结

在本章中，我们学到了很多关于改进设计的知识。我们了解到重构意味着重构代码而不改变程序的外部行为。我们看到为了确保行为的保留，我们需要采取非常小的步骤和测试。我们了解到遗留代码是我们害怕改变的代码，为了为其编写测试，我们需要首先更改代码，这导致了一个困境。我们还学到，幸运的是，我们可以对代码进行一些小的更改，这些更改保证了行为的保留，但打破了依赖关系，从而允许我们通过测试插入代码。然后我们看到，我们可以使用纯函数来识别和打破依赖关系，从而导致我们可以根据内聚性将它们重新组合成类。

最后，我们了解到我们可以在函数式编程中使用设计模式，并且看到了一些例子。即使您不使用函数式编程的其他内容，使用策略、命令或注入依赖等函数将使您的代码更容易进行最小干扰的更改。我们提到了一个非常抽象的设计模式，单子，以及我们如何使用`Maybe`单子和`State`单子。这两者都可以在我们的写作中帮助我们更少的代码实现更丰富的功能。

我们已经讨论了很多关于软件设计的内容。但是函数式编程是否适用于架构？这就是我们将在下一章中讨论的内容——事件溯源。
