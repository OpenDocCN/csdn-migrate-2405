# C++ 现代编程（七）

> 原文：[`annas-archive.org/md5/F02528C543403FA60BC7527E0C58459D`](https://annas-archive.org/md5/F02528C543403FA60BC7527E0C58459D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：数学问题

# 问题

这是本章的问题解决部分。

# 1. 可被 3 和 5 整除的自然数之和

编写一个计算和打印所有自然数的程序，这些自然数可被 3 或 5 整除，直到用户输入的给定限制为止。

# 2. 最大公约数

编写一个程序，给定两个正整数，将计算并打印两者的最大公约数。

# 3. 最小公倍数

编写一个程序，给定两个或多个正整数，计算并打印它们的最小公倍数。

# 4. 给定数字以下的最大质数

编写一个程序，计算并打印小于用户提供的数字的最大质数，该数字必须是正整数。

# 5. 性感素数

编写一个程序，打印用户输入限制范围内的所有性感素数对。

# 6. 过剩数

编写一个程序，打印所有过剩数及其过剩值，直到用户输入的数字为止。

# 7. 亲和数

编写一个程序，打印小于 1,000,000 的所有亲和数对的列表。

# 8. 阿姆斯特朗数

编写一个程序，打印所有三位数的阿姆斯特朗数。

# 9. 数的质因数

编写一个程序，打印用户输入数字的质因数。

# 10. 格雷码

编写一个程序，显示所有 5 位数的普通二进制表示、格雷码表示和解码的格雷码值。

# 11. 将数值转换为罗马数字

编写一个程序，给定用户输入的数字，打印其罗马数字等价物。

# 12. 最大 Collatz 序列

编写一个程序，确定并打印出哪个数字最多产生最长的 Collatz 序列，以及它的长度是多少。

# 13. 计算 Pi 的值

编写一个计算 Pi 值的程序，精确到小数点后两位。

# 14. 验证 ISBN

编写一个程序，验证用户输入的 10 位值（作为字符串）是否表示有效的 ISBN-10 号码。

# 解决方案

以上是上述问题解决部分的解决方案。

# 1. 可被 3 和 5 整除的自然数之和

解决此问题的方法是迭代从 3（1 和 2 不能被 3 整除，因此没有测试它们的意义）到用户输入的限制的所有数字。使用模运算来检查一个数字除以 3 和 5 的余数是否为 0。然而，能够加到更大限制的技巧是使用`long long`而不是`int`或`long`进行求和，否则在加到 100,000 之前会发生溢出：

```cpp
int main()
{
   unsigned int limit = 0;
   std::cout << "Upper limit:";
   std::cin >> limit;

   unsigned long long sum = 0;
   for (unsigned int i = 3; i < limit; ++i)
   {
     if (i % 3 == 0 || i % 5 == 0)
        sum += i;
   }

   std::cout << "sum=" << sum << std::endl;
}
```

# 2. 最大公约数

两个或多个非零整数的最大公约数（*gcd*简称），也称为最大公因数（*gcf*）、最大公因数（*hcf*）、最大公度量（*gcm*）或最大公约数，是能够整除它们所有的最大正整数。可以计算 gcd 的几种方法；一种有效的方法是欧几里得算法。对于两个整数，该算法是：

```cpp
gcd(a,0) = a
gcd(a,b) = gcd(b, a mod b)
```

这可以在 C++中使用递归函数非常简单地实现：

```cpp
unsigned int gcd(unsigned int const a, unsigned int const b)
{
   return b == 0 ? a : gcd(b, a % b);
}
```

欧几里得算法的非递归实现应该如下所示：

```cpp
unsigned int gcd(unsigned int a, unsigned int b)
{
   while (b != 0) {
      unsigned int r = a % b;
      a = b;
      b = r;
   }
   return a;
}
```

在 C++17 中，头文件`<numeric>`中有一个名为`gcd()`的`constexpr`函数，用于计算两个数字的最大公约数。

# 3. 最小公倍数

两个或多个非零整数的**最小公倍数**（**lcm**），也称为最小公倍数，或最小公倍数，是可以被它们所有整除的最小正整数。计算最小公倍数的一种可能方法是将问题简化为计算最大公约数。在这种情况下使用以下公式：

```cpp
lcm(a, b) = abs(a, b) / gcd(a, b)
```

计算最小公倍数的函数可能如下所示：

```cpp
int lcm(int const a, int const b)
{
   int h = gcd(a, b);
   return h ? (a * (b / h)) : 0;
}
```

要计算多于两个整数的*lcm*，可以使用头文件`<numeric>`中的`std::accumulate`算法：

```cpp
template<class InputIt>
int lcmr(InputIt first, InputIt last)
{
   return std::accumulate(first, last, 1, lcm);
}
```

在 C++17 中，有一个名为`lcm()`的`constexpr`函数，位于头文件`<numeric>`中，用于计算两个数的最小公倍数。

# 4. 给定数字的最大质数

质数是只有两个因子 1 和本身的数。要找到小于给定数字的最大质数，你应该首先编写一个确定一个数是否为质数的函数，然后调用这个函数，从给定数字开始，向 1 递减直到遇到第一个质数。有各种算法可以确定一个数是否为质数。确定质数性的常见实现如下：

```cpp
bool is_prime(int const num) 
{
   if (num <= 3) { return num > 1; }
   else if (num % 2 == 0 || num % 3 == 0) 
   { 
      return false; 
   }
   else 
   {
      for (int i = 5; i * i <= num; i += 6) 
      {
         if (num % i == 0 || num % (i + 2) == 0) 
         {
            return false;
         }
      }
      return true;
   }
}
```

这个函数可以这样使用：

```cpp
int main()
{
   int limit = 0;
   std::cout << "Upper limit:";
   std::cin >> limit;

   for (int i = limit; i > 1; i--)
   {
      if (is_prime(i))
      {
         std::cout << "Largest prime:" << i << std::endl;
         return 0;
      }
   }
}
```

# 5. 性质质数对

性质质数是相差六的质数（例如 5 和 11，或 13 和 19）。还有*孪生质数*，相差两，和*表兄质数*，相差四。

在上一个挑战中，我们实现了一个确定整数是否为质数的函数。我们将重用该函数进行此练习。你需要做的是检查一个数字`n`是否为质数，数字`n+6`也是质数，并在这种情况下将这对数字打印到控制台上：

```cpp
int main()
{
   int limit = 0;
   std::cout << "Upper limit:";
   std::cin >> limit;

   for (int n = 2; n <= limit; n++)
   {
      if (is_prime(n) && is_prime(n+6))
      {
         std::cout << n << "," << n+6 << std::endl;
      }
   }
}
```

你可以将其作为进一步的练习来计算和显示性质质数的三元组、四元组和五元组。

# 6. 丰富数

丰富数，也被称为过剩数，是一个其真因子之和大于该数本身的数。一个数的真因子是除了该数本身以外的正的质因子。真因子之和超过该数本身的数量被称为过剩。例如，数字 12 有真因子 1、2、3、4 和 6。它们的和是 16，这使得 12 成为一个丰富数。它的过剩是 4（即 16-12）。

要确定真因子的和，我们尝试从 2 到该数的平方根的所有数字（所有质因子都小于或等于这个值）。如果当前数字，我们称之为`i`，能够整除该数，那么`i`和`num/i`都是因子。然而，如果它们相等（例如，如果`i=3`，而`n=9`，那么`i`能整除 9，但`n/i=3`），我们只添加`i`，因为真因子只能被添加一次。否则，我们添加`i`和`num/i`并继续：

```cpp
int sum_proper_divisors(int const number)
{
   int result = 1;
   for (int i = 2; i <= std::sqrt(number); i++)
   {
      if (number%i == 0)
      {
         result += (i == (number / i)) ? i : (i + number / i);
      }
   }
   return result;
}
```

打印丰富数就像迭代到指定的限制，计算真因子的和并将其与数字进行比较一样简单：

```cpp
void print_abundant(int const limit)
{
   for (int number = 10; number <= limit; ++number)
   {
      auto sum = sum_proper_divisors(number);
      if (sum > number)
      {
         std::cout << number << ", abundance=" 
                   << sum - number << std::endl;
      }
   }
}

int main()
{
   int limit = 0;
   std::cout << "Upper limit:";
   std::cin >> limit;

   print_abundant(limit);
}
```

# 7. 亲和数

如果一个数的真因子之和等于另一个数的真因子之和，那么这两个数被称为亲和数。一个数的真因子是除了该数本身以外的正的质因子。亲和数不应该与*友好数*混淆。例如，数字 220 的真因子是 1、2、4、5、10、11、20、22、44、55 和 110，它们的和是 284。284 的真因子是 1、2、4、71 和 142；它们的和是 220。因此，数字 220 和 284 被称为亲和数。

解决这个问题的方法是遍历所有小于给定限制的数字。对于每个数字，计算其真因子的和。我们称这个和为`sum1`。重复这个过程并计算`sum1`的真因子的和。如果结果等于原始数字，那么数字和`sum1`是亲和数：

```cpp
void print_amicables(int const limit)
{
   for (int number = 4; number < limit; ++number)
   {
      auto sum1 = sum_proper_divisors(number);
      if (sum1 < limit)
      {
         auto sum2 = sum_proper_divisors(sum1);
         if (sum2 == number && number != sum1)
         {
            std::cout << number << "," << sum1 << std::endl;
         }
      }
   }
}
```

在上面的示例中，`sum_proper_divisors()`是在丰富数问题的解决方案中看到的函数。

上述函数会两次打印数字对，比如 220,284 和 284,220。修改这个实现，只打印每对一次。

# 8. 阿姆斯特朗数

阿姆斯特朗数（以迈克尔·F·阿姆斯特朗命名），也称为自恋数，完美的数字不变量或完美的数字，是一个等于其自身的数字，当它们被提升到数字的幂时。例如，最小的阿姆斯特朗数是 153，它等于![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/mod-cpp/img/8a736b24-c3af-4da2-a9da-12789af4ee9e.png)。

要确定一个三位数是否是一个自恋数，您必须首先确定它的数字，以便对它们的幂求和。然而，这涉及到除法和取模运算，这些都是昂贵的。计算它的一个更快的方法是依赖于这样一个事实，即一个数字是数字的和，乘以 10 的零基位置的幂。换句话说，对于最多 1,000 的数字，我们有`a*10² + b*10² + c`。因为你只需要确定三位数，这意味着`a`将从 1 开始。这比其他方法更快，因为乘法比除法和取模运算更快。这样一个函数的实现看起来像这样：

```cpp
void print_narcissistics()
{
   for (int a = 1; a <= 9; a++)
   {
      for (int b = 0; b <= 9; b++)
      {
         for (int c = 0; c <= 9; c++)
         {
            auto abc = a * 100 + b * 10 + c;
            auto arm = a * a * a + b * b * b + c * c * c;
            if (abc == arm)
            {
               std::cout << arm << std::endl;
            }
         }
      }
   }
}
```

您可以将其作为进一步的练习，编写一个确定自恋数的函数，直到达到限制，而不管它们的位数如何。这样一个函数会更慢，因为你首先必须确定数字的数字序列，将它们存储在一个容器中，然后将数字加到适当的幂（数字的数量）。

# 9. 数字的质因数

正整数的质因数是能够完全整除该整数的质数。例如，8 的质因数是 2 x 2 x 2，42 的质因数是 2 x 3 x 7。要确定质因数，您应该使用以下算法：

1.  当`n`可以被 2 整除时，2 是一个质因数，必须添加到列表中，而`n`变为`n/2`的结果。完成此步骤后，`n`是一个奇数。

1.  从 3 迭代到`n`的平方根。当当前数字，我们称之为`i`，除以`n`时，`i`是一个质因数，必须添加到列表中，而`n`变为`n/i`的结果。当`i`不再除以`n`时，将`i`增加 2（以获得下一个奇数）。

1.  当`n`是大于 2 的质数时，上述步骤将不会导致`n`变为 1。因此，如果在第 2 步结束时`n`仍大于 2，则`n`是一个质因数。

```cpp
std::vector<unsigned long long> prime_factors(unsigned long long n)
{
   std::vector<unsigned long long> factors;
   while (n % 2 == 0) {
      factors.push_back(2);
      n = n / 2;
   }
   for (unsigned long long i = 3; i <= std::sqrt(n); i += 2)
   {
      while (n%i == 0) {
         factors.push_back(i);
         n = n / i;
      }
   }

   if (n > 2) 
      factors.push_back(n);
   return factors;
}

int main()
{
   unsigned long long number = 0;
   std::cout << "number:";
   std::cin >> number;

   auto factors = prime_factors(number);
   std::copy(std::begin(factors), std::end(factors),
        std::ostream_iterator<unsigned long long>(std::cout, " "));
}
```

作为进一步的练习，确定数字 600,851,475,143 的最大质因数。

# 10. 格雷码

格雷码，也称为反射二进制码或简单反射二进制，是一种二进制编码形式，其中两个连续的数字只相差一个位。要执行二进制反射格雷码编码，我们需要使用以下公式：

```cpp
if b[i-1] = 1 then g[i] = not b[i]
else g[i] = b[i]
```

这相当于以下内容：

```cpp
g = b xor (b logically right shifted 1 time)
```

要解码二进制反射格雷码，应使用以下公式：

```cpp
b[0] = g[0]
b[i] = g[i] xor b[i-1]
```

这些可以用 C++编写如下，对于 32 位无符号整数：

```cpp
unsigned int gray_encode(unsigned int const num)
{
   return num ^ (num >> 1);
}

unsigned int gray_decode(unsigned int gray)
{
   for (unsigned int bit = 1U << 31; bit > 1; bit >>= 1)
   {
      if (gray & bit) gray ^= bit >> 1;
   }
   return gray;
}
```

要打印所有 5 位整数，它们的二进制表示，编码的格雷码表示和解码的值，我们可以使用以下代码：

```cpp
std::string to_binary(unsigned int value, int const digits)
{
   return std::bitset<32>(value).to_string().substr(32-digits, digits);
}

int main()
{
   std::cout << "Number\tBinary\tGray\tDecoded\n";
   std::cout << "------\t------\t----\t-------\n";

   for (unsigned int n = 0; n < 32; ++n)
   {
      auto encg = gray_encode(n);
      auto decg = gray_decode(encg);

      std::cout 
         << n << "\t" << to_binary(n, 5) << "\t" 
         << to_binary(encg, 5) << "\t" << decg << "\n";
   }
}
```

# 11. 将数值转换为罗马数字

罗马数字，如今所知，使用七个符号：I = 1，V = 5，X = 10，L = 50，C = 100，D = 500，M = 1000。该系统使用加法和减法来组成数字符号。从 1 到 10 的符号是 I，II，III，IV，V，VI，VII，VIII，IX 和 X。罗马人没有零的符号，而是用*nulla*来表示。在这个系统中，最大的符号在左边，最不重要的在右边。例如，1994 年的罗马数字是 MCMXCIV。如果您不熟悉罗马数字的规则，您应该在网上阅读更多。

要确定一个数字的罗马数字，使用以下算法：

1.  从最高（M）到最低（I）检查每个罗马基本符号

1.  如果当前值大于符号的值，则将符号连接到罗马数字并从当前值中减去其值

1.  重复直到当前值达到零

例如，考虑 42：小于 42 的第一个罗马基本符号是 XL，它是 40。我们将它连接到罗马数字上，得到 XL，并从当前数字中减去，得到 2。小于 2 的第一个罗马基本符号是 I，它是 1。我们将它添加到罗马数字上，得到 XLI，并从数字中减去 1，得到 1。我们再添加一个 I 到罗马数字中，它变成了 XLII，并再次从数字中减去 1，达到 0，因此停止：

```cpp
std::string to_roman(unsigned int value)
{
   std::vector<std::pair<unsigned int, char const*>> roman {
      { 1000, "M" },{ 900, "CM" }, { 500, "D" },{ 400, "CD" }, 
      { 100, "C" },{ 90, "XC" }, { 50, "L" },{ 40, "XL" },
      { 10, "X" },{ 9, "IX" }, { 5, "V" },{ 4, "IV" }, { 1, "I" }};

   std::string result;
   for (auto const & kvp : roman) {
      while (value >= kvp.first) {
         result += kvp.second;
         value -= kvp.first;
      }
   }
   return result;
}
```

这个函数可以按照以下方式使用：

```cpp
int main()
{
   for(int i = 1; i <= 100; ++i) 
   {
      std::cout << i << "\t" << to_roman(i) << std::endl; 
   }

   int number = 0;
   std::cout << "number:";
   std::cin >> number;
   std::cout << to_roman(number) << std::endl;
}
```

# 12. 最大的 Collatz 序列

Collatz 猜想，也称为乌拉姆猜想、角谷谜题、斯韦茨猜想、哈斯算法或锡拉丘兹问题，是一个未经证实的猜想，它指出如下所述的序列总是达到 1。该系列定义如下：从任何正整数`n`开始，并从前一个整数获得每个新项：如果前一个项是偶数，则下一个项是前一个项的一半，否则是前一个项的 3 倍加 1。

你要解决的问题是生成所有小于一百万的正整数的 Collatz 序列，确定其中最长的序列，并打印其长度和产生它的起始数字。虽然我们可以应用蛮力法为每个数字生成序列并计算达到 1 之前的项数，但更快的解决方案是保存已经生成的所有序列的长度。当从值`n`开始的序列的当前项变小于`n`时，那么它是一个其序列已经被确定的数字，因此我们可以简单地获取其缓存长度并将其添加到当前长度以确定从`n`开始的序列的长度。然而，这种方法引入了对 Collatz 序列的计算的限制，因为在某个时候，缓存将超过系统可以分配的内存量：

```cpp
std::pair<unsigned long long, long> longest_collatz(
   unsigned long long const limit)
{
   long length = 0;
   unsigned long long number = 0;
   std::vector<int> cache(limit + 1, 0);

   for (unsigned long long i = 2; i <= limit; i++) 
   {
      auto n = i;
      long steps = 0;
      while (n != 1 && n >= i) 
      {
         if ((n % 2) == 0) n = n / 2;
         else n = n * 3 + 1;
         steps++;
      }
      cache[i] = steps + cache[n];

      if (cache[i] > length) 
      {
         length = cache[i];
         number = i;
```

```cpp
      }
   }

   return std::make_pair(number, length);
}
```

# 13. 计算 Pi 的值

用蒙特卡洛模拟大致确定 Pi 的值是一个合适的解决方案。这是一种使用输入的随机样本来探索复杂过程或系统行为的方法。该方法在许多应用和领域中使用，包括物理学、工程学、计算机、金融、商业等。

为了做到这一点，我们将依赖以下想法：直径为`d`的圆的面积是`PI * d² / 4`。边长等于`d`的正方形的面积是`d²`。如果我们将两者相除，我们得到`PI/4`。如果我们将圆放在正方形内并在正方形内生成均匀分布的随机数，那么圆内的数字计数应该与圆的面积成正比，正方形内的数字计数应该与正方形的面积成正比。这意味着将正方形和圆中的总命中数相除应该得到`PI/4`。生成的点越多，结果就越准确。

为了生成伪随机数，我们将使用 Mersenne twister 和均匀统计分布：

```cpp
template <typename E = std::mt19937, 
          typename D = std::uniform_real_distribution<>>
double compute_pi(E& engine, D& dist, int const samples = 1000000)
{
   auto hit = 0;
   for (auto i = 0; i < samples; i++)
   {
      auto x = dist(engine);
      auto y = dist(engine);
      if (y <= std::sqrt(1 - std::pow(x, 2))) hit += 1;
   }
   return 4.0 * hit / samples;
}

int main()
{
   std::random_device rd;
   auto seed_data = std::array<int, std::mt19937::state_size> {};
   std::generate(std::begin(seed_data), std::end(seed_data), 
                 std::ref(rd));
   std::seed_seq seq(std::begin(seed_data), std::end(seed_data));
   auto eng = std::mt19937{ seq };
   auto dist = std::uniform_real_distribution<>{ 0, 1 };

   for (auto j = 0; j < 10; j++)
      std::cout << compute_pi(eng, dist) << std::endl;
}
```

# 14. 验证 ISBN

**国际标准书号**（**ISBN**）是书籍的唯一数字标识符。目前使用的是 13 位格式。然而，对于这个问题，你需要验证使用 10 位数字的旧格式。10 位数字中的最后一位是一个校验和。选择这一位数字是为了使所有十个数字的和，每个数字乘以它的（整数）权重，从 10 到 1 递减，是 11 的倍数。

`validate_isbn_10`函数如下所示，接受一个 ISBN 作为字符串，并在字符串长度为 10、所有十个元素都是数字，并且所有数字乘以它们的权重（或位置）的和是 11 的倍数时返回`true`：

```cpp
bool validate_isbn_10(std::string_view isbn)
{
   auto valid = false;
   if (isbn.size() == 10 &&
       std::count_if(std::begin(isbn), std::end(isbn), isdigit) == 10)
   {
      auto w = 10;
      auto sum = std::accumulate(
         std::begin(isbn), std::end(isbn), 0,
         &w {
            return total + w-- * (c - '0'); });

     valid = !(sum % 11);
   }
   return valid;
}
```

你可以把这看作是进一步练习，以改进这个函数，使其能够正确验证包括连字符的 ISBN-10 号码，比如`3-16-148410-0`。另外，你也可以编写一个验证 ISBN-13 号码的函数。


# 第十三章：语言特性

# 问题

这是本章的问题解决部分。

# 15. IPv4 数据类型

编写一个表示 IPv4 地址的类。实现所需的函数，以便能够从控制台读取和写入这些地址。用户应该能够以点分形式输入值，例如`127.0.0.1`或`168.192.0.100`。这也是 IPv4 地址应该格式化为输出流的形式。

# 16. 在范围内枚举 IPv4 地址

编写一个程序，允许用户输入表示范围的两个 IPv4 地址，并列出该范围内的所有地址。扩展为前一个问题定义的结构以实现所请求的功能。

# 17. 创建具有基本操作的 2D 数组

编写一个表示具有元素访问（`at()`和`data()`）、容量查询、迭代器、填充和交换方法的二维数组容器的类模板。应该可以移动此类型的对象。

# 18. 具有任意数量参数的最小函数

编写一个函数模板，可以接受任意数量的参数，并使用`operator <`进行比较返回它们所有的最小值。编写此函数模板的变体，可以使用二进制比较函数进行参数化，而不是使用`operator <`。

# 19. 将一系列值添加到容器中

编写一个通用函数，可以将任意数量的元素添加到具有`push_back(T&& value)`方法的容器的末尾。

# 20. 容器任何、全部、无

编写一组通用函数，使其能够检查给定容器中是否存在任何、全部或任何指定参数。这些函数应该使得能够编写以下代码成为可能：

```cpp
std::vector<int> v{ 1, 2, 3, 4, 5, 6 };
assert(contains_any(v, 0, 3, 30));

std::array<int, 6> a{ { 1, 2, 3, 4, 5, 6 } };
assert(contains_all(a, 1, 3, 5, 6));

std::list<int> l{ 1, 2, 3, 4, 5, 6 };
assert(!contains_none(l, 0, 6));
```

# 21. 系统句柄包装器

考虑一个操作系统句柄，例如文件句柄。编写一个包装器，处理句柄的获取和释放，以及其他操作，如验证句柄的有效性和从一个对象移动句柄所有权。

# 22. 各种温度标度的文字

编写一个小型库，使得能够以三种最常用的标度（摄氏度、华氏度和开尔文）表示温度，并在它们之间进行转换。该库必须使您能够以所有这些标度编写温度文字，例如`36.5_deg`表示摄氏度，`97.7_f`表示华氏度，`309.65_K`表示开尔文；对这些值执行操作；并在它们之间进行转换。

# 解决方案

以下是上述问题解决部分的解决方案。

# 15. IPv4 数据类型

该问题要求编写一个类来表示 IPv4 地址。这是一个 32 位值，通常以十进制点格式表示，例如`168.192.0.100`；它的每个部分都是一个 8 位值，范围从 0 到 255。为了方便表示和处理，我们可以使用四个`unsigned char`来存储地址值。这样的值可以从四个`unsigned char`或从一个`unsigned long`构造。为了能够直接从控制台（或任何其他输入流）读取值，并能够将值写入控制台（或任何其他输出流），我们必须重载`operator>>`和`operator<<`。以下清单显示了可以满足所请求功能的最小实现：

```cpp
class ipv4
{
   std::array<unsigned char, 4> data;
public:
   constexpr ipv4() : data{ {0} } {}
   constexpr ipv4(unsigned char const a, unsigned char const b, 
                  unsigned char const c, unsigned char const d):
      data{{a,b,c,d}} {}
   explicit constexpr ipv4(unsigned long a) :
      data{ { static_cast<unsigned char>((a >> 24) & 0xFF), 
              static_cast<unsigned char>((a >> 16) & 0xFF),
              static_cast<unsigned char>((a >> 8) & 0xFF),
              static_cast<unsigned char>(a & 0xFF) } } {}
   ipv4(ipv4 const & other) noexcept : data(other.data) {}
   ipv4& operator=(ipv4 const & other) noexcept 
   {
      data = other.data;
      return *this;
   }

   std::string to_string() const
   {
      std::stringstream sstr;
      sstr << *this;
      return sstr.str();
   }

   constexpr unsigned long to_ulong() const noexcept
   {
      return (static_cast<unsigned long>(data[0]) << 24) |
             (static_cast<unsigned long>(data[1]) << 16) |
             (static_cast<unsigned long>(data[2]) << 8) |
              static_cast<unsigned long>(data[3]);
   }

   friend std::ostream& operator<<(std::ostream& os, const ipv4& a)
   {
      os << static_cast<int>(a.data[0]) << '.' 
         << static_cast<int>(a.data[1]) << '.'
         << static_cast<int>(a.data[2]) << '.'
         << static_cast<int>(a.data[3]);
      return os;
   }

   friend std::istream& operator>>(std::istream& is, ipv4& a)
   {
      char d1, d2, d3;
      int b1, b2, b3, b4;
      is >> b1 >> d1 >> b2 >> d2 >> b3 >> d3 >> b4;
      if (d1 == '.' && d2 == '.' && d3 == '.')
         a = ipv4(b1, b2, b3, b4);
      else
         is.setstate(std::ios_base::failbit);
      return is;
   }
};
```

`ipv4`类可以如下使用：

```cpp
int main()
{
   ipv4 address(168, 192, 0, 1);
   std::cout << address << std::endl;

   ipv4 ip;
   std::cout << ip << std::endl;
   std::cin >> ip;
   if(!std::cin.fail())
      std::cout << ip << std::endl;
}
```

# 16. 在范围内枚举 IPv4 地址

为了能够在给定范围内枚举 IPv4 地址，首先应该能够比较 IPv4 值。因此，我们应该至少实现`operator<`，但以下清单包含所有比较运算符的实现：`==`、`!=`、`<`、`>`、`<=`和`>=`。此外，为了增加 IPv4 值，提供了前缀和后缀`operator++`的实现。以下代码是前一个问题中 IPv4 类的扩展：

```cpp
ipv4& operator++()
{
   *this = ipv4(1 + to_ulong());
   return *this;
}

ipv4& operator++(int)
{
   ipv4 result(*this);
   ++(*this);
   return *this;
}

friend bool operator==(ipv4 const & a1, ipv4 const & a2) noexcept
{
   return a1.data == a2.data;
}

friend bool operator!=(ipv4 const & a1, ipv4 const & a2) noexcept
{
   return !(a1 == a2);
}

friend bool operator<(ipv4 const & a1, ipv4 const & a2) noexcept
{
   return a1.to_ulong() < a2.to_ulong();
}

friend bool operator>(ipv4 const & a1, ipv4 const & a2) noexcept
{
   return a2 < a1;
}

friend bool operator<=(ipv4 const & a1, ipv4 const & a2) noexcept
{
   return !(a1 > a2);
}

friend bool operator>=(ipv4 const & a1, ipv4 const & a2) noexcept
{
   return !(a1 < a2);
}
```

通过对前一个问题中的`ipv4`类进行这些更改，我们可以编写以下程序：

```cpp
int main()
{
   std::cout << "input range: ";
   ipv4 a1, a2;
   std::cin >> a1 >> a2;
   if (a2 > a1)
   {
      for (ipv4 a = a1; a <= a2; a++)
      {
         std::cout << a << std::endl;
      }
   }
   else 
   {
      std::cerr << "invalid range!" << std::endl;
   }
}
```

# 17. 创建具有基本操作的 2D 数组

在看如何定义这样的结构之前，让我们考虑一下它的几个测试用例。以下片段显示了所有请求的功能：

```cpp
int main()
{
   // element access
   array2d<int, 2, 3> a {1, 2, 3, 4, 5, 6};
   for (size_t i = 0; i < a.size(1); ++i)
      for (size_t j = 0; j < a.size(2); ++j)
      a(i, j) *= 2;

   // iterating
   std::copy(std::begin(a), std::end(a), 
      std::ostream_iterator<int>(std::cout, " "));

   // filling 
   array2d<int, 2, 3> b;
   b.fill(1);

   // swapping
   a.swap(b);

   // moving
   array2d<int, 2, 3> c(std::move(b));
}
```

请注意，对于元素访问，我们使用`operator()`，比如`a(i,j)`，而不是`operator[]`，比如`a[i][j]`，因为只有前者可以接受多个参数（每个维度的索引）。后者只能有一个参数，并且为了使表达式`a[i][j]`有效，它必须返回一个中间类型（基本上表示一行），然后再重载`operator[]`以返回单个元素。

已经有存储固定或可变长度元素序列的标准容器。这个二维数组类应该只是这样一个容器的适配器。在选择`std::array`和`std::vector`之间，我们应该考虑两件事：

+   `array2d`类应该具有移动语义，以便能够移动对象

+   应该可以使用列表初始化此类型的对象

`std::array`容器只有在其持有的元素是可移动构造和可移动分配时才可移动。另一方面，它不能从`std::initializer_list`构造。因此，更可行的选择仍然是`std::vector`。

在内部，此适配器容器可以将其数据存储在向量的向量中（每行是一个具有`C`个元素的`vector<T>`，而 2D 数组中有`R`个这样的元素存储在`vector<vector<T>>`中）或者类型为`T`的`R![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/mod-cpp/img/2f9ae4c1-380b-4377-84dd-a28429c062c5.png)C`元素的单个向量中。在后一种情况下，第`i`行和第`j`列的元素位于索引`i * C + j`处。这种方法具有较小的内存占用，将所有数据存储在单个连续块中，并且实现起来也更简单。因此，这是首选解决方案的原因。

这里展示了具有所请求功能的二维数组类的可能实现：

```cpp
template <class T, size_t R, size_t C>
class array2d
{
   typedef T                 value_type;
   typedef value_type*       iterator;
   typedef value_type const* const_iterator;
   std::vector<T>            arr;
public:
   array2d() : arr(R*C) {}
   explicit array2d(std::initializer_list<T> l):arr(l) {}
   constexpr T* data() noexcept { return arr.data(); }
   constexpr T const * data() const noexcept { return arr.data(); }

   constexpr T& at(size_t const r, size_t const c) 
   {
      return arr.at(r*C + c);
   }

   constexpr T const & at(size_t const r, size_t const c) const
   {
      return arr.at(r*C + c);
   }

   constexpr T& operator() (size_t const r, size_t const c)
   {
      return arr[r*C + c];
   }

   constexpr T const & operator() (size_t const r, size_t const c) const
   {
      return arr[r*C + c];
   }

   constexpr bool empty() const noexcept { return R == 0 || C == 0; }

   constexpr size_t size(int const rank) const
   {
      if (rank == 1) return R;
      else if (rank == 2) return C;
      throw std::out_of_range("Rank is out of range!");
   }

   void fill(T const & value)
   {
      std::fill(std::begin(arr), std::end(arr), value);
   }

   void swap(array2d & other) noexcept { arr.swap(other.arr); }

   const_iterator begin() const { return arr.data(); }
   const_iterator end() const   { return arr.data() + arr.size(); }
   iterator       begin()       { return arr.data(); }
   iterator       end()         { return arr.data() + arr.size(); }
};
```

# 18\. 具有任意数量参数的最小函数

可以使用可变函数模板编写可以接受可变数量参数的函数模板。为此，我们需要实现编译时递归（实际上只是通过一组重载函数进行调用）。以下片段显示了如何实现所请求的函数：

```cpp
template <typename T>
T minimum(T const a, T const b) { return a < b ? a : b; }

template <typename T1, typename... T>
T1 minimum(T1 a, T... args)
{
   return minimum(a, minimum(args...));
}

int main()
{
   auto x = minimum(5, 4, 2, 3);
}
```

为了能够使用用户提供的二进制比较函数，我们需要编写另一个函数模板。比较函数必须是第一个参数，因为它不能跟随函数参数包。另一方面，这不能是前一个最小函数的重载，而是具有不同名称的函数。原因是编译器无法区分模板参数列表`<typename T1, typename... T>`和`<class Compare, typename T1, typename... T>`。更改很小，应该很容易在此片段中跟踪：

```cpp
template <class Compare, typename T>
T minimumc(Compare comp, T const a, T const b) 
{ return comp(a, b) ? a : b; }

template <class Compare, typename T1, typename... T>
T1 minimumc(Compare comp, T1 a, T... args)
{
   return minimumc(comp, a, minimumc(comp, args...));
}

int main()
{
   auto y = minimumc(std::less<>(), 3, 2, 1, 0);
}
```

# 19\. 向容器添加一系列值

使用可变函数模板可以编写具有任意数量参数的函数。该函数应该将容器作为第一个参数，然后是表示要添加到容器后面的值的可变数量的参数。但是，使用折叠表达式可以显着简化编写这样的函数模板。这里展示了这样的实现：

```cpp
template<typename C, typename... Args>
void push_back(C& c, Args&&... args)
{
   (c.push_back(args), ...);
}
```

可以在以下清单中看到使用此函数模板的各种容器类型的示例：

```cpp
int main()
{
   std::vector<int> v;
   push_back(v, 1, 2, 3, 4);
   std::copy(std::begin(v), std::end(v), 
             std::ostream_iterator<int>(std::cout, " "));

   std::list<int> l;
   push_back(l, 1, 2, 3, 4);
   std::copy(std::begin(l), std::end(l), 
             std::ostream_iterator<int>(std::cout, " "));
}
```

# 20\. 容器任何，全部，无

能够检查变量数量的存在或不存在的要求表明，我们应该编写可变函数模板。然而，这些函数需要一个辅助函数，一个通用的函数，用于检查元素是否在容器中找到，并返回一个`bool`来指示成功或失败。由于所有这些函数，我们可以称之为`contains_all`，`contains_any`和`contains_none`，都是对辅助函数返回的结果应用逻辑运算符，我们将使用折叠表达式来简化代码。在折叠表达式扩展后启用短路评估，这意味着我们只评估导致明确结果的元素。因此，如果我们正在寻找所有 1、2 和 3 的存在，并且 2 缺失，那么在查找容器中的值 2 时，函数将返回而不检查值 3：

```cpp
template<class C, class T>
bool contains(C const & c, T const & value)
{
   return std::end(c) != std::find(std::begin(c), std::end(c), value);
}

template<class C, class... T>
bool contains_any(C const & c, T &&... value)
{
   return (... || contains(c, value));
}

template<class C, class... T>
bool contains_all(C const & c, T &&... value)
{
   return (... && contains(c, value));
}

template<class C, class... T>
bool contains_none(C const & c, T &&... value)
{
   return !contains_any(c, std::forward<T>(value)...);
}
```

# 21. 系统句柄包装器

系统句柄是对系统资源的引用形式。因为所有操作系统最初至少是用 C 编写的，所以创建和释放句柄是通过专用系统函数完成的。这增加了因错误处理而导致资源泄漏的风险，例如在异常情况下。在下面的代码片段中，特定于 Windows，您可以看到一个函数，在该函数中打开文件，从中读取，并最终关闭。然而，这有一些问题：在一个情况下，开发人员忘记在离开函数之前关闭句柄；在另一种情况下，在句柄正确关闭之前调用了一个抛出异常的函数，而没有捕获异常。然而，由于函数抛出异常，清理代码永远不会执行：

```cpp
void bad_handle_example()
{
   bool condition1 = false;
   bool condition2 = true;
   HANDLE handle = CreateFile(L"sample.txt",
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              nullptr);

   if (handle == INVALID_HANDLE_VALUE)
      return;

   if (condition1)
   {
      CloseHandle(handle);
      return;
   }

   std::vector<char> buffer(1024);
   unsigned long bytesRead = 0;
   ReadFile(handle, 
            buffer.data(), 
            buffer.size(), 
            &bytesRead, 
            nullptr);

   if (condition2)
   {
      // oops, forgot to close handle
      return;
   }

   // throws exception; the next line will not execute
   function_that_throws();

   CloseHandle(handle);
}
```

C++包装类可以确保在包装对象超出范围并被销毁时正确处理句柄（无论是通过正常执行路径还是作为异常的结果）。一个合适的实现应该考虑不同类型的句柄，以及一系列值来指示无效句柄（如 0/null 或-1）。下面显示的实现提供了：

+   在对象被销毁时显式获取和自动释放句柄

+   移动语义以实现句柄所有权的转移

+   比较运算符用于检查两个对象是否引用相同的句柄

+   其他操作，如交换和重置

这里展示的实现是 Kenny Kerr 实现的句柄类的修改版本，并发表在 2011 年 7 月的 MSDN 杂志文章*Windows with C++ - C++ and the Windows API*中，[`msdn.microsoft.com/en-us/magazine/hh288076.aspx`](https://msdn.microsoft.com/en-us/magazine/hh288076.aspx)。尽管这里显示的句柄特性是指 Windows 句柄，但编写适用于其他平台的特性应该是相当简单的。

```cpp
template <typename Traits>
class unique_handle
{
   using pointer = typename Traits::pointer;
   pointer m_value;
public:
   unique_handle(unique_handle const &) = delete;
   unique_handle& operator=(unique_handle const &) = delete;

   explicit unique_handle(pointer value = Traits::invalid()) noexcept
      :m_value{ value }
   {}

   unique_handle(unique_handle && other) noexcept
      : m_value{ other.release() }
   {}

   unique_handle& operator=(unique_handle && other) noexcept
   {
      if (this != &other)
         reset(other.release());
      return *this;
   }

   ~unique_handle() noexcept
   {
      Traits::close(m_value);
   }

   explicit operator bool() const noexcept
   {
      return m_value != Traits::invalid();
   }

   pointer get() const noexcept { return m_value; }

   pointer release() noexcept
   {
      auto value = m_value;
      m_value = Traits::invalid();
      return value;
   }

   bool reset(pointer value = Traits::invalid()) noexcept
   {
      if (m_value != value)
      {
         Traits::close(m_value);
         m_value = value;
      }
      return static_cast<bool>(*this);
   }

   void swap(unique_handle<Traits> & other) noexcept
   {
      std::swap(m_value, other.m_value);
   }
};

template <typename Traits>
void swap(unique_handle<Traits> & left, unique_handle<Traits> & right) noexcept
{
   left.swap(right);
}

template <typename Traits>
bool operator==(unique_handle<Traits> const & left,
                unique_handle<Traits> const & right) noexcept
{
   return left.get() == right.get();
}

template <typename Traits>
bool operator!=(unique_handle<Traits> const & left,
                unique_handle<Traits> const & right) noexcept
{
   return left.get() != right.get();
}

struct null_handle_traits
{
   using pointer = HANDLE;
   static pointer invalid() noexcept { return nullptr; }
   static void close(pointer value) noexcept
   {
      CloseHandle(value);
   }
};

struct invalid_handle_traits
{
   using pointer = HANDLE;
   static pointer invalid() noexcept { return INVALID_HANDLE_VALUE; }
   static void close(pointer value) noexcept
   {
      CloseHandle(value);
   }
};

using null_handle = unique_handle<null_handle_traits>;
using invalid_handle = unique_handle<invalid_handle_traits>;
```

有了这种句柄类型的定义，我们可以用更简单的术语重写先前的示例，避免所有那些因为异常而未正确关闭句柄的问题，这些异常发生时没有得到正确处理，或者仅仅是因为开发人员忘记在不再需要时释放资源。这段代码既更简单又更健壮：

```cpp
void good_handle_example()
{
   bool condition1 = false;
   bool condition2 = true;

   invalid_handle handle{
      CreateFile(L"sample.txt",
                 GENERIC_READ,
                 FILE_SHARE_READ,
                 nullptr,
                 OPEN_EXISTING,
                 FILE_ATTRIBUTE_NORMAL,
                 nullptr) };

   if (!handle) return;

   if (condition1) return;

   std::vector<char> buffer(1024);
   unsigned long bytesRead = 0;
   ReadFile(handle.get(),
            buffer.data(),
            buffer.size(),
            &bytesRead,
            nullptr);

   if (condition2) return;

   function_that_throws();
}
```

# 22. 各种温度标度的文字

为了满足这一要求，我们需要为多种类型、运算符和函数提供实现：

+   称为`scale`的支持温度标度的枚举。

+   一个类模板，用于表示温度值，参数化为`quantity`，称为`quantity`。

+   比较运算符`==`、`!=`、`<`、`>`、`<=`和`>=`，用于比较相同类型的两个数量。

+   算术运算符`+`和`-`用于添加和减去相同类型的值。此外，我们可以实现成员运算符`+=`和`-+`。

+   一个函数模板，用于将温度从一种标度转换为另一种，称为`temperature_cast`。这个函数本身不执行转换，而是使用类型特性来执行转换。

+   用于创建用户定义的温度字面量的文字操作符`""_deg`，`""_f`和`""_k`。

为了简洁起见，以下代码片段仅包含处理摄氏度和华氏度温度的代码。您应该将其视为进一步练习，以扩展代码以支持开尔文标度。附带书籍的代码包含了所有三个所需标度的完整实现。

`are_equal()`函数是一个用于比较浮点值的实用函数：

```cpp
bool are_equal(double const d1, double const d2, 
               double const epsilon = 0.001)
{
   return std::fabs(d1 - d2) < epsilon;
}
```

可能的温度标度的枚举和表示温度值的类定义如下：

```cpp
namespace temperature
{
   enum class scale { celsius, fahrenheit, kelvin };

   template <scale S>
   class quantity
   {
      const double amount;
   public:
      constexpr explicit quantity(double const a) : amount(a) {}
      explicit operator double() const { return amount; }
   };
}
```

`quantity<S>`类的比较操作符可以在这里看到：

```cpp
namespace temperature 
{
   template <scale S>
   inline bool operator==(quantity<S> const & lhs, quantity<S> const & rhs)
   {
      return are_equal(static_cast<double>(lhs), static_cast<double>(rhs));
   }

   template <scale S>
   inline bool operator!=(quantity<S> const & lhs, quantity<S> const & rhs)
   {
      return !(lhs == rhs);
   }

   template <scale S>
   inline bool operator< (quantity<S> const & lhs, quantity<S> const & rhs)
   {
      return static_cast<double>(lhs) < static_cast<double>(rhs);
   }

   template <scale S>
   inline bool operator> (quantity<S> const & lhs, quantity<S> const & rhs)
   {
      return rhs < lhs;
   }

   template <scale S>
   inline bool operator<=(quantity<S> const & lhs, quantity<S> const & rhs)
   {
      return !(lhs > rhs);
   }

   template <scale S>
   inline bool operator>=(quantity<S> const & lhs, quantity<S> const & rhs)
   {
      return !(lhs < rhs);
   }

   template <scale S>
   constexpr quantity<S> operator+(quantity<S> const &q1, 
                                   quantity<S> const &q2)
   {
      return quantity<S>(static_cast<double>(q1) + 
                         static_cast<double>(q2));
   }

   template <scale S>
   constexpr quantity<S> operator-(quantity<S> const &q1, 
                                   quantity<S> const &q2)
   {
      return quantity<S>(static_cast<double>(q1) - 
                         static_cast<double>(q2));
   }
}
```

为了在不同温度标度之间进行转换，我们将定义一个名为`temperature_cast()`的函数模板，该函数利用了几个类型特征来执行实际的转换。所有这些都在这里显示，尽管并非所有类型特征；其他类型特征可以在附带书籍的代码中找到：

```cpp
namespace temperature
{
   template <scale S, scale R>
   struct conversion_traits
   {
      static double convert(double const value) = delete;
   };

   template <>
   struct conversion_traits<scale::celsius, scale::fahrenheit>
   {
      static double convert(double const value)
      {
         return (value * 9) / 5 + 32;
      }
   };

   template <>
   struct conversion_traits<scale::fahrenheit, scale::celsius>
   {
      static double convert(double const value)
      {
         return (value - 32) * 5 / 9;
      }
   };

   template <scale R, scale S>
   constexpr quantity<R> temperature_cast(quantity<S> const q)
   {
      return quantity<R>(conversion_traits<S, R>::convert(
         static_cast<double>(q)));
   }
}
```

用于创建温度值的文字操作符显示在以下代码片段中。这些操作符定义在一个名为`temperature_scale_literals`的单独命名空间中，这是一种良好的做法，以减少与其他文字操作符的名称冲突的风险：

```cpp
namespace temperature
{
   namespace temperature_scale_literals
   {
      constexpr quantity<scale::celsius> operator "" _deg(
         long double const amount)
      {
         return quantity<scale::celsius> {static_cast<double>(amount)};
      }

      constexpr quantity<scale::fahrenheit> operator "" _f(
         long double const amount)
      {
         return quantity<scale::fahrenheit> {static_cast<double>(amount)};
      }
   }
}
```

以下示例显示了如何定义两个温度值，一个是摄氏度，一个是华氏度，并在两者之间进行转换：

```cpp
int main()
{
   using namespace temperature;
   using namespace temperature_scale_literals;

   auto t1{ 36.5_deg };
   auto t2{ 79.0_f };

   auto tf = temperature_cast<scale::fahrenheit>(t1);
   auto tc = temperature_cast<scale::celsius>(tf);
   assert(t1 == tc);
}
```


# 第十四章：字符串和正则表达式

# 问题

这是本章的问题解决部分。

# 23\. 二进制转字符串

编写一个函数，给定一个 8 位整数范围（例如数组或向量），返回一个包含输入数据十六进制表示的字符串。该函数应能够产生大写和小写内容。以下是一些输入和输出示例：

输入：`{ 0xBA, 0xAD, 0xF0, 0x0D }`，输出：`"BAADF00D"`或`"baadf00d"`

输入：`{ 1,2,3,4,5,6 }`，输出：`"010203040506"`

# 24\. 字符串转二进制

编写一个函数，给定一个包含十六进制数字的字符串作为输入参数，返回表示字符串内容的数值反序列化的 8 位整数向量。以下是示例：

输入：`"BAADF00D"`或`"baadF00D"`，输出：`{0xBA, 0xAD, 0xF0, 0x0D}`

输入`"010203040506"`，输出：`{1, 2, 3, 4, 5, 6}`

# 25\. 文章标题大写

编写一个函数，将输入文本转换为大写版本，其中每个单词以大写字母开头，其他所有字母都是小写。例如，文本`"the c++ challenger"`应转换为`"The C++ Challenger"`。

# 26\. 用分隔符连接字符串

编写一个函数，给定一个字符串列表和一个分隔符，通过连接所有输入字符串并用指定的分隔符分隔，创建一个新字符串。分隔符不得出现在最后一个字符串之后，当没有提供输入字符串时，函数必须返回一个空字符串。

示例：输入`{ "this","is","an","example" }`和分隔符`' '`（空格），输出：`"this is an example"`。

# 27\. 使用可能的分隔符将字符串拆分为标记

编写一个函数，给定一个字符串和可能的分隔符字符列表，将字符串分割成由任何分隔符分隔的标记，并将它们返回到一个`std::vector`中。

示例：输入：`"this,is.a sample!!"`，使用分隔符`",.! "`，输出：`{"this", "is", "a", "sample"}`。

# 28\. 最长回文子串

编写一个函数，给定输入字符串，找到并返回字符串中最长的回文序列。如果存在相同长度的多个回文序列，则应返回第一个。

# 29\. 车牌验证

考虑格式为`LLL-LL DDD`或`LLL-LL DDDD`（其中`L`是从*A*到*Z*的大写字母，`D`是数字）的车牌，编写：

+   一个验证车牌号是否为正确格式的函数

+   一个函数，给定输入文本，提取并返回文本中找到的所有车牌号

# 30\. 提取 URL 部分

编写一个函数，给定表示 URL 的字符串，解析并提取 URL 的各个部分（协议、域名、端口、路径、查询和片段）。

# 31\. 转换字符串中的日期

编写一个函数，给定一个包含格式为`dd.mm.yyyy`或`dd-mm-yyyy`的日期的文本，将文本转换为包含格式为`yyyy-mm-dd`的日期。

# 解决方案

这是上述问题解决部分的解决方案。

# 23\. 二进制转字符串

为了编写一个通用的函数，可以处理各种范围，如`std::array`、`std::vector`、类 C 数组或其他范围，我们应该编写一个函数模板。在下面，有两个重载；一个接受一个容器作为参数和一个标志，指示大小写风格，另一个接受一对迭代器（标记范围的第一个元素和最后一个元素的后一个元素）和指示大小写的标志。范围的内容被写入一个`std::ostringstream`对象，使用适当的 I/O 操纵器，如宽度、填充字符或大小写标志：

```cpp
template <typename Iter>
std::string bytes_to_hexstr(Iter begin, Iter end, 
                            bool const uppercase = false)
{
   std::ostringstream oss;
   if(uppercase) oss.setf(std::ios_base::uppercase);
   for (; begin != end; ++begin)
     oss << std::hex << std::setw(2) << std::setfill('0') 
         << static_cast<int>(*begin);
   return oss.str();
}

template <typename C>
std::string bytes_to_hexstr(C const & c, bool const uppercase = false)
{
   return bytes_to_hexstr(std::cbegin(c), std::cend(c), uppercase);
}
```

这些函数可以如下使用：

```cpp
int main()
{
   std::vector<unsigned char> v{ 0xBA, 0xAD, 0xF0, 0x0D };
   std::array<unsigned char, 6> a{ {1,2,3,4,5,6} };
   unsigned char buf[5] = {0x11, 0x22, 0x33, 0x44, 0x55};

   assert(bytes_to_hexstr(v, true) == "BAADF00D");
   assert(bytes_to_hexstr(a, true) == "010203040506");
   assert(bytes_to_hexstr(buf, true) == "1122334455");

   assert(bytes_to_hexstr(v) == "baadf00d");
   assert(bytes_to_hexstr(a) == "010203040506");
   assert(bytes_to_hexstr(buf) == "1122334455");
}
```

# 24\. 字符串转二进制

这里请求的操作与前一个问题中实现的相反。然而，这一次，我们可以编写一个函数而不是一个函数模板。输入是一个`std::string_view`，它是一个字符序列的轻量级包装器。输出是一个 8 位无符号整数的向量。下面的`hexstr_to_bytes`函数将每两个文本字符转换为一个`unsigned char`值（`"A0"`变成`0xA0`），将它们放入一个`std::vector`中，并返回该向量：

```cpp
unsigned char hexchar_to_int(char const ch)
{
   if (ch >= '0' && ch <= '9') return ch - '0';
   if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
   if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
      throw std::invalid_argument("Invalid hexadecimal character");
}

std::vector<unsigned char> hexstr_to_bytes(std::string_view str)
{
   std::vector<unsigned char> result;
   for (size_t i = 0; i < str.size(); i += 2) 
   {
      result.push_back(
         (hexchar_to_int(str[i]) << 4) | hexchar_to_int(str[i+1]));
   }
   return result;
}
```

这个函数假设输入字符串包含偶数个十六进制数字。在输入字符串包含奇数个十六进制数字的情况下，最后一个将被丢弃（所以`"BAD"`变成了`{0xBA}`）。作为进一步的练习，修改前面的函数，使得它不是丢弃最后一个奇数位，而是考虑一个前导零，这样`"BAD"`就变成了`{0x0B, 0xAD}`。另外，作为另一个练习，您可以编写一个函数的版本，它可以反序列化内容，其中十六进制数字由分隔符分隔，比如空格（例如`"BA AD F0 0D"`）。

下一个代码示例显示了如何使用这个函数：

```cpp
int main()
{
   std::vector<unsigned char> expected{ 0xBA, 0xAD, 0xF0, 0x0D, 0x42 };
   assert(hexstr_to_bytes("BAADF00D42") == expected);
   assert(hexstr_to_bytes("BaaDf00d42") == expected);
}
```

# 25\. 将文章标题大写

函数模板`capitalize()`，实现如下，可以处理任何类型字符的字符串。它不修改输入字符串，而是创建一个新的字符串。为此，它使用一个`std::stringstream`。它遍历输入字符串中的所有字符，并在遇到空格或标点符号时将指示新单词的标志设置为`true`。当它们表示一个单词中的第一个字符时，输入字符被转换为大写，否则转换为小写：

```cpp
template <class Elem>
using tstring = std::basic_string<Elem, std::char_traits<Elem>, 
                                  std::allocator<Elem>>;
template <class Elem>
using tstringstream = std::basic_stringstream<
   Elem, std::char_traits<Elem>, std::allocator<Elem>>;

template <class Elem>
tstring<Elem> capitalize(tstring<Elem> const & text)
{
   tstringstream<Elem> result;
   bool newWord = true;
   for (auto const ch : text)
   {
      newWord = newWord || std::ispunct(ch) || std::isspace(ch);
      if (std::isalpha(ch))
      {
         if (newWord)
         {
            result << static_cast<Elem>(std::toupper(ch));
            newWord = false;
         }
         else
            result << static_cast<Elem>(std::tolower(ch));
      }
      else result << ch;
   }
   return result.str();
}
```

在下面的程序中，您可以看到如何使用这个函数来大写文本：

```cpp
int main()
{
   using namespace std::string_literals;
   assert("The C++ Challenger"s ==
          capitalize("the c++ challenger"s));
   assert("This Is An Example, Should Work!"s == 
          capitalize("THIS IS an ExamplE, should wORk!"s));
}
```

# 26\. 用分隔符连接字符串

以下代码中列出了两个名为`join_strings()`的重载。一个接受一个字符串容器和一个表示分隔符的字符序列的指针，而另一个接受两个随机访问迭代器，表示范围的第一个和最后一个元素，以及一个分隔符。它们都返回一个通过连接所有输入字符串创建的新字符串，使用输出字符串流和`std::copy`函数。这个通用函数将指定范围中的所有元素复制到一个输出范围中，由输出迭代器表示。我们在这里使用了一个`std::ostream_iterator`，它使用`operator<<`每次迭代器被赋予一个值时将指定的值写入指定的输出流： 

```cpp
template <typename Iter>
std::string join_strings(Iter begin, Iter end, 
                         char const * const separator)
{
   std::ostringstream os;
   std::copy(begin, end-1, 
             std::ostream_iterator<std::string>(os, separator));
   os << *(end-1);
   return os.str();
}

template <typename C>
std::string join_strings(C const & c, char const * const separator)
{
   if (c.size() == 0) return std::string{};
   return join_strings(std::begin(c), std::end(c), separator);
}

int main()
{
   using namespace std::string_literals;
   std::vector<std::string> v1{ "this","is","an","example" };
   std::vector<std::string> v2{ "example" };
   std::vector<std::string> v3{ };

   assert(join_strings(v1, " ") == "this is an example"s);
   assert(join_strings(v2, " ") == "example"s);
   assert(join_strings(v3, " ") == ""s);
}
```

作为进一步的练习，您应该修改接受迭代器作为参数的重载，以便它可以与其他类型的迭代器一起工作，比如双向迭代器，从而使得可以使用这个函数与列表或其他容器一起使用。

# 27\. 使用可能的分隔符列表将字符串拆分为标记

两种不同版本的拆分函数如下所示：

+   第一个使用单个字符作为分隔符。为了拆分输入字符串，它使用一个字符串流，该字符串流初始化为输入字符串的内容，使用`std::getline()`从中读取块，直到遇到下一个分隔符或行尾字符。

+   第二个版本使用了一个可能的字符分隔符列表，指定在`std::string`中。它使用`std:string::find_first_of()`来定位从给定位置开始的任何分隔符字符的第一个位置。它在循环中这样做，直到整个输入字符串被处理。提取的子字符串被添加到结果向量中：

```cpp
template <class Elem>
using tstring = std::basic_string<Elem, std::char_traits<Elem>, 
                                  std::allocator<Elem>>;

template <class Elem>
using tstringstream = std::basic_stringstream<
   Elem, std::char_traits<Elem>, std::allocator<Elem>>;
template<typename Elem>
inline std::vector<tstring<Elem>> split(tstring<Elem> text, 
                                        Elem const delimiter)
{
   auto sstr = tstringstream<Elem>{ text };
   auto tokens = std::vector<tstring<Elem>>{};
   auto token = tstring<Elem>{};
   while (std::getline(sstr, token, delimiter))
   {
      if (!token.empty()) tokens.push_back(token);
   }
   return tokens;
}

template<typename Elem>
inline std::vector<tstring<Elem>> split(tstring<Elem> text, 
                                        tstring<Elem> const & delimiters)
{
   auto tokens = std::vector<tstring<Elem>>{};
   size_t pos, prev_pos = 0;
   while ((pos = text.find_first_of(delimiters, prev_pos)) != 
   std::string::npos)
   {
      if (pos > prev_pos)
      tokens.push_back(text.substr(prev_pos, pos - prev_pos));
      prev_pos = pos + 1;
   }
   if (prev_pos < text.length())
   tokens.push_back(text.substr(prev_pos, std::string::npos));
   return tokens;
}
```

下面的示例代码显示了如何使用一个分隔符字符或多个分隔符来拆分不同的字符串的两个示例：

```cpp
int main()
{
   using namespace std::string_literals;
   std::vector<std::string> expected{"this", "is", "a", "sample"};
   assert(expected == split("this is a sample"s, ' '));
   assert(expected == split("this,is a.sample!!"s, ",.! "s));
}
```

# 28\. 最长回文子字符串

解决这个问题的最简单方法是尝试蛮力方法，检查每个子字符串是否为回文。然而，这意味着我们需要检查*C(N, 2)*个子字符串（其中*N*是字符串中的字符数），时间复杂度将是*![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/mod-cpp/img/76505ab6-7d29-4aab-9955-744ed0bcd1b6.png)*。通过存储子问题的结果，复杂度可以降低到*![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/mod-cpp/img/2f7e78fe-014a-40b2-9524-bc0f479781a1.png)*。为此，我们需要一个大小为![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/mod-cpp/img/a4173824-4963-42ca-b9ab-fd97affe7750.png)的布尔值表，其中`[i, j]`处的元素指示位置`i`到`j`的子字符串是否为回文。我们首先通过将所有`[i,i]`处的元素初始化为`true`（单字符回文）和所有`[i,i+i]`处的元素初始化为`true`（所有连续两个相同字符的两字符回文）来开始。然后，我们继续检查大于两个字符的子字符串，如果`[i+i,j-1]`处的元素为`true`且字符串中位置`i`和`j`的字符也相等，则将`[i,j]`处的元素设置为`true`。在此过程中，我们保留最长回文子字符串的起始位置和长度，以便在完成计算表后提取它。

在代码中，这个解决方案如下所示：

```cpp
std::string longest_palindrome(std::string_view str)
{
   size_t const len = str.size();
   size_t longestBegin = 0;
   size_t maxLen = 1;

   std::vector<bool> table(len * len, false);
   for (size_t i = 0; i < len; i++)
      table[i*len + i] = true;

   for (size_t i = 0; i < len - 1; i++)
   {
      if (str[i] == str[i + 1]) 
      {
         table[i*len + i + 1] = true;
         if (maxLen < 2)
         {
            longestBegin = i;
            maxLen = 2;
         }
      }
   }

   for (size_t k = 3; k <= len; k++)
   {
      for (size_t i = 0; i < len - k + 1; i++)
      {
         size_t j = i + k - 1;
         if (str[i] == str[j] && table[(i + 1)*len + j - 1])
         {
            table[i*len +j] = true;
            if (maxLen < k)
            {
               longestBegin = i;
               maxLen = k;
            }
         }
      }
   }
   return std::string(str.substr(longestBegin, maxLen));
}
```

以下是`longest_palindrome()`函数的一些测试用例：

```cpp
int main()
{
   using namespace std::string_literals;
   assert(longest_palindrome("sahararahnide") == "hararah");
   assert(longest_palindrome("level") == "level");
   assert(longest_palindrome("s") == "s");
}
```

# 29\. 验证车牌

解决这个问题的最简单方法是使用正则表达式。符合描述格式的正则表达式是`"[A-Z]{3}-[A-Z]{2} \d{3,4}"`。

第一个函数只需验证输入字符串是否只包含与此正则表达式匹配的文本。为此，我们可以使用`std::regex_match()`，如下所示：

```cpp
bool validate_license_plate_format(std::string_view str)
{
   std::regex rx(R"([A-Z]{3}-[A-Z]{2} \d{3,4})");
   return std::regex_match(str.data(), rx);
}

int main()
{
   assert(validate_license_plate_format("ABC-DE 123"));
   assert(validate_license_plate_format("ABC-DE 1234"));
   assert(!validate_license_plate_format("ABC-DE 12345"));
   assert(!validate_license_plate_format("abc-de 1234"));
}
```

第二个函数略有不同。它不是匹配输入字符串，而是必须识别字符串中正则表达式的所有出现。因此，正则表达式将更改为`"([A-Z]{3}-[A-Z]{2} \d{3,4})*"`。要遍历所有匹配项，我们必须使用`std::sregex_iterator`，如下所示：

```cpp
std::vector<std::string> extract_license_plate_numbers(
                            std::string const & str)
{
   std::regex rx(R"(([A-Z]{3}-[A-Z]{2} \d{3,4})*)");
   std::smatch match;
   std::vector<std::string> results;

   for(auto i = std::sregex_iterator(std::cbegin(str), std::cend(str), rx); 
       i != std::sregex_iterator(); ++i) 
   {
      if((*i)[1].matched)
      results.push_back(i->str());
   }
   return results;
}

int main()
{
   std::vector<std::string> expected {
      "AAA-AA 123", "ABC-DE 1234", "XYZ-WW 0001"};
   std::string text("AAA-AA 123qwe-ty 1234 ABC-DE 123456..XYZ-WW 0001");
   assert(expected == extract_license_plate_numbers(text));
}
```

# 30\. 提取 URL 部分

这个问题也适合使用正则表达式来解决。然而，找到一个可以匹配任何 URL 的正则表达式是一个困难的任务。这个练习的目的是帮助您练习正则表达式库的技能，而不是找到特定目的的终极正则表达式。因此，这里使用的正则表达式仅供教学目的。

您可以使用在线测试器和调试器，如[`regex101.com/`](https://regex101.com/)，尝试正则表达式。这可以帮助您解决正则表达式并针对各种数据集尝试它们。

对于此任务，我们将认为 URL 具有以下部分：`protocol`和`domain`是必需的，而`port`、`path`、`query`和`fragment`都是可选的。以下结构用于从解析 URL 返回结果（或者，您可以返回一个元组，并使用结构化绑定将变量绑定到元组的各个子部分）：

```cpp
struct uri_parts
{
   std::string                protocol;
   std::string                domain;
   std::optional<int>         port;
   std::optional<std::string> path;
   std::optional<std::string> query;
   std::optional<std::string> fragment;
};
```

可以解析 URL 并提取并返回其部分的函数可能具有以下实现。请注意，返回类型是`std::optional<uri_parts>`，因为该函数可能无法将输入字符串与正则表达式匹配；在这种情况下，返回值为`std::nullopt`：

```cpp
std::optional<uri_parts> parse_uri(std::string uri)
{
   std::regex rx(R"(^(\w+):\/\/([\w.-]+)(:(\d+))?([\w\/\.]+)?(\?([\w=&]*)(#?(\w+))?)?$)");
   auto matches = std::smatch{};
   if (std::regex_match(uri, matches, rx))
   {
      if (matches[1].matched && matches[2].matched)
      {
         uri_parts parts;
         parts.protocol = matches[1].str();
         parts.domain = matches[2].str();
         if (matches[4].matched)
            parts.port = std::stoi(matches[4]);
         if (matches[5].matched)
            parts.path = matches[5];
         if (matches[7].matched)
            parts.query = matches[7];
         if (matches[9].matched)
            parts.fragment = matches[9];
         return parts;
      }
   }
   return {};
}
```

以下程序使用包含不同部分的两个 URL 测试`parse_uri()`函数：

```cpp
int main()
{
   auto p1 = parse_uri("https://packt.com");
   assert(p1.has_value());
   assert(p1->protocol == "https");
   assert(p1->domain == "packt.com");
   assert(!p1->port.has_value());
   assert(!p1->path.has_value());
   assert(!p1->query.has_value());
   assert(!p1->fragment.has_value());

   auto p2 = parse_uri("https://bbc.com:80/en/index.html?lite=true#ui");
   assert(p2.has_value());
   assert(p2->protocol == "https");
   assert(p2->domain == "bbc.com");
   assert(p2->port == 80);
   assert(p2->path.value() == "/en/index.html");
   assert(p2->query.value() == "lite=true");
   assert(p2->fragment.value() == "ui");
}
```

# 31\. 将字符串中的日期转换

可以使用`std::regex_replace()`和正则表达式执行文本转换。可以匹配指定格式日期的正则表达式是`(\d{1,2})(\.|-|/)(\d{1,2})(\.|-|/)(\d{4})`。这个正则表达式定义了五个捕获组；第一个是日期，第二个是分隔符（`.`或`-`），第三个是月份，第四个再次是分隔符（`.`或`-`），第五个是年份。

由于我们想要将日期从格式 `dd.mm.yyyy` 或 `dd-mm-yyyy` 转换为 `yyyy-mm-dd`，因此 `std::regex_replace()` 的正则表达式替换格式字符串应该是 `"($5-$3-$1)"`：

```cpp
std::string transform_date(std::string_view text)
{
   auto rx = std::regex{ R"((\d{1,2})(\.|-|/)(\d{1,2})(\.|-|/)(\d{4}))" };
   return std::regex_replace(text.data(), rx, R"($5-$3-$1)");
}

int main()
{
   using namespace std::string_literals;
   assert(transform_date("today is 01.12.2017!"s) == 
          "today is 2017-12-01!"s);
}
```


# 第十五章：流和文件系统

# 问题

这是本章的问题解决部分。

# 32\. 帕斯卡三角形

编写一个函数，将帕斯卡三角形的最多 10 行打印到控制台。

# 33\. 列出进程列表

假设您有系统中所有进程列表的快照。每个进程的信息包括名称、标识符、状态（可以是*运行*或*挂起*）、帐户名称（进程运行的帐户）、以字节为单位的内存大小和平台（可以是 32 位或 64 位）。您的任务是编写一个函数，该函数接受这样一个进程列表，并以表格格式按字母顺序将它们打印到控制台。所有列必须左对齐，除了内存列必须右对齐。内存大小的值必须以 KB 显示。以下是此函数的输出示例：

```cpp
chrome.exe      1044   Running    marius.bancila    25180  32-bit
chrome.exe      10100  Running    marius.bancila   227756  32-bit
cmd.exe         512    Running    SYSTEM               48  64-bit
explorer.exe    7108   Running    marius.bancila    29529  64-bit
skype.exe       22456  Suspended  marius.bancila      656  64-bit
```

# 34\. 从文本文件中删除空行

编写一个程序，给定文本文件的路径，通过删除所有空行来修改文件。只包含空格的行被视为空行。

# 35\. 计算目录的大小

编写一个函数，递归计算目录的大小（以字节为单位）。应该可以指示是否应该跟随符号链接。

# 36\. 删除早于给定日期的文件

编写一个函数，给定目录的路径和持续时间，以递归方式删除所有早于指定持续时间的条目（文件或子目录）。持续时间可以表示任何内容，例如天、小时、分钟、秒等，或这些的组合，例如一小时二十分钟。如果指定的目录本身早于给定的持续时间，则应完全删除它。

# 37\. 查找与正则表达式匹配的目录中的文件

编写一个函数，给定目录的路径和正则表达式，返回所有目录条目的列表，其名称与正则表达式匹配。

# 38\. 临时日志文件

创建一个日志类，将文本消息写入可丢弃的文本文件。文本文件应具有唯一名称，并且必须位于临时目录中。除非另有说明，否则当类的实例被销毁时，应删除此日志文件。但是，可以通过将其移动到永久位置来保留日志文件。

# 解决方案

以下是上述问题解决部分的解决方案。

# 32\. 帕斯卡三角形

帕斯卡三角形是表示二项式系数的构造。三角形以一个具有单个值 1 的行开始。每行的元素是通过将上面、左边和右边的数字相加，并将空白条目视为 0 来构造的。以下是一个具有五行的三角形的示例：

```cpp
 1
 1   1
 1   2   1
 1   3   3   1
1   4   6   4   1
```

要打印三角形，我们必须：

+   将输出位置向右移动适当数量的空格，以便顶部投影在三角形底部的中间。

+   通过对上述左值和右值求和来计算每个值。一个更简单的公式是，对于第`i`行和第`j`列，每个新值`x`等于前一个值`x`乘以`(i - j) / (j + 1)`，其中`x`从 1 开始。

以下是一个可能的打印三角形的函数实现：

```cpp
unsigned int number_of_digits(unsigned int const i)
{
   return i > 0 ? (int)log10((double)i) + 1 : 1;
}

void print_pascal_triangle(int const n)
{
   for (int i = 0; i < n; i++) 
   {
      auto x = 1;
      std::cout << std::string((n - i - 1)*(n / 2), ' ');
      for (int j = 0; j <= i; j++) 
      {
         auto y = x;
         x = x * (i - j) / (j + 1);
         auto maxlen = number_of_digits(x) - 1;
         std::cout << y << std::string(n - 1 - maxlen - n%2, ' ');
      }
      std::cout << std::endl;
   }
}
```

以下程序要求用户输入级别的数量，并将三角形打印到控制台：

```cpp
int main()
{
   int n = 0;
   std::cout << "Levels (up to 10): ";
   std::cin >> n;
   if (n > 10)
      std::cout << "Value too large" << std::endl;
   else
      print_pascal_triangle(n);
}
```

# 33\. 列出进程列表

为了解决这个问题，我们将考虑以下表示有关进程信息的类：

```cpp
enum class procstatus {suspended, running};
enum class platforms {p32bit, p64bit};

struct procinfo
{
   int         id;
   std::string name;
   procstatus  status;
   std::string account;
   size_t      memory;
   platforms   platform;
};
```

为了将状态和平台以文本形式而不是数值形式打印出来，我们需要从枚举到`std::string`的转换函数：

```cpp
std::string status_to_string(procstatus const status)
{
   if (status == procstatus::suspended) return "suspended";
   else return "running";
}

std::string platform_to_string(platforms const platform)
{
   if (platform == platforms::p32bit) return "32-bit";
   else return "64-bit";
}
```

需要按进程名称按字母顺序排序进程。因此，第一步是对进程的输入范围进行排序。对于打印本身，我们应该使用 I/O 操纵符：

```cpp
void print_processes(std::vector<procinfo> processes)
{
   std::sort(
      std::begin(processes), std::end(processes),
      [](procinfo const & p1, procinfo const & p2) {
         return p1.name < p2.name; });

   for (auto const & pi : processes)
   {
      std::cout << std::left << std::setw(25) << std::setfill(' ')
                << pi.name;
      std::cout << std::left << std::setw(8) << std::setfill(' ')
                << pi.id;
      std::cout << std::left << std::setw(12) << std::setfill(' ')
                << status_to_string(pi.status);
      std::cout << std::left << std::setw(15) << std::setfill(' ')
                << pi.account;
      std::cout << std::right << std::setw(10) << std::setfill(' ')
                << (int)(pi.memory/1024);
      std::cout << std::left << ' ' << platform_to_string(pi.platform);
      std::cout << std::endl;
   }
}
```

以下程序定义了一个进程列表（实际上可以使用特定于操作系统的 API 检索运行中的进程列表），并以请求的格式打印到控制台：

```cpp
int main()
{
   using namespace std::string_literals;

   std::vector<procinfo> processes
   {
      {512, "cmd.exe"s, procstatus::running, "SYSTEM"s, 
            148293, platforms::p64bit },
      {1044, "chrome.exe"s, procstatus::running, "marius.bancila"s, 
            25180454, platforms::p32bit},
      {7108, "explorer.exe"s, procstatus::running, "marius.bancila"s,  
            2952943, platforms::p64bit },
      {10100, "chrome.exe"s, procstatus::running, "marius.bancila"s, 
            227756123, platforms::p32bit},
      {22456, "skype.exe"s, procstatus::suspended, "marius.bancila"s, 
            16870123, platforms::p64bit }, 
   };

   print_processes(processes);
}
```

# 34. 从文本文件中删除空行

解决此任务的一种可能方法是执行以下操作：

1.  创建一个临时文件，其中只包含要保留的原始文件的文本

1.  从输入文件逐行读取并将不为空的行复制到临时文件中

1.  在处理完原始文件后删除它

1.  将临时文件移动到原始文件的路径

另一种方法是移动临时文件并覆盖原始文件。以下实现遵循列出的步骤。临时文件是在`filesystem::temp_directory_path()`返回的临时目录中创建的：

```cpp
namespace fs = std::experimental::filesystem;

void remove_empty_lines(fs::path filepath)
{
   std::ifstream filein(filepath.native(), std::ios::in);
   if (!filein.is_open())
      throw std::runtime_error("cannot open input file");

   auto temppath = fs::temp_directory_path() / "temp.txt";
   std::ofstream fileout(temppath.native(), 
   std::ios::out | std::ios::trunc);
   if (!fileout.is_open())
      throw std::runtime_error("cannot create temporary file");

   std::string line;
   while (std::getline(filein, line))
   {
      if (line.length() > 0 &&
      line.find_first_not_of(' ') != line.npos)
      {
         fileout << line << '\n';
      }
   }
   filein.close();
   fileout.close();

   fs::remove(filepath);
   fs::rename(temppath, filepath);
}
```

# 35. 计算目录的大小

要计算目录的大小，我们必须遍历所有文件并计算各个文件的大小之和。

`filesystem::recursive_directory_iterator`是`filesystem`库中的一个迭代器，允许以递归方式遍历目录的所有条目。它有各种构造函数，其中一些采用`filesystem::directory_options`类型的值，指示是否应该跟随符号链接。通用的`std::accumulate()`算法可以用于将文件大小总和在一起。由于目录的总大小可能超过 2GB，因此不应使用`int`或`long`，而应使用`unsigned long long`作为总和类型。以下函数显示了所需任务的可能实现：

```cpp
namespace fs = std::experimental::filesystem;

std::uintmax_t get_directory_size(fs::path const & dir,
                                  bool const follow_symlinks = false)
{
   auto iterator = fs::recursive_directory_iterator(
      dir,
      follow_symlinks ? fs::directory_options::follow_directory_symlink : 
                        fs::directory_options::none);

   return std::accumulate(
      fs::begin(iterator), fs::end(iterator),
      0ull,
      [](std::uintmax_t const total,
         fs::directory_entry const & entry) {
             return total + (fs::is_regular_file(entry) ?
                    fs::file_size(entry.path()) : 0);
   });
}

int main()
{
   std::string path;
   std::cout << "Path: ";
   std::cin >> path;
   std::cout << "Size: " << get_directory_size(path) << std::endl;
}
```

# 36. 删除早于指定日期的文件

要执行文件系统操作，应该使用`filesystem`库。对于处理时间和持续时间，应该使用`chrono`库。实现请求功能的函数必须执行以下操作：

1.  检查目标路径指示的条目是否存在且是否比给定持续时间旧，如果是，则删除它

1.  如果不是旧的，并且它是一个目录，则遍历其所有条目并递归调用该函数：

```cpp
namespace fs = std::experimental::filesystem;
namespace ch = std::chrono;

template <typename Duration>
bool is_older_than(fs::path const & path, Duration const duration)
{
   auto ftimeduration = fs::last_write_time(path).time_since_epoch();
   auto nowduration = (ch::system_clock::now() - duration)
                      .time_since_epoch();
   return ch::duration_cast<Duration>(nowduration - ftimeduration)
                      .count() > 0;
}

template <typename Duration>
void remove_files_older_than(fs::path const & path, 
                             Duration const duration)
{
   try
   {
      if (fs::exists(path))
      {
         if (is_older_than(path, duration))
         {
            fs::remove(path);
         }
         else if(fs::is_directory(path))
         {
            for (auto const & entry : fs::directory_iterator(path))
            {
               remove_files_older_than(entry.path(), duration);
            }
         }
      }
   }
   catch (std::exception const & ex)
   {
      std::cerr << ex.what() << std::endl;
   }
}
```

除了使用`directory_iterator`和递归调用`remove_files_older_than()`之外，另一种方法是使用`recursive_directory_iterator`，并且如果超过给定持续时间，则简单地删除条目。然而，这种方法会使用未定义的行为，因为如果在创建递归目录迭代器后删除或添加文件或目录到目录树中，则不指定是否通过迭代器观察到更改。因此，应避免使用此方法。

`is_older_than()`函数模板确定了自系统时钟纪元以来当前时刻和最后一次文件写入操作之间经过的时间，并检查两者之间的差异是否大于指定的持续时间。

`remove_files_older_than()`函数可以如下使用：

```cpp
int main()
{
   using namespace std::chrono_literals;

#ifdef _WIN32
   auto path = R"(..\Test\)";
#else
   auto path = R"(../Test/)";
#endif

   remove_files_older_than(path, 1h + 20min);
}
```

# 37. 在目录中查找与正则表达式匹配的文件

实现指定的功能应该很简单：递归遍历指定目录的所有条目，并保留所有正则文件名匹配的条目。为此，您应该使用以下方法：

+   `filesystem::recursive_directory_iterator`用于遍历目录条目

+   `regex`和`regex_match()`来检查文件名是否与正则表达式匹配

+   `copy_if()`和`back_inserter`来复制符合特定条件的目录条目到`vector`的末尾。

这样的函数可能如下所示：

```cpp
namespace fs = std::experimental::filesystem;

std::vector<fs::directory_entry> find_files(
   fs::path const & path,
   std::string_view regex)
{
   std::vector<fs::directory_entry> result;
   std::regex rx(regex.data());

   std::copy_if(
      fs::recursive_directory_iterator(path),
      fs::recursive_directory_iterator(),
      std::back_inserter(result),
      &rx {
         return fs::is_regular_file(entry.path()) &&
                std::regex_match(entry.path().filename().string(), rx);
   });

   return result;
}
```

有了这个，我们可以编写以下代码：

```cpp
int main()
{
   auto dir = fs::temp_directory_path();
   auto pattern = R"(wct[0-9a-zA-Z]{3}\.tmp)";
   auto result = find_files(dir, pattern);

   for (auto const & entry : result)
   {
      std::cout << entry.path().string() << std::endl;
   }
}
```

# 38. 临时日志文件

您必须为此任务实现的日志类应该：

+   有一个构造函数，在临时目录中创建一个文本文件并打开它进行写入

+   在销毁期间，如果文件仍然存在，则关闭并删除它

+   有一个关闭文件并将其移动到永久路径的方法

+   重载`operator<<`以将文本消息写入输出文件

为了为文件创建唯一的名称，可以使用 UUID（也称为 GUID）。C++标准不支持与此相关的任何功能，但有第三方库，如`boost::uuid`、*CrossGuid*或`stduuid`，实际上是我创建的一个库。对于这个实现，我将使用最后一个。你可以在[`github.com/mariusbancila/stduuid`](https://github.com/mariusbancila/stduuid)找到它。

```cpp
namespace fs = std::experimental::filesystem;

class logger
{
   fs::path logpath;
   std::ofstream logfile;
public:
   logger()
   {
      auto name = uuids::to_string(uuids::uuid_random_generator{}());
      logpath = fs::temp_directory_path() / (name + ".tmp");
      logfile.open(logpath.c_str(), std::ios::out|std::ios::trunc);
   }

   ~logger() noexcept
   {
      try {
         if(logfile.is_open()) logfile.close();
         if (!logpath.empty()) fs::remove(logpath);
      }
      catch (...) {}
   }

   void persist(fs::path const & path)
   {
      logfile.close();
      fs::rename(logpath, path);
      logpath.clear();
   }

   logger& operator<<(std::string_view message)
   {
      logfile << message.data() << '\n';
      return *this;
   }
};
```

使用这个类的一个例子如下：

```cpp
int main()
{
   logger log;
   try 
   {
      log << "this is a line" << "and this is another one";
      throw std::runtime_error("error");
   }
   catch (...) 
   {
      log.persist(R"(lastlog.txt)");
   }
}
```
