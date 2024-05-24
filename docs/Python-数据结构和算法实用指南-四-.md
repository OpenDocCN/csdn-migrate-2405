# Python 数据结构和算法实用指南（四）

> 原文：[`zh.annas-archive.org/md5/66ae3d5970b9b38c5ad770b42fec806d`](https://zh.annas-archive.org/md5/66ae3d5970b9b38c5ad770b42fec806d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：字符串算法和技术

根据所解决的问题，有许多流行的字符串处理算法。然而，最重要、最流行和最有用的字符串处理问题之一是从给定文本中找到给定的子字符串或模式。它有各种应用，例如从文本文档中搜索元素，检测抄袭等。

在本章中，我们将学习标准的字符串处理或模式匹配算法，以找出给定模式或子字符串在给定文本中的位置。我们还将讨论暴力算法，以及 Rabin-Karp、Knuth-Morris-Pratt（KMP）和 Boyer-Moore 模式匹配算法。我们还将讨论与字符串相关的一些基本概念。我们将用简单的解释、示例和实现来讨论所有算法。

本章旨在讨论与字符串相关的算法。本章将涵盖以下主题：

+   学习 Python 中字符串的基本概念

+   学习模式匹配算法及其实现

+   理解和实现 Rabin-Karp 模式匹配算法

+   理解和实现 Knuth-Morris-Pratt（KMP）算法

+   理解和实现 Boyer-Moore 模式匹配算法

# 技术要求

本章讨论的基于本章讨论的概念和算法的所有程序都在书中以及 GitHub 存储库中提供，链接如下：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter12`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-Second-Edition/tree/master/Chapter12)。

# 字符串符号和概念

字符串基本上是一系列对象，主要是一系列字符。与其他任何数据类型（如 int 或 float）一样，我们需要存储数据和要应用的操作。字符串数据类型允许我们存储数据，Python 提供了一组丰富的操作和函数，可以应用于字符串数据类型的数据。Python 3.7 提供的大多数操作和函数，可以应用于字符串的数据，都在第一章中详细描述了*Python 对象、类型和表达式*。

字符串主要是文本数据，通常处理得非常高效。以下是一个字符串（S）的示例——`"packt publishing"`。

子字符串也是给定字符串的一部分字符序列。例如，`"packt"`是字符串`"packt publishing"`的子字符串。

子序列是从给定字符串中删除一些字符但保持字符出现顺序的字符序列。例如，`"pct pblishing"`是字符串`"packt publishing"`的有效子序列，通过删除字符`a`、`k`和`u`获得。但是，这不是一个子字符串。子序列不同于子字符串，因为它可以被认为是子字符串的泛化。

字符串`s`的前缀是字符串`s`的子字符串，它出现在字符串的开头。还有另一个字符串`u`，它存在于前缀之后的字符串 s 中。例如，子字符串`"pack"`是字符串`(s) = "packt publishing"`的前缀，因为它是起始子字符串，之后还有另一个子字符串。

后缀`(d)`是一个子字符串，它出现在字符串（s）的末尾，以便在子字符串 d 之前存在另一个非空子字符串。例如，子字符串`"shing"`是字符串`"packt publishing"`的后缀。Python 具有内置函数，用于检查字符串是否具有给定的前缀或后缀，如下面的代码片段所示：

```py
string =  "this is data structures book by packt publisher"; suffix =  "publisher"; prefix = "this"; print(string.endswith(suffix))  #Check if string contains given suffix.
print(string.startswith(prefix)) #Check if string starts with given prefix.

#Outputs
>>True
>>True
```

模式匹配算法是最重要的字符串处理算法，我们将在后续章节中讨论它们。

# 模式匹配算法

模式匹配算法用于确定给定模式字符串（P）在文本字符串（T）中匹配的索引位置。如果模式在文本字符串中不匹配，则返回`"pattern not found"`。例如，对于给定字符串（s）=`"packt publisher"`，模式（p）=`"publisher"`，模式匹配算法返回模式在文本字符串中匹配的索引位置。

在本节中，我们将讨论四种模式匹配算法，即暴力方法，以及 Rabin-Karp 算法，Knuth-Morris-Pratt（KMP）和 Boyer Moore 模式匹配算法。

# 暴力算法

暴力算法，或者模式匹配算法的朴素方法，非常基础。使用这种方法，我们简单地测试给定字符串中输入模式的所有可能组合，以找到模式的出现位置。这个算法非常朴素，如果文本很长就不适用。

在这里，我们首先逐个比较模式和文本字符串的字符，如果模式的所有字符与文本匹配，我们返回模式的第一个字符放置的文本的索引位置。如果模式的任何字符与文本字符串不匹配，我们将模式向右移动一个位置。我们继续比较模式和文本字符串，通过将模式向右移动一个索引位置。

为了更好地理解暴力算法的工作原理，让我们看一个例子。假设我们有一个文本字符串(T)=**acbcabccababcaacbcac**，模式字符串(P)是**acbcac**。现在，模式匹配算法的目标是确定给定文本 T 中模式字符串的索引位置，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/248df9b8-9f4d-4cb4-a404-b08d3cc5cef8.png)

我们首先比较文本的第一个字符，即**a**，和模式的字符。在这里，模式的初始五个字符匹配，最后一个字符不匹配。由于不匹配，我们进一步将模式向右移动一个位置。我们再次开始逐个比较模式的第一个字符和文本字符串的第二个字符。在这里，文本字符串的字符**c**与模式的字符**a**不匹配。由于不匹配，我们将模式向右移动一个位置，如前面的图所示。我们继续比较模式和文本字符串的字符，直到遍历整个文本字符串。在上面的例子中，我们在索引位置**14**找到了匹配，用箭头指向**aa**。

在这里，让我们考虑模式匹配的暴力算法的 Python 实现：

```py
def brute_force(text, pattern):
    l1 = len(text)      # The length of the text string
    l2 = len(pattern)   # The length of the pattern 
    i = 0
    j = 0               # looping variables are set to 0
    flag = False        # If the pattern doesn't appear at all, then set this to false and execute the last if statement

    while i < l1:         # iterating from the 0th index of text
        j = 0
        count = 0    
        # Count stores the length upto which the pattern and the text have matched

        while j < l2:
            if i+j < l1 and text[i+j] == pattern[j]:  
        # statement to check if a match has occoured or not
        count += 1     # Count is incremented if a character is matched 
            j += 1
        if count == l2:   # it shows a matching of pattern in the text 
                print("\nPattern occours at index", i) 
                  # print the starting index of the successful match
                flag = True 
     # flag is True as we wish to continue looking for more matching of  
      pattern in the text. 
            i += 1
    if not flag: 
        # If the pattern doesn't occours at all, means no match of  
         pattern in the text string
        print('\nPattern is not at all present in the array')

brute_force('acbcabccababcaacbcac','acbcac')         # function call

#outputs
#Pattern occours at index 14
```

在暴力方法的上述代码中，我们首先计算给定文本字符串和模式的长度。我们还用`0`初始化循环变量，并将标志设置为`False`。这个变量用于在字符串中继续搜索模式的匹配。如果标志在文本字符串结束时为`False`，这意味着在文本字符串中根本没有模式的匹配。

接下来，我们从文本字符串的`0th`索引开始搜索循环，直到末尾。在这个循环中，我们有一个计数变量，用于跟踪匹配的模式和文本的长度。接下来，我们有另一个嵌套循环，从`0th`索引运行到模式的长度。在这里，变量`i`跟踪文本字符串中的索引位置，变量`j`跟踪模式中的字符。接下来，我们使用以下代码片段比较模式和文本字符串的字符：

```py
if i+j<l1 and text[i+j] == pattern[j]:
```

此外，我们在文本字符串中每次匹配模式的字符后递增计数变量。然后，我们继续匹配模式和文本字符串的字符。如果模式的长度等于计数变量，那么就意味着有匹配。

如果在文本字符串中找到了模式的匹配，我们会打印文本字符串的索引位置，并将标志变量保持为`True`，因为我们希望继续在文本字符串中搜索更多模式的匹配。最后，如果标志变量的值为`False`，这意味着在文本字符串中根本没有找到模式的匹配。

朴素字符串匹配算法的最佳情况和最坏情况的时间复杂度分别为`O(n)`和`O(m*(n-m+1))`。最佳情况是模式在文本中找不到，并且模式的第一个字符根本不在文本中，例如，如果文本字符串是`ABAACEBCCDAAEE`，模式是`FAA`。在这种情况下，由于模式的第一个字符在文本中不匹配，比较次数将等于文本的长度(`n`)。

最坏情况发生在文本字符串和模式的所有字符都相同的情况下，例如，如果文本字符串是`AAAAAAAAAAAAAAAA`，模式是`AAAA`。另一个最坏情况是只有最后一个字符不同，例如，如果文本字符串是`AAAAAAAAAAAAAAAF`，模式是`AAAAF`。因此，最坏情况的时间复杂度将是`O(m*(n-m+1))`。

# 拉宾-卡普算法

拉宾-卡普模式匹配算法是改进后的蛮力方法，用于在文本字符串中找到给定模式的位置。拉宾-卡普算法的性能通过减少比较次数来改进，借助哈希。我们在第七章中详细描述了哈希，*哈希和符号表*。哈希函数为给定的字符串返回一个唯一的数值。

这种算法比蛮力方法更快，因为它避免了不必要的逐个字符比较。相反，模式的哈希值一次性与文本字符串的子字符串的哈希值进行比较。如果哈希值不匹配，模式就向前移动一位，因此无需逐个比较模式的所有字符。

这种算法基于这样的概念：如果两个字符串的哈希值相等，那么假定这两个字符串也相等。这种算法的主要问题是可能存在两个不同的字符串，它们的哈希值相等。在这种情况下，算法可能无法工作；这种情况被称为虚假命中。为了避免这个问题，在匹配模式和子字符串的哈希值之后，我们通过逐个比较它们的字符来确保模式实际上是匹配的。

拉宾-卡普模式匹配算法的工作原理如下：

1.  首先，在开始搜索之前，我们对模式进行预处理，即计算长度为`m`的模式的哈希值以及长度为`m`的文本的所有可能子字符串的哈希值。因此，可能的子字符串的总数将是`(n-m+1)`。这里，`n`是文本的长度。

1.  我们比较模式的哈希值，并逐一与文本的子字符串的哈希值进行比较。

1.  如果哈希值不匹配，我们就将模式向前移动一位。

1.  如果模式的哈希值和文本的子字符串的哈希值匹配，那么我们逐个比较模式和子字符串的字符，以确保模式实际上在文本中找到。

1.  我们继续进行步骤 2-4 的过程，直到达到给定文本字符串的末尾。

在这个算法中，我们可以使用 Horner 法则或任何返回给定字符串唯一值的哈希函数来计算数值哈希值。我们也可以使用字符串所有字符的序数值之和来计算哈希值。

让我们举个例子来理解 Rabin-Karp 算法。假设我们有一个文本字符串（T）=`"publisher paakt packt"`，模式（P）=`"packt"`。首先，我们计算模式（长度为`m`）的哈希值和文本字符串的所有子字符串（长度为`m`）的哈希值。

我们开始比较模式`"packt"`的哈希值与第一个子字符串“publi”的哈希值。由于哈希值不匹配，我们将模式移动一个位置，然后再次比较模式的哈希值与文本的下一个子字符串`"ublis"`的哈希值。由于这些哈希值也不匹配，我们再次将模式移动一个位置。如果哈希值不匹配，我们总是将模式移动一个位置。

此外，如果模式的哈希值和子字符串的哈希值匹配，我们逐个比较模式和子字符串的字符，并返回文本字符串的位置。在这个例子中，这些值在位置`17`匹配。重要的是要注意，可能有一个不同的字符串，其哈希值可以与模式的哈希值匹配。这种情况称为虚假命中，是由于哈希冲突而引起的。Rabin-Karp 算法的功能如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/06dc36ee-ebaf-43b7-b19e-564e36fafb04.png)

# 实现 Rabin-Karp 算法

实现 Rabin-Karp 算法的第一步是选择哈希函数。我们使用字符串所有字符的序数值之和作为哈希函数。

我们首先存储文本和模式的所有字符的序数值。接下来，我们将文本和模式的长度存储在`len_text`和`len_pattern`变量中。然后，我们通过对模式中所有字符的序数值求和来计算模式的哈希值。

接下来，我们创建一个名为`len_hash_array`的变量，它存储了使用`len_text - len_pattern + 1`的长度（等于模式的长度）的所有可能子字符串的总数，并创建了一个名为`hash_text`的数组，它存储了所有可能子字符串的哈希值。

接下来，我们开始一个循环，它将运行所有可能的文本子字符串。最初，我们通过使用`sum(ord_text[:len_pattern])`对其所有字符的序数值求和来计算第一个子字符串的哈希值。此外，所有子字符串的哈希值都是使用其前一个子字符串的哈希值计算的，如`((hash_text[i-1] - ord_text[i-1]) + ord_text[i+len_pattern-1])`。

计算哈希值的完整 Python 实现如下所示：

```py
def generate_hash(text, pattern):
      ord_text = [ord(i) for i in text]   
                       # stores unicode value of each character in text 
      ord_pattern = [ord(j) for j in pattern] 
                   # stores unicode value of each character in pattern
      len_text = len(text)           # stores length of the text 
      len_pattern = len(pattern)     # stores length of the pattern
      hash_pattern = sum(ord_pattern)
      len_hash_array = len_text - len_pattern + 1    
       #stores the length of new array that will contain the hash 
       values of text
      hash_text = [0]*(len_hash_array) 
                         # Initialize all the values in the array to 0.
      for i in range(0, len_hash_array): 
           if i == 0:  
                hash_text[i] = sum(ord_text[:len_pattern]) 
                                      # initial value of hash function
           else:
                hash_text[i] = ((hash_text[i-1] - ord_text[i-1]) + 
                ord_text[i+len_pattern-1]) 
                    # calculating next hash value using previous value

      return [hash_text, hash_pattern]         # return the hash values
```

在预处理模式和文本之后，我们有预先计算的哈希值，我们将用它们来比较模式和文本。

主要的 Rabin-Karp 算法实现如下。首先，我们将给定的文本和模式转换为字符串格式，因为只能为字符串计算序数值。

接下来，我们调用`generate_hash`函数来计算哈希值。我们还将文本和模式的长度存储在`len_text`和`len_pattern`变量中。我们还将`flag`变量初始化为`False`，以便跟踪模式是否至少出现一次在文本中。

接下来，我们开始一个循环，实现算法的主要概念。这个循环将运行`hash_text`的长度，这是可能子字符串的总数。最初，我们通过使用`if hash_text[i] == hash_pattern`比较子字符串的第一个哈希值和模式的哈希值。它们不匹配；我们什么也不做，寻找另一个子字符串。如果它们匹配，我们通过循环使用`if pattern[j] == text[i+j]`逐个字符比较子字符串和模式。

然后，我们创建一个`count`变量来跟踪模式和子字符串中匹配的字符数。如果计数的长度和模式的长度变得相等，这意味着所有字符都匹配，并且返回模式被找到的索引位置。最后，如果`flag`变量保持为`False`，这意味着模式在文本中根本不匹配。

Rabin-Karp 算法的完整 Python 实现如下所示：

```py
def Rabin_Karp_Matcher(text, pattern):
    text = str(text)                 # convert text into string format
    pattern = str(pattern)           # convert pattern into string format
    hash_text, hash_pattern = generate_hash(text, pattern) 
                    # generate hash values using generate_hash function
    len_text = len(text)              # length of text
    len_pattern = len(pattern)        # length of pattern
    flag = False # checks if pattern is present atleast once or not at all
    for i in range(len(hash_text)): 
        if hash_text[i] == hash_pattern:     # if the hash value matches
            count = 0 
            for j in range(len_pattern): 
                if pattern[j] == text[i+j]: 
                        # comparing patten and substring character by character
                    count += 1  
                else:
                    break
                if count == len_pattern:       # Pattern is found in the text
                    flag = True                # update flag accordingly
                    print("Pattern occours at index", i)
                if not flag:                # Pattern doesn't match even once.
                    print("Pattern is not at all present in the text")
```

Rabin-Karp 模式匹配算法在搜索之前预处理模式，即计算模式的哈希值，其复杂度为`O(m)`。此外，Rabin-Karp 算法的最坏情况运行时间复杂度为`O(m *(n-m+1))`。

最坏情况是模式根本不在文本中出现。

平均情况将发生在模式至少出现一次的情况下。

# Knuth-Morris-Pratt 算法

**Knuth-Morris-Pratt**（**KMP**）算法是一种基于预先计算的前缀函数的模式匹配算法，该函数存储了模式中重叠文本部分的信息。KMP 算法预处理这个模式，以避免在使用前缀函数时进行不必要的比较。该算法利用前缀函数来估计模式应该移动多少来搜索文本字符串中的模式，每当我们得到一个不匹配时。KMP 算法是高效的，因为它最小化了给定模式与文本字符串的比较。

KMP 算法背后的动机可以在以下解释性图表中看到：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/8f518fde-532f-4f1a-855d-94e9c0b80d22.png)

# 前缀函数

`prefix`函数（也称为失败函数）在模式中查找模式本身。当出现不匹配时，它试图找出由于模式本身的重复而可以重复使用多少之前的比较。它的值主要是最长的前缀，也是后缀。

例如，如果我们有一个模式的`prefix`函数，其中所有字符都不同，那么`prefix`函数的值将为`0`，这意味着如果我们找到任何不匹配，模式将被移动到模式中的字符数。这也意味着模式中没有重叠，并且不会重复使用任何先前的比较。如果文本字符串只包含不同的字符，我们将从模式的第一个字符开始比较。考虑以下示例：模式**abcde**包含所有不同的字符，因此它将被移动到模式中的字符数，并且我们将开始比较模式的第一个字符与文本字符串的下一个字符，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/ef15fd04-c114-4737-9dbe-344b65cf61a8.png)

让我们考虑另一个示例，以更好地理解`prefix`函数如何为模式（P）**abcabbcab**工作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/0a762ce6-7571-451d-a0cb-378a379fc3f1.png)

在上图中，我们从索引**1**开始计算`prefix`函数的值。如果字符没有重复，我们将值赋为**0**。在上面的例子中，我们为索引位置**1**到**3**的`prefix`函数分配了**0**。接下来，在索引位置**4**，我们可以看到有一个字符**a**，它是模式中第一个字符的重复，所以我们在这里分配值**1**，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/58b14e31-38ce-4f51-b496-bdf83615502d.png)

接下来，我们看索引位置**5**处的下一个字符。它有最长的后缀模式**ab**，因此它的值为**2**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/cd0fc819-6318-4b89-926b-d283d072cd15.png)

同样，我们看下一个索引位置**6**。这里，字符是**b**。这个字符在模式中没有最长的后缀，所以它的值是**0**。接下来，我们在索引位置**7**处赋值**0**。然后，我们看索引位置**8**，并将值**1**分配给它，因为它有长度为**1**的最长后缀。最后，在索引位置**9**，我们有长度为**2**的最长后缀：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/04aa8d29-9b55-4e3f-9d39-f519846bc1c5.png)

`prefix`函数的值显示了如果不匹配，字符串的开头有多少可以重复使用。例如，如果在索引位置**5**处比较失败，`prefix`函数的值为**2**，这意味着不需要比较前两个字符。

# 理解 KMP 算法

KMP 模式匹配算法使用具有模式本身重叠的模式，以避免不必要的比较。KMP 算法的主要思想是根据模式中的重叠来检测模式应该移动多少。算法的工作原理如下：

1.  首先，我们为给定的模式预先计算`prefix`函数，并初始化一个表示匹配字符数的计数器 q。

1.  我们从比较模式的第一个字符与文本字符串的第一个字符开始，如果匹配，则递增模式的计数器**q**和文本字符串的计数器，并比较下一个字符。

1.  如果不匹配，我们将预先计算的`prefix`函数的值赋给**q**的索引值。

1.  我们继续在文本字符串中搜索模式，直到达到文本的末尾，即如果我们找不到任何匹配。如果模式中的所有字符都在文本字符串中匹配，我们返回模式在文本中匹配的位置，并继续搜索另一个匹配。

让我们考虑以下示例来理解这一点：

给定模式的`prefix`函数如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/628b4eb1-1001-487f-9197-1dea713c5750.png)

现在，我们开始比较模式的第一个字符与文本字符串的第一个字符，并继续比较，直到找到匹配。例如，在下图中，我们从比较文本字符串的字符**a**和模式的字符**a**开始。由于匹配，我们继续比较，直到找到不匹配或者我们已经比较了整个模式。在这里，我们在索引位置**6**找到了不匹配，所以现在我们必须移动模式。

我们使用`prefix`函数的帮助来找到模式应该移动的次数。这是因为在不匹配的位置（即`prefix_function(6)`为**2**）上，`prefix`函数的值为**2**，所以我们从模式的索引位置`2`开始比较模式。由于 KMP 算法的效率，我们不需要比较索引位置**1**的字符，我们比较模式的字符**c**和文本的字符**b**。由于它们不匹配，我们将模式向右移动**1**个位置，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b4b25215-9e10-4cd4-b815-12f07cb088ad.png)

接下来，我们比较的字符是**b**和**a**——它们不匹配，所以我们将模式向右移动**1**个位置。接下来，我们比较模式和文本字符串，并在文本的索引位置 10 处找到字符**b**和**c**之间的不匹配。在这里，我们使用预先计算的“前缀”函数来移动模式，因为`prefix_function(4)`是**2**，所以我们将其移动到索引位置**2**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/44d1fb23-e596-45c4-a474-374590b295a9.png)

之后，由于字符**b**和**c**不匹配，我们将模式向右移动 1 个位置。接下来，我们比较文本中索引为**11**的字符，直到找到不匹配为止。我们发现字符**b**和**c**不匹配，如下图所示。由于`prefix_function(2)`是`0`，我们将模式移动到模式的索引`0`。我们重复相同的过程，直到达到字符串的末尾。我们在文本字符串的索引位置**13**找到了模式的匹配，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/bebe5024-3aff-4b76-8623-1c2681510c3d.png)

KMP 算法有两个阶段，预处理阶段，这是我们计算“前缀”函数的地方，它的空间和时间复杂度为`O(m)`，然后，在第二阶段，即搜索阶段，KMP 算法的时间复杂度为`O(n)`。

现在，我们将讨论如何使用 Python 实现 KMP 算法。

# 实现 KMP 算法

这里解释了 KMP 算法的 Python 实现。我们首先为给定的模式实现“前缀”函数。为此，首先我们使用`len()`函数计算模式的长度，然后初始化一个列表来存储“前缀”函数计算出的值。

接下来，我们开始执行循环，从 2 到模式的长度。然后，我们有一个嵌套循环，直到我们处理完整个模式为止。变量`k`初始化为`0`，这是模式的第一个元素的“前缀”函数。如果模式的第`k`个元素等于第`q`个元素，那么我们将`k`的值增加`1`。

k 的值是由“前缀”函数计算得出的值，因此我们将其分配给模式的`q`的索引位置。最后，我们返回具有模式每个字符的计算值的“前缀”函数列表。以下是“前缀”函数的代码：

```py
def pfun(pattern): # function to generate prefix function for the given pattern
    n = len(pattern) # length of the pattern
    prefix_fun = [0]*(n) # initialize all elements of the list to 0
    k = 0
    for q in range(2,n):
         while k>0 and pattern[k+1] != pattern[q]:
            k = prefix_fun[k]
         if pattern[k+1] == pattern[q]: # If the kth element of the pattern is equal to the qth element
            k += 1            # update k accordingly
         prefix_fun[q] = k
    return prefix_fun         # return the prefix function 
```

一旦我们创建了“前缀”函数，我们就实现了主要的 KMP 匹配算法。我们首先计算文本字符串和模式的长度，它们分别存储在变量`m`和`n`中。以下代码详细显示了这一点：

```py

def KMP_Matcher(text,pattern): 
    m = len(text)
    n = len(pattern)
    flag = False
    text = '-' + text       # append dummy character to make it 1-based indexing
    pattern = '-' + pattern       # append dummy character to the pattern also
    prefix_fun = pfun(pattern) # generate prefix function for the pattern
    q = 0
    for i in range(1,m+1):
        while q>0 and pattern[q+1] != text[i]: 
        # while pattern and text are not equal, decrement the value of q if it is > 0
            q = prefix_fun[q]
        if pattern[q+1] == text[i]: # if pattern and text are equal, update value of q
            q += 1
        if q == n: # if q is equal to the length of the pattern, it means that the pattern has been found.
            print("Pattern occours with shift",i-n) # print the index,
```

```py
where first match occours.
            flag = True
            q = prefix_fun[q]
    if not flag:
            print('\nNo match found')

KMP_Matcher('aabaacaadaabaaba','abaac')         #function call
```

# Boyer-Moore 算法

正如我们已经讨论过的，字符串模式匹配算法的主要目标是通过避免不必要的比较来尽可能地跳过比较。

Boyer-Moore 模式匹配算法是另一种这样的算法（除了 KMP 算法），它通过使用一些方法跳过一些比较来进一步提高模式匹配的性能。您需要理解以下概念才能使用 Boyer-Moore 算法：

1.  在这个算法中，我们将模式从左向右移动，类似于 KMP 算法

1.  我们从右向左比较模式和文本字符串的字符，这与 KMP 算法相反

1.  该算法通过使用好后缀和坏字符移位的概念来跳过不必要的比较

# 理解 Boyer-Moore 算法

Boyer-Moore 算法从右到左比较文本上的模式。它通过预处理模式来使用模式中各种可能的对齐信息。这个算法的主要思想是我们将模式的末尾字符与文本进行比较。如果它们不匹配，那么模式可以继续移动。如果末尾的字符不匹配，就没有必要进行进一步的比较。此外，在这个算法中，我们还可以看到模式的哪一部分已经匹配（与匹配的后缀），因此我们利用这个信息，通过跳过任何不必要的比较来对齐文本和模式。

当我们发现不匹配时，Boyer-Moore 算法有两个启发式来确定模式的最大可能移位：

+   坏字符启发式

+   好后缀启发式

在不匹配时，每个启发式都建议可能的移位，而 Boyer-Moore 算法通过考虑由于坏字符和好后缀启发式可能的最大移位来移动模式。坏字符和好后缀启发式的详细信息将在以下子节中通过示例详细解释。

# 坏字符启发式

Boyer-Moore 算法将模式和文本字符串从右到左进行比较。它使用坏字符启发式来移动模式。根据坏字符移位的概念，如果模式的字符与文本不匹配，那么我们检查文本的不匹配字符是否出现在模式中。如果这个不匹配的字符（也称为坏字符）不出现在模式中，那么模式将被移动到这个字符的旁边，如果该字符在模式中的某处出现，我们将模式移动到与文本字符串的坏字符对齐的位置。

让我们通过一个例子来理解这个概念。考虑一个文本字符串（T）和模式={**acacac**}。我们从右到左比较字符，即文本字符串的字符**b**和模式的字符**c**。它们不匹配，所以我们在模式中寻找文本字符串的不匹配字符**b**。由于它不在模式中出现，我们将模式移动到不匹配的字符旁边，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/cc298adf-fb27-4d70-9f29-5148bc40d532.png)

让我们看另一个例子。我们从右到左比较文本字符串和模式的字符，对于文本的字符**d**，我们得到了不匹配。在这里，后缀**ac**是匹配的，但是字符**d**和**c**不匹配，不匹配的字符**d**不在模式中出现。因此，我们将模式移动到不匹配的字符旁边，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/9fc8421b-9ed9-4282-bf63-522846e13eb9.png)

让我们考虑坏字符启发式的另一个例子。在这里，后缀**ac**是匹配的，但是接下来的字符**a**和**c**不匹配，因此我们在模式中搜索不匹配的字符**a**的出现。由于它在模式中出现了两次，我们有两个选项来对齐不匹配的字符，如下图所示。在这种情况下，我们有多个选项来移动模式，我们移动模式的最小次数以避免任何可能的匹配。（换句话说，它将是模式中该字符的最右出现位置。）如果模式中只有一个不匹配的字符的出现，我们可以轻松地移动模式，使不匹配的字符对齐。

在以下示例中，我们更喜欢选项**1**来移动模式：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/284beb26-731a-441f-a1c3-2eb800c011c1.png)

# 好后缀启发式

坏字符启发式并不总是提供良好的建议。Boyer-Moore 算法还使用好后缀启发式来将模式移位到文本字符串上，以找出匹配模式的位置。

好后缀启发式是基于匹配的后缀。在这里，我们将模式向右移动，以使匹配的后缀子模式与模式中另一个相同后缀的出现对齐。它的工作原理是：我们从右到左开始比较模式和文本字符串。如果我们找到任何不匹配，那么我们检查到目前为止已经匹配的后缀的出现。这被称为好后缀。我们以这样的方式移动模式，以便将好后缀的另一个出现对齐到文本上。好后缀启发式主要有两种情况：

1.  匹配的后缀在模式中有一个或多个出现。

1.  匹配后缀的某部分存在于模式的开头（这意味着匹配后缀的后缀存在于模式的前缀中）。

让我们通过以下示例了解这些情况。假设我们有一个模式**acabac**。我们对字符**a**和**b**进行不匹配，但此时，我们已经匹配了后缀，即**ac**。现在，我们在模式中搜索好后缀**ac**的另一个出现，并通过对齐后缀来移动模式，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/19965040-07c0-4fc5-84d1-a785c3b25d1c.png)

让我们考虑另一个例子，我们有两个选项来对齐模式的移位，以便获得两个好后缀字符串。在这里，我们将选择**1**来通过考虑具有最小移位的选项来对齐好后缀，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/467f95d8-927f-44e1-9ff8-dc722ba839ae.png)

让我们再看一个例子。在这里，我们得到了**aac**的后缀匹配，但对于字符**b**和**a**，我们得到了不匹配。我们搜索好后缀**aac**，但在模式中找不到另一个出现。但是，我们发现模式开头的前缀**ac**与整个后缀不匹配，但与匹配后缀**aac**的后缀**ac**匹配。在这种情况下，我们通过将模式与后缀对齐来移动模式，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/323ab0d1-b503-42f7-ab66-aa97a9fc0299.png)

另一个好后缀启发式的案例如下。在这种情况下，我们匹配后缀**aac**，但在字符**b**和**a**处不匹配。我们尝试在模式中搜索匹配的后缀，但在模式中没有后缀的出现，所以在这种情况下，我们将模式移位到匹配的后缀之后，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/e84ff37e-2ddd-4ece-9883-2011cd8531ed.png)

我们通过坏字符启发式和好后缀启发式给出的更长距离来移动模式。

Boyer-Moore 算法在模式的预处理中需要`O(m)`的时间，进一步搜索需要`O(mn)`的时间复杂度。

# 实现 Boyer-Moore 算法

让我们了解 Boyer-Moore 算法的实现。最初，我们有文本字符串和模式。在初始化变量之后，我们开始使用 while 循环，该循环从模式的最后一个字符开始与文本的相应字符进行比较。

然后，通过使用嵌套循环从模式的最后一个索引到模式的第一个字符，从右到左比较字符。这使用`range(len(pattern)-1, -1, -1)`。

外部 while 循环跟踪文本字符串中的索引，而内部 for 循环跟踪模式中的索引位置。

接下来，我们开始使用`pattern[j] != text[i+j]`来比较字符。如果它们不匹配，我们将使标志变量`False`，表示存在不匹配。

现在，我们通过使用条件`j == len(pattern)-1`来检查好后缀是否存在。如果这个条件为真，意味着没有可能的好后缀，所以我们检查坏字符启发式，即如果模式中存在或不存在不匹配的字符，使用条件`text[i+j] in pattern[0:j]`，如果条件为真，则意味着坏字符存在于模式中。在这种情况下，我们使用`i=i+j-pattern[0:j].rfind(text[i+j])`将模式移动到与模式中此字符的其他出现对齐。这里，`(i+j)`是坏字符的索引。

如果坏字符不在模式中（它不在`else`部分），我们使用索引`i=i+j+1`将整个模式移动到不匹配的字符旁边。

接下来，我们进入条件的`else`部分，检查好后缀。当我们发现不匹配时，我们进一步测试，看看我们的模式前缀中是否有任何好后缀的子部分。我们通过使用以下条件来做到这一点：

```py
 text[i+j+k:i+len(pattern)] not in pattern[0:len(pattern)-1]
```

此外，我们检查好后缀的长度是否为`1`。如果好后缀的长度为`1`，我们不考虑这个移动。如果好后缀大于`1`，我们通过好后缀启发式找出移动次数，并将其存储在`gsshift`变量中。这是将模式移动到与文本的好后缀匹配的位置的指令。此外，我们计算由于坏字符启发式可能的移动次数，并将其存储在`bcshift`变量中。当坏字符存在于模式中时，可能的移动次数是`i+j-pattern[0:j].rfind(text[i+j])`，当坏字符不在模式中时，可能的移动次数将是`i+j+1`。

接下来，我们通过使用坏字符和好后缀启发式的最大移动次数将模式移动到文本字符串上。最后，我们检查标志变量是否为`True`。如果为`True`，这意味着找到了模式，并且匹配的索引已存储在`matched_indexes`变量中。

Boyer-Moore 算法的完整实现如下所示：

```py
text= "acbaacacababacacac"
pattern = "acacac"

matched_indexes = []
i=0
flag = True
while i<=len(text)-len(pattern):
    for j in range(len(pattern)-1, -1, -1): #reverse searching
        if pattern[j] != text[i+j]:
            flag = False #indicates there is a mismatch
            if j == len(pattern)-1: #if good-suffix is not present, we test bad character 
                if text[i+j] in pattern[0:j]:
                    i=i+j-pattern[0:j].rfind(text[i+j]) #i+j is index of bad character, this line is used for jumping pattern to match bad character of text with same character in pattern
                else:
                    i=i+j+1 #if bad character is not present, jump pattern next to it
            else:
                k=1
                while text[i+j+k:i+len(pattern)] not in pattern[0:len(pattern)-1]: #used for finding sub part of a good-suffix
                    k=k+1
                if len(text[i+j+k:i+len(pattern)]) != 1: #good-suffix should not be of one character
                    gsshift=i+j+k-pattern[0:len(pattern)-1].rfind(text[i+j+k:i+len(pattern)]) #jumps pattern to a position where good-suffix of pattern matches with good-suffix of text
                else:
                    #gsshift=i+len(pattern)
                    gsshift=0 #when good-suffix heuristic is not applicable, we prefer bad character heuristic
                if text[i+j] in pattern[0:j]:
                    bcshift=i+j-pattern[0:j].rfind(text[i+j]) #i+j is index of bad character, this line is used for jumping pattern to match bad character of text with same character in pattern
                else:
                    bcshift=i+j+1
                i=max((bcshift, gsshift))
            break
    if flag: #if pattern is found then normal iteration
        matched_indexes.append(i)
        i = i+1
    else: #again set flag to True so new string in text can be examined
        flag = True

print ("Pattern found at", matched_indexes)

```

# 总结

在本章中，我们已经讨论了在实时场景中具有广泛应用的最流行和重要的字符串处理算法。我们从查看与字符串相关的基本概念和定义开始了本章。接下来，我们详细描述了用于模式匹配问题的暴力、Rabin-Karp、KMP 和 Boyer-Moore 模式匹配算法。我们已经看到，暴力模式匹配算法非常慢，因为它逐个比较模式和文本字符串的字符。

在模式匹配算法中，我们试图找到跳过不必要比较的方法，并尽快将模式移动到文本上，以快速找到匹配模式的位置。KMP 算法通过查看模式本身中的重叠子字符串来找出不必要的比较，以避免不重要的比较。此外，我们讨论了 Boyer-Moore 算法，在文本和模式很长时非常高效。这是实践中使用的最流行的模式匹配算法。

在下一章中，我们将更详细地讨论数据结构设计策略和技术。


# 第十三章：设计技术和策略

在本章中，我们退一步，关注计算机算法设计中更广泛的主题。随着编程经验的增长，某些模式开始变得明显。算法的世界包含了大量的技术和设计原则。掌握这些技术是解决该领域更难问题所必需的。

在本章中，我们将讨论不同类型算法的分类方式。将描述和说明设计技术。我们还将进一步讨论算法分析。最后，我们将提供一些非常重要算法的详细实现。

本章将涵盖以下主题：

+   算法的分类

+   各种算法设计方法

+   各种重要算法的实现和解释

# 技术要求

本章使用的源代码可在以下 GitHub 链接中找到：

[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-3.7-Second-Edition/tree/master/Chapter13`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-3.7-Second-Edition/tree/master/Chapter13)。

# 算法的分类

基于算法设计的目标，有许多分类方案。在之前的章节中，我们实现了各种算法。要问的问题是：这些算法是否具有相同的形式或相似之处？如果答案是肯定的，那么问：作为比较基础使用的相似之处和特征是什么？如果答案是否定的，那么这些算法能否被分成类别？

这些是我们将在随后的小节中讨论的问题。这里我们介绍了分类算法的主要方法。

# 按实现分类

将一系列步骤或流程翻译成工作算法时，可能采用多种形式。算法的核心可能使用以下一个或多个资产。

# 递归

递归算法是指调用自身以重复执行代码直到满足某个条件的算法。有些问题通过递归实现它们的解决方案更容易表达。一个经典的例子是汉诺塔。

简单来说，迭代函数是循环执行代码的一部分，而递归函数是调用自身来重复执行代码的函数。另一方面，迭代算法使用一系列步骤或重复结构来制定解决方案；它迭代执行代码的一部分。

这种重复结构可以是一个简单的`while`循环，或者任何其他类型的循环。迭代解决方案也比递归实现更容易想到。

# 逻辑

算法的一种实现是将其表达为受控逻辑推导。这个逻辑组件由将在计算中使用的公理组成。控制组件确定了推导应用到公理的方式。这表达为形式 a*lgorithm = logic + control*。这构成了逻辑编程范式的基础。

逻辑组件决定了算法的含义。控制组件只影响其效率。在不修改逻辑的情况下，可以通过改进控制组件来提高效率。

# 串行或并行算法

大多数计算机的 RAM 模型允许假设计算是一次执行一条指令的。

串行算法，也称为**顺序算法**，是按顺序执行的算法。执行从开始到结束进行，没有其他执行过程。

为了能够同时处理多条指令，需要不同的模型或计算技术。并行算法可以同时执行多个操作。在 PRAM 模型中，有共享全局内存的串行处理器。处理器还可以并行执行各种算术和逻辑操作。这使得可以同时执行多条指令。

并行/分布式算法将问题分解成子问题，分配给处理器来收集结果。一些排序算法可以有效地并行化，而迭代算法通常是可并行化的。

# 确定性与非确定性算法

确定性算法每次以相同的输入运行时都会产生相同的输出。有一些问题的解决方案设计非常复杂，以至于以确定性的方式表达它们的解决方案可能是一个挑战。

非确定性算法可以改变执行顺序或某些内部子过程，导致每次运行算法时最终结果都会发生变化。

因此，每次运行非确定性算法时，算法的输出都会不同。例如，使用概率值的算法将根据生成的随机数的值，在连续执行时产生不同的输出。

# 按复杂度分类

确定算法的复杂度是为了估计在计算或程序执行期间需要多少空间（内存）和时间。通常，通过它们的复杂度来比较两个算法的性能。较低复杂度的算法，即执行给定任务所需的空间和时间较少的算法，更受青睐。

第三章《算法设计原理》更全面地介绍了复杂性。我们将在这里总结我们所学到的内容。

# 复杂度曲线

让我们考虑一个规模为 n 的问题。为了确定算法的时间复杂度，我们用 T(n)表示。该值可能属于 O(1)、O(log n)、O(n)、O(n log(n))、O(n²)、O(n³)或 O(2^n)。根据算法执行的步骤，时间复杂度可能会受到影响。符号 O(n)捕捉了算法的增长率。

让我们现在来考虑一个实际的场景，来确定哪种算法更适合解决给定的问题。我们如何得出冒泡排序算法比快速排序算法慢的结论？或者，一般来说，我们如何衡量一个算法相对于另一个算法的效率？

好吧，我们可以比较任意数量的算法的大 O 来确定它们的效率。这种方法给我们提供了一个时间度量或增长率，它描述了算法在 n 变大时的行为。

这是一个图表，显示了算法性能可能属于的不同运行时间：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/92ff52c1-8d4d-4f7a-901f-117345b34c1d.png)

按照从最好到最差的顺序，运行时间的列表为 O(1)、O(log n)、O(n)、O(n log n)、O(n²)、O(n³)和 O(2^n)。因此，如果一个算法的时间复杂度为 O(1)，而另一个算法的复杂度为 O(log n)，应该选择第一个算法。

# 按设计分类

在本节中，我们根据它们的设计提出了算法的分类。

一个给定的问题可能有多种解决方案。当分析这些解决方案时，可以观察到每个解决方案都遵循某种模式或技术。我们可以根据它们解决问题的方式对算法进行分类，如下面的小节所示。

# 分而治之

这种问题解决方法正如其名称所示。为了解决（征服）某个问题，算法将其分解为可以轻松解决的子问题。此外，这些子问题的解决方案被组合在一起，以便最终解决方案是原始问题的解决方案。

问题被分解为更小的子问题的方式大多是通过递归完成的。我们将在随后的小节中详细讨论这种技术。使用这种技术的一些算法包括归并排序、快速排序和二分查找。

# 动态规划

这种技术与分而治之类似，即将问题分解为更小的问题。然而，在分而治之中，必须先解决每个子问题，然后才能用其结果来解决更大的问题。

相比之下，动态规划不会计算已经遇到的子问题的解决方案。相反，它使用一种记忆技术来避免重新计算。

动态规划问题具有两个特征——**最优子结构**和**重叠子问题**。我们将在下一节进一步讨论这一点。

# 贪婪算法

确定某个问题的最佳解决方案可能会非常困难。为了克服这一点，我们采用一种方法，从多个可用选项或选择中选择最有前途的选择。

使用贪婪算法，指导规则是始终选择产生最有利的结果的选项，并继续这样做，希望达到完美的解决方案。这种技术旨在通过一系列局部最优选择找到全局最优的最终解决方案。局部最优选择似乎导致解决方案。

# 技术实现

让我们深入讨论一些我们讨论过的理论编程技术的实现。我们从动态规划开始。

# 使用动态规划进行实现

正如我们已经描述的，在这种方法中，我们将给定的问题分解为更小的子问题。在找到解决方案时，要注意不要重新计算任何先前遇到的子问题。

这听起来有点像递归，但这里有些不同。一个问题可能适合使用动态规划来解决，但不一定需要形成递归调用的形式。

使问题成为动态规划的理想候选者的一个特性是它具有**重叠的子问题集**。

一旦我们意识到在计算过程中子问题的形式已经重复，我们就不需要再次计算它。相反，我们返回先前遇到的子问题的预先计算结果。

为了确保我们永远不必重新评估子问题，我们需要一种有效的方法来存储每个子问题的结果。以下两种技术是 readily available。

# 记忆化

这种技术从初始问题集开始，将其分解为小的子问题。在确定了子程序的解决方案之后，我们将结果存储到该特定子问题中。将来，当遇到这个子问题时，我们只返回其预先计算的结果。

# 制表

在制表中，我们填充一个表格，其中包含子问题的解决方案，然后将它们组合起来解决更大的问题。

# 斐波那契数列

让我们考虑一个例子来理解动态规划的工作原理。我们使用斐波那契数列来说明记忆化和制表技术。

斐波那契数列可以使用递推关系来演示。递推关系是用来定义数学函数或序列的递归函数。例如，以下递推关系定义了斐波那契数列[1, 1, 2, 3, 5, 8 ...]：

```py
func(1) = 1
func(0) = 1 
func(n) = func(n-1) + func(n-2)
```

请注意，斐波那契数列可以通过将*n*的值放入序列[1, 2, 3, 4, ...]来生成。

# 记忆化技术

让我们生成斐波那契数列的前五项：

```py
    1 1 2 3 5
```

生成序列的递归式程序如下：

```py
 def fib(n): 
    if n <= 2: 
       return 1 
    else: 
       return fib(n-1) + fib(n-2) 
```

代码非常简单，但由于递归调用的存在，读起来有点棘手，因为最终解决了问题。

当满足基本情况时，`fib()`函数返回 1。如果*n*等于或小于 2，则满足基本情况。

如果未满足基本情况，我们将再次调用`fib()`函数，并这次将第一个调用提供`n-1`，第二个提供`n-2`：

```py
    return fib(n-1) + fib(n-2) 
```

解决斐波那契数列中的第`i^(th)`项的策略布局如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d80891b2-a57d-4b44-9630-76fafc37a303.png)

对树状图的仔细观察显示了一些有趣的模式。对**fib(1)**的调用发生了两次。对**fib(2)**的调用发生了三次。此外，对**fib(3)**的调用发生了两次。

相同函数调用的返回值永远不会改变；例如，每当我们调用**fib(2)**时，其返回值始终相同。**fib(1)**和**fib(3)**也是如此。因此，如果我们每次遇到相同的函数时都重新计算，将浪费计算时间，因为返回的结果相同。

对具有相同参数和输出的函数的重复调用表明存在重叠。某些计算在较小的子问题中重复出现。

更好的方法是在首次遇到**fib(1)**时存储计算结果。同样，我们应该存储**fib(2)**和**fib(3)**的返回值。稍后，每当我们遇到对**fib(1)**、**fib(2)**或**fib(3)**的调用时，我们只需返回它们各自的结果。

我们的`fib`调用的图现在看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/f7165fe9-182b-46e1-9d5d-e83ea6187486.png)

如果多次遇到，我们已经消除了计算**fib(3)**，fib(2)和**fib(1)**的需要。这是备忘录技术的典型，其中在将问题分解为子问题时，不会重新计算重叠调用函数。

我们斐波那契示例中的重叠函数调用是**fib(1)**、**fib(2)**和**fib(3)**：

```py
    def dyna_fib(n, lookup): 
        if n <= 2: 
            lookup[n] = 1 

        if lookup[n] is None: 
            lookup[n] = dyna_fib(n-1, lookup) + dyna_fib(n-2, lookup) 

        return lookup[n]
```

要创建一个包含 1,000 个元素的列表，我们执行以下操作，并将其传递给`dyna_fib`函数的 lookup 参数：

```py
    map_set = [None]*(1000)
```

这个列表将存储对`dyna_fib()`函数的各种调用的计算值：

```py
    if n <= 2: 
        lookup[n] = 1 
```

对于`dyna_fib()`函数的任何小于或等于 2 的*n*的调用都将返回 1。当评估`dyna_fib(1)`时，我们将值存储在`map_set`的索引 1 处。

将`lookup[n]`的条件写为以下内容：

```py
if lookup[n] is None:
    lookup[n] = dyna_fib(n-1, lookup) + dyna_fib(n-2, lookup)
```

我们传递 lookup，以便在评估子问题时可以引用它。对`dyna_fib(n-1, lookup)`和`dyna_fib(n-2, lookup)`的调用存储在`lookup[n]`中。

当我们运行函数的更新实现以找到斐波那契数列的第`*i*^(th)`项时，我们可以看到显着的改进。这个实现比我们最初的实现运行得快得多。将值 20 提供给这两个实现，并观察执行速度的差异。

然而，由于使用额外的内存存储函数调用的结果，更新后的算法牺牲了空间复杂度。

# 表格法

动态规划中的第二种技术涉及使用结果表或在某些情况下使用矩阵来存储计算结果以供以后使用。

这种方法通过首先解决最终解决方案的路径来解决更大的问题。对于`fib()`函数，我们开发了一个表，其中预先确定了`fib(1)`和`fib(2)`的值。基于这两个值，我们将逐步计算`fib(n)`：

```py
    def fib(n): 

        results = [1, 1] 

        for i in range(2, n): 
            results.append(results[i-1] + results[i-2]) 

        return results[-1]
```

`results`变量在索引 0 和 1 处存储值 1 和 1。这代表`fib(1)`和`fib(2)`的返回值。要计算大于 2 的值的`fib()`函数的值，我们只需调用`for`循环，将`results[i-1] + results[i-2]`的和附加到结果列表中。

# 使用分治法实现

这种编程方法强调将问题分解为与原始问题相同类型或形式的较小子问题的需要。这些子问题被解决并组合以获得原始问题的解决方案。

以下三个步骤与这种编程相关。

# 划分

划分意味着分解实体或问题。在这里，我们设计手段将原始问题分解为子问题。我们可以通过迭代或递归调用来实现这一点。

# 征服

无法无限地继续将问题分解为子问题。在某个时候，最小的不可分割问题将返回一个解决方案。一旦这种情况发生，我们可以扭转我们的思维过程，并说如果我们知道最小子问题的解决方案，我们就可以获得原始问题的最终解决方案。

# 合并

为了得到最终解决方案，我们需要结合较小问题的解决方案来解决更大的问题。

还有其他变体的分而治之算法，例如合并和组合，征服和解决。许多算法使用分而治之原则，例如归并排序、快速排序和 Strassen 矩阵乘法。

我们现在将描述归并排序算法的实现，就像我们在第三章“算法设计原理”中看到的那样。

# 归并排序

归并排序算法基于分而治之的原则。给定一列未排序的元素，我们将列表分成两个近似的部分。我们继续递归地将列表分成两半。

经过一段时间，由于递归调用而创建的子列表将只包含一个元素。在那时，我们开始在征服或合并步骤中合并解决方案：

```py
    def merge_sort(unsorted_list): 
        if len(unsorted_list) == 1: 
            return unsorted_list 

        mid_point = int((len(unsorted_list))//2) 

        first_half = unsorted_list[:mid_point] 
        second_half = unsorted_list[mid_point:] 

        half_a = merge_sort(first_half) 
        half_b = merge_sort(second_half) 

        return merge(half_a, half_b) 
```

我们的实现从将未排序的元素列表传递到`merge_sort`函数开始。`if`语句用于建立基本情况，即如果`unsorted_list`中只有一个元素，我们只需再次返回该列表。如果列表中有多于一个元素，我们使用`mid_point = int((len(unsorted_list)) // 2)`找到近似中间位置。

使用这个`mid_point`，我们将列表分成两个子列表，即`first_half`和`second_half`：

```py
    first_half = unsorted_list[:mid_point] 
    second_half = unsorted_list[mid_point:] 
```

通过将这两个子列表再次传递给`merge_sort`函数来进行递归调用：

```py
    half_a = merge_sort(first_half)  
    half_b = merge_sort(second_half)
```

现在是合并步骤。当`half_a`和`half_b`传递了它们的值后，我们调用`merge`函数，该函数将合并或组合存储在`half_a`和`half_b`中的两个解决方案，即列表：

```py
 def merge(first_sublist, second_sublist): 
     i = j = 0 
     merged_list = [] 

     while i < len(first_sublist) and j < len(second_sublist): 
         if first_sublist[i] < second_sublist[j]: 
             merged_list.append(first_sublist[i]) 
             i += 1 
         else: 
             merged_list.append(second_sublist[j]) 
             j += 1 

     while i < len(first_sublist): 
         merged_list.append(first_sublist[i]) 
         i += 1 

     while j < len(second_sublist): 
         merged_list.append(second_sublist[j]) 
         j += 1 

     return merged_list 
```

`merge`函数接受我们要合并的两个列表`first_sublist`和`second_sublist`。`i`和`j`变量被初始化为 0，并用作指针，告诉我们在合并过程中两个列表的位置。

最终的`merged_list`将包含合并后的列表：

```py
    while i < len(first_sublist) and j < len(second_sublist): 
        if first_sublist[i] < second_sublist[j]: 
            merged_list.append(first_sublist[i]) 
            i += 1 
        else: 
            merged_list.append(second_sublist[j]) 
            j += 1 
```

`while`循环开始比较`first_sublist`和`second_sublist`中的元素。`if`语句选择两者中较小的一个，`first_sublist[i]`或`second_sublist[j]`，并将其附加到`merged_list`。`i`或`j`索引递增以反映我们在合并步骤中的位置。当任一子列表为空时，`while`循环停止。

可能会有元素留在`first_sublist`或`second_sublist`中。最后两个`while`循环确保这些元素在返回`merged_list`之前被添加。

对`merge(half_a, half_b)`的最后调用将返回排序后的列表。

让我们通过合并两个子列表`[4, 6, 8]`和`[5, 7, 11, 40]`来对算法进行干扰运行：

| **步骤** | `first_sublist` | `second_sublist` | `merged_list` |
| --- | --- | --- | --- |
| 步骤 0 | `[4 6 8]` | `[5 7 11 40]` | `[]` |
| 步骤 1 | `[ 6 8]` | `[5 7 11 40]` | `[4]` |
| 步骤 2 | `[ 6 8]` | `[ 7 11 40]` | `[4 5]` |
| 步骤 3 | `[ 8]` | `[ 7 11 40]` | `[4 5 6]` |
| 步骤 4 | `[ 8]` | `[ 11 40]` | `[4 5 6 7]` |
| 步骤 5 | `[ ]` | `[ 11 40]` | `[4 5 6 7 8]` |
| 步骤 6 | `[]` | `[ ]` | `[4 5 6 7 8 11 40]` |

注意粗体文本代表循环中当前项的引用，`first_sublist`（使用`i`索引）和`second_sublist`（使用`j`索引）。

在执行的这一点上，合并函数中的第三个`while`循环开始将 11 和 40 移入`merged_list`。返回的`merged_list`将包含完全排序的列表。

请注意，合并算法需要`O(n)`的时间，而合并排序算法的运行时间复杂度为`O(log n) T(n) = O(n)*O(log n) = O(n log n)`。

# 使用贪婪算法的实现

正如我们之前讨论的，贪婪算法做出决策以产生最佳的局部解决方案，从而提供最佳解决方案。这种技术的希望是，通过在每一步做出最佳选择，总路径将导致整体最优解决方案或结束。

贪婪算法的例子包括用于查找最小生成树的**Prim 算法**、**背包问题**和**旅行推销员问题**。

# 硬币计数问题

为了演示贪婪技术的工作原理，让我们看一个例子。考虑一个问题，我们希望计算使给定金额 A 所需的最小硬币数量，其中我们有给定硬币值的无限供应。

例如，在某个任意国家，我们有以下硬币面额：1、5 和 8 GHC。给定一个金额（例如 12 GHC），我们想要找到提供这个金额所需的最少硬币数量。

使用面额`{a[1],a[2],a[3]...a[n]}`来提供给定金额 A 的最小硬币数量的算法如下：

1.  我们对面额列表`{a[1], a[2], a[3] ...a[n]}`进行排序。

1.  我们得到小于 A 的`{a[1], a[2], a[3]...a[n]}`中的最大面额。

1.  我们通过将 A 除以最大面额来获得商。

1.  我们通过使用（A % 最大面额）来获得剩余金额 A。

1.  如果 A 的值变为 0，则返回结果。

1.  否则，如果 A 的值大于 0，我们将最大面额和商变量附加到结果变量中。并重复步骤 2-5。

使用贪婪方法，我们首先选择可用面额中的最大值——8——来除以 12。余数 4 既不能被 8 整除，也不能被比 8 更小的面额 5 整除。所以，我们尝试 1 GHC 面额的硬币，需要四个。最终，使用这种贪婪算法，我们返回了一个 8 GHC 硬币和四个 1 GHC 硬币的答案。

到目前为止，我们的贪婪算法似乎表现得相当不错。返回相应面额的函数如下：

```py
    def basic_small_change(denom, total_amount): 
        sorted_denominations = sorted(denom, reverse=True) 

        number_of_denoms = [] 

        for i in sorted_denominations: 
            div = total_amount // i 
            total_amount = total_amount % i 
            if div > 0: 
                number_of_denoms.append((i, div)) 

        return number_of_denoms
```

这种贪婪算法总是从可能的最大面额开始。注意`denom`是一个面额列表，`sorted(denom, reverse=True)`会将列表按照相反的顺序排序，这样我们就可以在索引`0`处获得最大面额。现在，从排序后的面额列表`sorted_denominations`的索引`0`开始，我们迭代并应用贪婪技术：

```py
    for i in sorted_denominations: 
        div = total_amount // i 
        total_amount = total_amount % i 
        if div > 0: 
            number_of_denoms.append((i, div)) 
```

循环将遍历面额列表。每次循环运行时，它通过将`total_amount`除以当前面额*i*来获得商`div`。`total_amount`变量被更新以存储余数以供进一步处理。如果商大于 0，我们将其存储在`number_of_denoms`中。

然而，有一些可能的情况下这种算法可能会失败。例如，当传入 12 GHC 时，我们的算法返回了一个 8 GHC 和四个 1 GHC 硬币。然而，这个输出并不是最优解。最佳解是使用两个 5 GHC 和两个 1 GHC 硬币。

这里提出了一个更好的贪婪算法。这次，函数返回一个允许我们调查最佳结果的元组列表：

```py
    def optimal_small_change(denom, total_amount): 

        sorted_denominations = sorted(denom, reverse=True) 

        series = [] 
        for j in range(len(sorted_denominations)): 
            term = sorted_denominations[j:] 

            number_of_denoms = [] 
            local_total = total_amount 
            for i in term: 
                div = local_total // i 
                local_total = local_total % i 
                if div > 0: 
                    number_of_denoms.append((i, div)) 

            series.append(number_of_denoms) 

        return series
```

外部`for`循环使我们能够限制我们找到解决方案的面额：

```py
    for j in range(len(sorted_denominations)): 
        term = sorted_denominations[j:] 
        ...     
```

假设我们有列表[5, 4, 3]，在`sorted_denominations`中对其进行切片`[j:]`有助于我们获得子列表[5, 4, 3]，[4, 3]和[3]，从中我们尝试找到正确的组合。

# 最短路径算法

最短路径问题要求我们找出图中节点之间最短可能的路径。在制定从点 A 到点 B 的最有效路径时，这对于地图和路径规划具有重要应用。

迪杰斯特拉算法是解决这个问题的一种非常流行的方法。该算法用于在图中找到从源到所有其他节点或顶点的最短距离。在这里，我们解释了如何使用贪婪方法来解决这个问题。

迪杰斯特拉算法适用于加权有向和无向图。该算法产生了从加权图中给定源节点 A 到最短路径的列表的输出。算法的工作原理如下：

1.  最初，将所有节点标记为未访问，并将它们从给定源节点的距离设置为无穷大（源节点设置为零）。

1.  将源节点设置为当前节点。

1.  对于当前节点，查找所有未访问的相邻节点；计算从源节点通过当前节点到该节点的距离。将新计算的距离与当前分配的距离进行比较，如果更小，则将其设置为新值。

1.  一旦我们考虑了当前节点的所有未访问的相邻节点，我们将其标记为已访问。

1.  接下来，考虑下一个未访问的节点，该节点距离源节点最近。重复步骤 2 到 4。

1.  当未访问节点的列表为空时，我们停止，这意味着我们已经考虑了所有未访问的节点。

考虑以下带有六个节点[A，B，C，D，E，F]的加权图的示例，以了解迪杰斯特拉算法的工作原理：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/30207f74-106b-4b35-8d06-0cf1a2377a4f.png)

通过手动检查，最初看起来节点 A 和节点 D 之间的最短路径似乎是距离为 9 的直线。然而，最短路径意味着最低总距离，即使这包括几个部分。相比之下，从节点 A 到节点 E，然后到节点 F，最后到节点 D 的旅行将产生总距离为 7，这使得它成为更短的路径。

我们将使用单源最短路径算法。它将确定从原点（在本例中为 A）到图中任何其他节点的最短路径。

在第八章中，*图和其他算法*，我们讨论了如何用邻接列表表示图。我们使用邻接列表以及每条边上的权重/成本/距离来表示图，如下面的 Python 代码所示。表用于跟踪从图中源到任何其他节点的最短距离。Python 字典将用于实现此表。

这是起始表：

| **节点** | **距离源的最短距离** | **前一个节点** |
| --- | --- | --- |
| **A** | 0 | None |
| **B** | ∞ | None |
| **C** | ∞ | None |
| **D** | ∞ | None |
| **E** | ∞ | None |
| **F** | ∞ | None |

图和表的邻接列表如下：

```py
    graph = dict() 
    graph['A'] = {'B': 5, 'D': 9, 'E': 2} 
    graph['B'] = {'A': 5, 'C': 2} 
    graph['C'] = {'B': 2, 'D': 3} 
    graph['D'] = {'A': 9, 'F': 2, 'C': 3} 
    graph['E'] = {'A': 2, 'F': 3} 
    graph['F'] = {'E': 3, 'D': 2} 
```

嵌套字典保存了距离和相邻节点。

当算法开始时，给定源节点（A）到任何节点的最短距离是未知的。因此，我们最初将所有其他节点的距离设置为无穷大，除了节点 A，因为从节点 A 到节点 A 的距离为 0。

当算法开始时，没有先前的节点被访问。因此，我们将节点 A 的前一个节点列标记为 None。

在算法的第一步中，我们开始检查节点 A 的相邻节点。要找到从节点 A 到节点 B 的最短距离，我们需要找到从起始节点到节点 B 的前一个节点的距离，这恰好是节点 A，并将其添加到从节点 A 到节点 B 的距离。我们对 A 的其他相邻节点（B、E 和 D）也是这样做的。这在下图中显示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/9745d5ee-f528-4bd2-b67b-181e3655f5c4.png)

我们将相邻节点 B 作为其从节点 A 的距离最小；从起始节点（A）到前一个节点（None）的距离为 0，从前一个节点到当前节点（B）的距离为 5。这个和与节点 B 的最短距离列中的数据进行比较。由于 5 小于无穷大（∞），我们用两者中较小的 5 替换∞。

每当一个节点的最短距离被较小的值替换时，我们需要为当前节点的所有相邻节点更新前一个节点列。之后，我们将节点 A 标记为已访问：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/220248fc-eec9-4d42-9d69-1ac4a8ca26a2.png)

在第一步结束时，我们的表如下所示：

| **节点** | **源的最短距离** | **前一个节点** |
| --- | --- | --- |
| **A*** | 0 | None |
| B | 5 | A |
| C | ∞ | None |
| D | 9 | A |
| E | 2 | A |
| F | ∞ | None |

此时，节点 A 被视为已访问。因此，我们将节点 A 添加到已访问节点的列表中。在表中，我们通过将文本加粗并在其后附加星号来显示节点 A 已被访问。

在第二步中，我们使用我们的表找到最短距离的节点作为指南。节点 E 的值为 2，具有最短距离。这是我们从节点 E 的表中可以推断出来的。要到达节点 E，我们必须访问节点 A 并覆盖距离 2。从节点 A，我们覆盖 0 的距离到达起始节点，即节点 A 本身。

节点 E 的相邻节点是 A 和 F。但是节点 A 已经被访问过，所以我们只考虑节点 F。要找到到节点 F 的最短路径或距离，我们必须找到从起始节点到节点 E 的距离，并将其添加到节点 E 和 F 之间的距离。我们可以通过查看节点 E 的最短距离列来找到从起始节点到节点 E 的距离，其值为 2。从节点 E 到 F 的距离可以从我们在本节早些时候开发的 Python 中的邻接列表中获得。

这个距离是 3。这两个加起来是 5，小于无穷大。记住我们正在检查相邻的节点 F。由于节点 E 没有更多相邻的节点，我们将节点 E 标记为已访问。我们更新的表和图将具有以下值：

| **节点** | **源的最短距离** | **前一个节点** |
| --- | --- | --- |
| **A*** | 0 | None |
| B | 5 | A |
| C | ∞ | None |
| D | 9 | A |
| **E*** | 2 | A |
| F | 5 | E |

访问节点 E 后，我们在表的最短距离列中找到最小值，即节点 B 和 F 的值为 5。让我们选择 B 而不是 F，纯粹基于字母顺序（我们也可以选择 F）。

节点 B 的相邻节点是 A 和 C，但是节点 A 已经被访问。根据我们之前建立的规则，从 A 到 C 的最短距离是 7。我们得到这个数字是因为从起始节点到节点 B 的距离是 5，而从节点 B 到 C 的距离是 2。

由于 7 小于无穷大，我们将最短距离更新为 7，并用节点 B 更新前一个节点列：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/b6437e76-eaf8-4d3c-910e-cb5751588c6d.png)

现在，B 也被标记为已访问。表和图的新状态如下：

| **节点** | **源的最短距离** | **前一个节点** |
| --- | --- | --- |
| **A*** | 0 | None |
| **B*** | 5 | A |
| C | 7 | B |
| D | 9 | A |
| **E*** | 2 | A |
| F | 5 | E |

最短距离但尚未访问的节点是节点**F**。**F**的相邻节点是节点**D**和**E**。但是节点**E**已经被访问过。因此，我们专注于找到从起始节点到节点**D**的最短距离。

我们通过将从节点**A**到**F**的距离与从节点**F**到**D**的距离相加来计算这个距离。这相加得到 7，小于**9**。因此，我们将**9**更新为**7**，并在节点**D**的上一个节点列中用**F**替换**A**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d4a2d0a8-6a4e-46d5-b469-37674c0617df.png)

节点**F**现在被标记为已访问。这是更新后的表格和到目前为止的图：

| **Node** | **Shortest distance from source** | **Previous node** |
| --- | --- | --- |
| **A*** | 0 | None |
| **B*** | 5 | A |
| C | 7 | B |
| D | 7 | F |
| **E*** | 2 | A |
| **F*** | 5 | E |

现在，只剩下两个未访问的节点，**C**和**D**，都具有距离成本为**7**。按字母顺序，我们选择检查**C**，因为这两个节点都与起始节点**A**的最短距离相同：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/09e116c0-42d5-430f-95d8-3b10bf5f1788.png)

然而，所有与**C**相邻的节点都已经被访问。因此，我们除了将节点**C**标记为已访问外，没有其他事情要做。此时表格保持不变：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d5ea3951-91ea-4723-8337-4d655593f431.png)

最后，我们取节点**D**，发现它的所有相邻节点也都已经被访问。我们只将其标记为已访问。表格保持不变：

| **Node** | **Shortest distance from source** | **Previous node** |
| --- | --- | --- |
| **A*** | 0 | None |
| **B*** | 5 | A |
| **C*** | 7 | B |
| **D*** | 7 | F |
| **E*** | 2 | A |
| **F*** | 5 | E |

让我们用我们的初始图表来验证这个表格。从图表中，我们知道从**A**到**F**的最短距离是**5**。我们需要通过**E**到达节点**F**：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/93a5e488-c767-400f-8fcb-4a27523a7e7d.png)

根据表格，从源列到节点**F**的最短距离是 5。这是正确的。它还告诉我们，要到达节点**F**，我们需要访问节点**E**，然后从**E**到节点**A**，这实际上是最短路径。

为了实现 Dijkstra 算法以找到最短路径，我们开始编写程序，通过表示能够跟踪图中变化的表格来找到最短距离。对于我们使用的图表，这是表格的字典表示：

```py
    table = dict() 
    table = { 
        'A': [0, None], 
        'B': [float("inf"), None], 
        'C': [float("inf"), None], 
        'D': [float("inf"), None], 
        'E': [float("inf"), None], 
        'F': [float("inf"), None], 
    } 
```

表格的初始状态使用`float("inf")`表示无穷大。字典中的每个键映射到一个列表。在列表的第一个索引处，存储了从源头 A 到达的最短距离。在第二个索引处，存储了上一个节点：

```py
    DISTANCE = 0 
    PREVIOUS_NODE = 1 
    INFINITY = float('inf') 
```

为了避免使用魔术数字，我们使用前面的常量。最短路径列的索引由`DISTANCE`引用。上一个节点列的索引由`PREVIOUS_NODE`引用。

现在一切都准备就绪，算法的主要函数将接受图（由邻接列表表示）、表格和起始节点作为参数：

```py
    def find_shortest_path(graph, table, origin): 
        visited_nodes = [] 
        current_node = origin 
        starting_node = origin 
```

我们将访问过的节点列表保存在`visited_nodes`列表中。`current_node`和`starting_node`变量都将指向我们选择的图中的起始节点。`origin`值是相对于找到最短路径的其他节点的参考点。

整个过程的重要工作是通过使用`while`循环完成的：

```py
    while True: 
        adjacent_nodes = graph[current_node] 
        if set(adjacent_nodes).issubset(set(visited_nodes)): 
            # Nothing here to do. All adjacent nodes have been visited. 
            pass 
        else: 
            unvisited_nodes = 
                set(adjacent_nodes).difference(set(visited_nodes)) 
            for vertex in unvisited_nodes: 
                distance_from_starting_node = 
                    get_shortest_distance(table, vertex) 
                if distance_from_starting_node == INFINITY and 
                   current_node == starting_node: 
                    total_distance = get_distance(graph, vertex, 
                                                  current_node) 
                else: 
                    total_distance = get_shortest_distance (table, 
                    current_node) + get_distance(graph, current_node, 
                                                 vertex) 

                if total_distance < distance_from_starting_node: 
                    set_shortest_distance(table, vertex, 
                                          total_distance) 
                    set_previous_node(table, vertex, current_node) 

        visited_nodes.append(current_node) 

        if len(visited_nodes) == len(table.keys()): 
            break 

        current_node = get_next_node(table,visited_nodes) 
```

让我们分解一下`while`循环在做什么。在`while`循环的主体中，我们获取我们想要调查的图中的当前节点，使用`adjacent_nodes = graph[current_node]`。现在，`current_node`应该在之前已经设置好。`if`语句用于查找`current_node`的所有相邻节点是否都已经被访问。

当`while`循环第一次执行时，`current_node`将包含 A，`adjacent_nodes`将包含节点 B、D 和 E。此外，`visited_nodes`也将为空。如果所有节点都已经被访问，我们只会继续执行程序中的其他语句。否则，我们将开始一个全新的步骤。

语句`set(adjacent_nodes).difference(set(visited_nodes))`返回尚未访问的节点。循环遍历这个未访问的节点列表：

```py
    distance_from_starting_node = get_shortest_distance(table, vertex) 
```

`get_shortest_distance(table, vertex)`辅助方法将返回我们表中最短距离列中存储的值，使用`vertex`引用的未访问节点之一：

```py
    if distance_from_starting_node == INFINITY and current_node == starting_node: 
         total_distance = get_distance(graph, vertex, current_node) 
```

当我们检查起始节点的相邻节点时，`distance_from_starting_node == INFINITY and current_node == starting_node` 将评估为 `True`，在这种情况下，我们只需要通过引用图找到起始节点和顶点之间的距离：

```py
    total_distance = get_distance(graph, vertex, current_node)
```

`get_distance`方法是我们用来获取`vertex`和`current_node`之间的边的值（距离）的另一个辅助方法。

如果条件失败，那么我们将把`total_distance`赋值为从起始节点到`current_node`的距离和`current_node`到`vertex`的距离之和。

一旦我们有了总距离，我们需要检查`total_distance`是否小于我们表中最短距离列中的现有数据。如果是，我们就使用这两个辅助方法来更新该行：

```py
    if total_distance < distance_from_starting_node: 
        set_shortest_distance(table, vertex, total_distance) 
    set_previous_node(table, vertex, current_node) 
```

此时，我们将`current_node`添加到已访问节点列表中：

```py
    visited_nodes.append(current_node) 
```

如果所有节点都已经被访问，那么我们必须退出`while`循环。为了检查所有节点是否都已经被访问，我们将`visited_nodes`列表的长度与我们表中的键的数量进行比较。如果它们相等，我们就简单地退出`while`循环。

`get_next_node`辅助方法用于获取下一个要访问的节点。正是这个方法帮助我们使用我们的表从起始节点中找到最短距离列中的最小值。

整个方法最终返回更新后的表。要打印表，我们使用以下语句：

```py
 shortest_distance_table = find_shortest_path(graph, table, 'A') 
 for k in sorted(shortest_distance_table): 
     print("{} - {}".format(k,shortest_distance_table[k])) 
```

这是前面语句的输出：

```py
>>> A - [0, None] B - [5, 'A'] C - [7, 'B'] D - [7, 'F'] E - [2, 'A'] F - [5, 'E']
```

为了完整起见，让我们找出这些辅助方法在做什么：

```py
    def get_shortest_distance(table, vertex): 
        shortest_distance = table[vertex][DISTANCE] 
        return shortest_distance 
```

`get_shortest_distance`函数返回我们表中索引 0 处存储的值。在该索引处，我们始终存储从起始节点到`vertex`的最短距离。`set_shortest_distance`函数只设置该值如下：

```py
    def set_shortest_distance(table, vertex, new_distance): 
        table[vertex][DISTANCE] = new_distance 
```

当我们更新节点的最短距离时，我们使用以下方法更新其上一个节点：

```py
    def set_previous_node(table, vertex, previous_node): 
        table[vertex][PREVIOUS_NODE] = previous_node 
```

请记住，`PREVIOUS_NODE`常量等于 1。在表中，我们将`previous_node`的值存储在`table[vertex][PREVIOUS_NODE]`处。

为了找到任意两个节点之间的距离，我们使用`get_distance`函数：

```py
    def get_distance(graph, first_vertex, second_vertex): 
        return graph[first_vertex][second_vertex] 
```

最后的辅助方法是`get_next_node`函数：

```py
    def get_next_node(table, visited_nodes): 
        unvisited_nodes = 
            list(set(table.keys()).difference(set(visited_nodes))) 
        assumed_min = table[unvisited_nodes[0]][DISTANCE] 
        min_vertex = unvisited_nodes[0] 
        for node in unvisited_nodes: 
            if table[node][DISTANCE] < assumed_min: 
                assumed_min = table[node][DISTANCE] 
                min_vertex = node 

        return min_vertex 
```

`get_next_node`函数类似于在列表中找到最小项的函数。

该函数首先通过使用`visited_nodes`来获取两个列表集合的差异来找到我们表中未访问的节点。`unvisited_nodes`列表中的第一项被假定为`table`中最短距离列中的最小值。

如果在`for`循环运行时找到了更小的值，`min_vertex`将被更新。然后函数将`min_vertex`作为未访问的顶点或距离源点最短的节点返回。

Dijkstra 算法的最坏运行时间是**O**(*|E| + |V| log |V|*)，其中*|V|*是顶点数，*|E|*是边数。

# 复杂度类

复杂度类根据问题的难度级别以及解决它们所需的时间和空间资源进行分组。在本节中，我们讨论了 N、NP、NP-Complete 和 NP-Hard 复杂度类。

# P 与 NP

计算机的出现加快了某些任务的执行速度。总的来说，计算机擅长完善计算的艺术和解决可以归结为一组数学计算的问题。

然而，这种说法并非完全正确。有一些类别的问题对计算机来说需要大量时间来做出合理的猜测，更不用说找到正确的解决方案了。

在计算机科学中，计算机可以使用逻辑步骤的逐步过程在多项式时间内解决的问题类别被称为 P 类型，其中 P 代表多项式。这些问题相对容易解决。

然后还有另一类被认为很难解决的问题。术语*难问题*用于指代在寻找解决方案时问题难度增加的方式。然而，尽管这些问题的难度增长率很高，但可以确定一个提议的解决方案是否在多项式时间内解决问题。这些被称为 NP 类型问题。这里的 NP 代表非确定性多项式时间。

现在百万美元的问题是，*P = NP*吗？

P* = NP*的证明是克莱数学研究所的百万美元问题之一，为正确解决方案提供了百万美元的奖金。

旅行推销员问题是 NP 类型问题的一个例子。问题陈述如下：在一个国家中给定*n*个城市，找到它们之间的最短路线，从而使旅行成本有效。

当城市数量较小时，这个问题可以在合理的时间内解决。然而，当城市数量超过两位数时，计算机所需的时间就会非常长。

许多计算机和网络安全系统都基于 RSA 加密算法。该算法的强度基于它使用的整数因子问题，这是一个 NP 类型问题。

找到由许多位数组成的质数的质因数是非常困难的。当两个大质数相乘时，得到一个大的非质数。这个数的因数分解是许多加密算法借用其强度的地方。

所有 P 类型问题都是**NP**问题的子集。这意味着任何可以在多项式时间内解决的问题也可以在多项式时间内验证：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/cfbbc0d9-bc13-467e-aeb5-982db9ad6891.png)

但是**P** = **NP**调查了可以在多项式时间内验证的问题是否也可以在多项式时间内解决。特别是，如果它们相等，这意味着可以在不需要实际尝试所有可能的解决方案的情况下解决通过尝试多个可能解决方案来解决的问题，从而不可避免地产生某种快捷证明。

当最终发现证明时，它肯定会对密码学、博弈论、数学和许多其他领域产生严重影响。

# NP-Hard

如果 NP 中的所有其他问题都可以在多项式时间内可归约或映射到它，那么问题就是 NP-Hard。它至少和 NP 中最难的问题一样难。

# NP-Complete

**NP-Complete**问题是最困难的问题。如果一个问题是**NP-Hard**问题，同时也在**NP**类中找到，那么它被认为是**NP-Complete**问题。

在这里，我们展示了各种复杂性群的维恩图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/c47f7c29-0359-481b-b287-34e5ca2e9a45.png)

# 数据中的知识发现

为了从给定数据中提取有用信息，我们首先收集要用于学习模式的原始数据。接下来，我们应用数据预处理技术来去除数据中的噪音。此外，我们从数据中提取重要特征，这些特征代表了数据，用于开发模型。特征提取是机器学习算法有效工作的最关键步骤。一个好的特征必须对机器学习算法具有信息量和区分度。特征选择技术用于去除不相关、冗余和嘈杂的特征。此外，突出的特征被输入到机器学习算法中，以学习数据中的模式。最后，我们应用评估措施来评判开发模型的性能，并使用可视化技术来可视化结果和数据。以下是步骤：

1.  数据收集

1.  数据预处理

1.  特征提取

1.  特征选择

1.  机器学习

1.  评估和可视化

# 总结

在本章中，我们详细讨论了算法设计技术，在计算机科学领域非常重要。在没有太多数学严谨的情况下，我们还讨论了一些算法分类的主要类别。

该领域中的其他设计技术，如分治、动态规划和贪婪算法，也被涵盖，以及重要样本算法的实现。最后，我们对复杂度类进行了简要讨论。我们看到，如果 P = NP 的证明被发现，它肯定会在许多领域产生重大影响。

在下一章中，我们将讨论一些真实世界的应用、工具和机器学习应用的基础知识。


# 第十四章：实现、应用和工具

学习算法而没有任何现实生活的应用仍然是一种纯粹的学术追求。在本章中，我们将探讨正在塑造我们世界的数据结构和算法。

这个时代的一个黄金机会是数据的丰富。电子邮件、电话号码、文本文档和图像包含大量的数据。在这些数据中，有着使数据更加重要的有价值信息。但是要从原始数据中提取这些信息，我们必须使用专门从事这项任务的数据结构、过程和算法。

机器学习使用大量算法来分析和预测某些变量的发生。仅基于纯数字的数据分析仍然使得许多潜在信息埋藏在原始数据中。因此，通过可视化呈现数据，使人们能够理解并获得有价值的见解。

在本章结束时，您应该能够做到以下几点：

+   精确修剪和呈现数据

+   为了预测，需要同时使用监督学习和无监督学习算法。

+   通过可视化呈现数据以获得更多见解

# 技术要求

为了继续本章，您需要安装以下包。这些包将用于对正在处理的数据进行预处理和可视化呈现。其中一些包还包含对我们的数据进行操作的算法的良好实现。

最好使用`pip`安装这些模块。因此，首先，我们需要使用以下命令为 Python 3 安装 pip：

+   `sudo apt-get update`

+   `sudo apt-get install python3-pip`

此外，需要运行以下命令来安装`numpy`、`scikit-learn`、`matplotlib`、`pandas`和`textblob`包：

```py
# pip3 install numpy
# pip3 install scikit-learn
# pip3 install matplotlib
# pip3 install pandas
# pip3 install textblob  
```

如果您使用的是旧版本的 Python（即 Python 2），则可以使用相同的命令来安装这些包，只需将`pip3`替换为`pip`。

您还需要安装`nltk`和`punkt`包，这些包提供了内置的文本处理功能。要安装它们，请打开 Python 终端并运行以下命令：

```py
>>import nltk
>>nltk.download('punkt')
```

这些包可能需要先安装其他特定于平台的模块。请注意并安装所有依赖项：

+   **NumPy**：一个具有操作 n 维数组和矩阵功能的库。

+   **Scikit-learn**：用于机器学习的高级模块。它包含许多用于分类、回归和聚类等算法的实现。

+   **Matplotlib**：这是一个绘图库，利用 NumPy 绘制各种图表，包括折线图、直方图、散点图，甚至 3D 图表。

+   **Pandas**：这个库处理数据操作和分析。

GitHub 链接如下：[`github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-3.x-Second-Edition/tree/master/Chapter14`](https://github.com/PacktPublishing/Hands-On-Data-Structures-and-Algorithms-with-Python-3.x-Second-Edition/tree/master/Chapter14)。

# 数据预处理

首先，要分析数据，我们必须对数据进行预处理，以去除噪音并将其转换为适当的格式，以便进一步分析。来自现实世界的数据集大多充满噪音，这使得直接应用任何算法变得困难。收集到的原始数据存在许多问题，因此我们需要采取方法来清理数据，使其适用于进一步的研究。

# 处理原始数据

收集到的数据可能与随时间收集的其他记录不一致。重复条目的存在和不完整的记录要求我们以这样的方式处理数据，以揭示隐藏的有用信息。

为了清理数据，我们完全丢弃了不相关和嘈杂的数据。缺失部分或属性的数据可以用合理的估计值替换。此外，当原始数据存在不一致性时，检测和纠正就变得必要了。

让我们探讨如何使用`NumPy`和`pandas`进行数据预处理技术。

# 缺失数据

如果数据存在缺失值，机器学习算法的性能会下降。仅仅因为数据集存在缺失字段或属性并不意味着它没有用处。可以使用几种方法来填补缺失值。其中一些方法如下：

+   使用全局常数填补缺失值。

+   使用数据集中的均值或中位数值。

+   手动提供数据。

+   使用属性的均值或中位数来填补缺失值。选择基于数据将要使用的上下文和敏感性。

例如，以下数据：

```py
    import numpy as np 
    data = pandas.DataFrame([ 
        [4., 45., 984.], 
        [np.NAN, np.NAN, 5.], 
        [94., 23., 55.], 
    ]) 
```

可以看到，数据元素`data[1][0]`和`data[1][1]`的值为`np.NAN`，表示它们没有值。如果不希望在给定数据集中存在`np.NAN`值，可以将其设置为一个常数。

让我们将值为`np.NAN`的数据元素设置为`0.1`：

```py
    print(data.fillna(0.1)) 
```

数据的新状态如下：

```py
0     1      2
0   4.0  45.0  984.0
1   0.1   0.1    5.0
2  94.0  23.0   55.0
```

要应用均值，我们需要做如下操作：

```py
    print(data.fillna(data.mean()))
```

为每列计算均值，并将其插入到具有`np.NAN`值的数据区域中：

```py
0     1      2
0   4.0  45.0  984.0
1  49.0  34.0    5.0
2  94.0  23.0   55.0
```

对于第一列，列`0`，均值通过`(4 + 94)/2`得到。然后将结果`49.0`存储在`data[1][0]`中。对列`1`和`2`也进行类似的操作。

# 特征缩放

数据框中的列称为其特征。行称为记录或观察。如果一个属性的值比其他属性的值具有更高的范围，机器学习算法的性能会下降。因此，通常需要将属性值缩放或归一化到一个公共范围内。

考虑一个例子，以下数据矩阵。这些数据将在后续部分中被引用，请注意：

```py
data1= ([[  58.,    1.,   43.],
 [  10.,  200.,   65.],
 [  20.,   75.,    7.]]
```

特征一的数据为`58`、`10`和`20`，其值位于`10`和`58`之间。对于特征二，数据位于`1`和`200`之间。如果将这些数据提供给任何机器学习算法，将产生不一致的结果。理想情况下，我们需要将数据缩放到一定范围内以获得一致的结果。

再次仔细检查发现，每个特征（或列）的均值都在不同的范围内。因此，我们要做的是使特征围绕相似的均值对齐。

特征缩放的一个好处是它提升了机器学习的学习部分。`scikit`模块有大量的缩放算法，我们将应用到我们的数据中。

# 最小-最大标量形式的归一化

最小-最大标量形式的归一化使用均值和标准差将所有数据装箱到位于某些最小和最大值之间的范围内。通常，范围设置在`0`和`1`之间；尽管可以应用其他范围，但`0`到`1`范围仍然是默认值：

```py
from sklearn.preprocessing import MinMaxScaler

scaled_values = MinMaxScaler(feature_range=(0,1)) 
results = scaled_values.fit(data1).transform(data1) 
print(results) 
```

使用`MinMaxScaler`类的一个实例，范围为`(0,1)`，并传递给`scaled_values`变量。调用`fit`函数进行必要的计算，用于内部使用以改变数据集。`transform`函数对数据集进行实际操作，并将值返回给`results`：

```py
[[ 1\.          0\.          0.62068966]
 [ 0\.          1\.          1\.        ]
 [ 0.20833333  0.3718593   0\.        ]]
```

从前面的输出中可以看出，所有数据都经过了归一化，并位于`0`和`1`之间。这种输出现在可以提供给机器学习算法。

# 标准缩放

我们初始数据集或表中各特征的均值分别为 29.3、92 和 38。为了使所有数据具有相似的均值，即数据的均值为零，方差为单位，我们可以应用标准缩放算法，如下所示：

```py
    stand_scalar =  preprocessing.StandardScaler().fit(data) 
    results = stand_scalar.transform(data) 
    print(results)
```

`data`被传递给从实例化`StandardScaler`类返回的对象的`fit`方法。`transform`方法作用于数据元素，并将输出返回给结果：

```py
[[ 1.38637564 -1.10805456  0.19519899]
 [-0.93499753  1.31505377  1.11542277]
 [-0.45137812 -0.2069992  -1.31062176]]
```

检查结果，我们观察到所有特征现在都是均匀分布的。

# 二值化数据

要对给定的特征集进行二值化，我们可以使用一个阈值。如果给定数据集中的任何值大于阈值，则该值将被替换为`1`，如果该值小于阈值，则替换为`0`。考虑以下代码片段，我们以 50 作为阈值来对原始数据进行二值化：

```py
 results = preprocessing.Binarizer(50.0).fit(data).transform(data) 
 print(results) 
```

创建一个`Binarizer`的实例，并使用参数`50.0`。`50.0`是将在二值化算法中使用的阈值：

```py
[[ 1\. 0\. 0.]
 [ 0\. 1\. 1.]
 [ 0\. 1\. 0.]] 
```

数据中所有小于 50 的值将为`0`，否则为`1`。

# 学习机器学习

机器学习是人工智能的一个子领域。机器学习基本上是一个可以从示例数据中学习并可以基于此提供预测的算法。机器学习模型从数据示例中学习模式，并使用这些学习的模式来预测未见数据。例如，我们将许多垃圾邮件和正常邮件的示例输入来开发一个机器学习模型，该模型可以学习邮件中的模式，并可以将新邮件分类为垃圾邮件或正常邮件。

# 机器学习类型

机器学习有三个广泛的类别，如下：

+   **监督学习**：在这里，算法会接收一组输入和相应的输出。然后算法必须找出对于未见过的输入，输出将会是什么。监督学习算法试图学习输入特征和目标输出中的模式，以便学习的模型可以预测新的未见数据的输出。分类和回归是使用监督学习方法解决的两种问题，其中机器学习算法从给定的数据和标签中学习。分类是一个将给定的未见数据分类到预定义类别集合中的过程，给定一组输入特征和与其相关的标签。回归与分类非常相似，唯一的区别在于，在回归中，我们有连续的目标值，而不是固定的预定义类别集合（名义或分类属性），我们预测连续响应中的值。这样的算法包括朴素贝叶斯、支持向量机、k-最近邻、线性回归、神经网络和决策树算法。

+   **无监督学习**：无监督学习算法仅使用输入来学习数据中的模式和聚类，而不使用存在于一组输入和输出变量之间的关系。无监督算法用于学习给定输入数据中的模式，而不带有与其相关的标签。聚类问题是使用无监督学习方法解决的最流行的问题之一。在这种情况下，数据点根据特征之间的相似性被分组成组或簇。这样的算法包括 k 均值聚类、凝聚聚类和层次聚类。

+   **强化学习**：在这种学习方法中，计算机动态地与环境交互，以改善其性能。

# 你好分类器

让我们举一个简单的例子来理解机器学习的工作原理；我们从一个文本分类器的`hello world`例子开始。这是对机器学习的一个温和的介绍。

这个例子将预测给定文本是否带有负面或正面的含义。在这之前，我们需要用一些数据来训练我们的算法（模型）。

朴素贝叶斯模型适用于文本分类目的。基于朴素贝叶斯模型的算法通常速度快，产生准确的结果。它基于特征相互独立的假设。要准确预测降雨的发生，需要考虑三个条件。这些条件是风速、温度和空气中的湿度量。实际上，这些因素确实会相互影响，以确定降雨的可能性。但朴素贝叶斯的抽象是假设这些特征在任何方面都是无关的，因此独立地影响降雨的可能性。朴素贝叶斯在预测未知数据集的类别时非常有用，我们很快就会看到。

现在，回到我们的 hello 分类器。在我们训练模型之后，它的预测将属于正类别或负类别之一：

```py
    from textblob.classifiers import NaiveBayesClassifier 
    train = [ 
        ('I love this sandwich.', 'pos'), 
        ('This is an amazing shop!', 'pos'), 
        ('We feel very good about these beers.', 'pos'), 
        ('That is my best sword.', 'pos'), 
        ('This is an awesome post', 'pos'), 
        ('I do not like this cafe', 'neg'), 
        ('I am tired of this bed.', 'neg'), 
        ("I can't deal with this", 'neg'), 
        ('She is my sworn enemy!', 'neg'), 
        ('I never had a caring mom.', 'neg') 
    ] 
```

首先，我们将从`textblob`包中导入`NaiveBayesClassifier`类。这个分类器非常容易使用，基于贝叶斯定理。

`train`变量由每个包含实际训练数据的元组组成。每个元组包含句子和它所关联的组。

现在，为了训练我们的模型，我们将通过传递`train`来实例化一个`NaiveBayesClassifier`对象：

```py
    cl = NaiveBayesClassifier(train) 
```

更新后的朴素贝叶斯模型`cl`将预测未知句子所属的类别。到目前为止，我们的模型只知道短语可以属于`neg`和`pos`两个类别中的一个。

以下代码使用我们的模型运行测试：

```py
    print(cl.classify("I just love breakfast")) 
    print(cl.classify("Yesterday was Sunday")) 
    print(cl.classify("Why can't he pay my bills")) 
    print(cl.classify("They want to kill the president of Bantu")) 
```

我们测试的输出如下：

```py
pos 
pos 
neg 
neg 
```

我们可以看到算法在正确将输入短语分类到它们的类别方面取得了一定程度的成功。

这个刻意构造的例子过于简单，但它确实显示了如果提供了正确数量的数据和合适的算法或模型，机器是可以在没有任何人类帮助的情况下执行任务的。

在我们的下一个例子中，我们将使用`scikit`模块来预测一个短语可能属于的类别。

# 一个监督学习的例子

让我们考虑一个文本分类问题的例子，可以使用监督学习方法来解决。文本分类问题是在我们有一组与固定数量的类别相关的文档时，将新文档分类到预定义的文档类别集合之一。与监督学习一样，我们需要首先训练模型，以便准确预测未知文档的类别。

# 收集数据

`scikit`模块带有我们可以用于训练机器学习模型的示例数据。在这个例子中，我们将使用包含 20 个文档类别的新闻组文档。为了加载这些文档，我们将使用以下代码行：

```py
 from sklearn.datasets import fetch_20newsgroups 
 training_data = fetch_20newsgroups(subset='train', categories=categories,   
                                           shuffle=True, random_state=42)
```

让我们只取四个文档类别来训练模型。在我们训练模型之后，预测的结果将属于以下类别之一：

```py
    categories = ['alt.atheism', 
                  'soc.religion.christian','comp.graphics', 'sci.med'] 
```

我们将用作训练数据的记录总数是通过以下方式获得的：

```py
 print(len(training_data)) 
```

机器学习算法不能直接处理文本属性，因此每个文档所属类别的名称被表示为数字（例如，`alt.atheism`表示为`0`），使用以下代码行：

```py
    print(set(training_data.target)) 
```

类别具有整数值，我们可以使用`print(training_data.target_names[0])`将其映射回类别本身。

在这里，`0`是从`set(training_data.target)`中随机选择的数字索引。

现在训练数据已经获得，我们必须将数据提供给机器学习算法。词袋模型是一种将文本文档转换为特征向量的方法，以便将文本转换为学习算法或模型可以应用的形式。此外，这些特征向量将用于训练机器学习模型。

# 词袋模型

词袋是一种模型，用于表示文本数据，它不考虑单词的顺序，而是使用单词计数。让我们看一个例子来理解词袋方法如何用于表示文本。看看以下两个句子：

```py
    sentence_1 = "as fit as a fiddle"
    sentence_2 = "as you like it"
```

词袋使我们能够将文本拆分为由矩阵表示的数值特征向量。

为了使用词袋模型减少我们的两个句子，我们需要获得所有单词的唯一列表：

```py
    set((sentence_1 + sentence_2).split(" "))
```

这个集合将成为我们矩阵中的列，被称为机器学习术语中的特征。矩阵中的行将代表用于训练的文档。行和列的交集将存储单词在文档中出现的次数。使用我们的两个句子作为例子，我们得到以下矩阵：

|  | **as** | **fit** | **a** | **fiddle** | **you** | **like** | **it** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **句子 1** | 2 | 1 | 1 | 1 | 0 | 0 | 0 |
| **句子 2** | 1 | 0 | 0 | 0 | 1 | 1 | 1 |

前面的数据有很多特征，通常对文本分类不重要。停用词可以被移除，以确保只分析相关的数据。停用词包括 is，am，are，was 等等。由于词袋模型在分析中不包括语法，停用词可以安全地被删除。

为了生成进入矩阵列的值，我们必须对我们的训练数据进行标记化：

```py
    from sklearn.feature_extraction.text import CountVectorizer 
    from sklearn.feature_extraction.text import TfidfTransformer 
    from sklearn.naive_bayes import MultinomialNB 
    count_vect = CountVectorizer() 
    training_matrix = count_vect.fit_transform(training_data.data) 
```

在这个例子中，`training_matrix`的维度为（2,257 x 35,788），对应于我们在这个例子中使用的四个数据类别。这意味着 2,257 对应于文档的总数，而 35,788 对应于列的数量，即构成所有文档中唯一单词集的特征的总数。

我们实例化`CountVectorizer`类，并将`training_data.data`传递给`count_vect`对象的`fit_transform`方法。结果存储在`training_matrix`中。`training_matrix`包含所有唯一的单词及其相应的频率。

有时，频率计数对于文本分类问题表现不佳；我们可以使用**词项频率-逆文档频率**（**TF-IDF**）加权方法来表示特征，而不是使用频率计数。

在这里，我们将导入`TfidfTransformer`，它有助于为我们的数据中的每个特征分配权重：

```py
    matrix_transformer = TfidfTransformer() 
    tfidf_data = matrix_transformer.fit_transform(training_matrix) 

    print(tfidf_data[1:4].todense()) 
```

`tfidf_data[1:4].todense()`只显示了一个三行 35,788 列矩阵的截断列表。所见的值是 TF-IDF；与使用频率计数相比，它是一种更好的表示方法。

一旦我们提取了特征并以表格格式表示它们，我们就可以应用机器学习算法进行训练。有许多监督学习算法；让我们看一个朴素贝叶斯算法的例子来训练文本分类器模型。

朴素贝叶斯算法是一种简单的分类算法，它基于贝叶斯定理。它是一种基于概率的学习算法，通过使用特征/单词/术语的词频来计算属于的概率来构建模型。朴素贝叶斯算法将给定的文档分类为预定义类别中的一个，其中新文档中观察到的单词的最大概率所在的类别。朴素贝叶斯算法的工作方式如下——首先，处理所有训练文档以提取出现在文本中的所有单词的词汇，然后计算它们在不同目标类别中的频率以获得它们的概率。接下来，将新文档分类到具有属于特定类别的最大概率的类别中。朴素贝叶斯分类器基于这样的假设，即单词出现的概率与文本中的位置无关。多项式朴素贝叶斯可以使用`scikit`库的`MultinomialNB`函数来实现，如下所示：

```py
 model = MultinomialNB().fit(tfidf_data, training_data.target) 
```

`MultinomialNB`是朴素贝叶斯模型的一个变体。我们将经过合理化的数据矩阵`tfidf_data`和类别`training_data.target`传递给其`fit`方法。

# 预测

为了测试训练模型如何预测未知文档的类别，让我们考虑一些示例测试数据来评估模型：

```py
    test_data = ["My God is good", "Arm chip set will rival intel"] 
    test_counts = count_vect.transform(test_data) 
    new_tfidf = matrix_transformer.transform(test_counts)
```

将`test_data`列表传递给`count_vect.transform`函数，以获得测试数据的向量化形式。为了获得测试数据集的 TF-IDF 表示，我们调用`matrix_transformer`对象的`transform`方法。当我们将新的测试数据传递给机器学习模型时，我们必须以与准备训练数据相同的方式处理数据。

为了预测文档可能属于哪个类别，我们使用`predict`函数如下：

```py
    prediction = model.predict(new_tfidf)  
```

循环可以用于迭代预测，显示它们被预测属于的类别：

```py
    for doc, category in zip(test_data, prediction): 
        print('%r => %s' % (doc, training_data.target_names[category])) 
```

当循环运行完成时，将显示短语及其可能属于的类别。示例输出如下：

```py
'My God is good' => soc.religion.christian
'Arm chip set will rival intel' => comp.graphics
```

到目前为止，我们所看到的都是监督学习的一个典型例子。我们首先加载已知类别的文档。然后将这些文档输入到最适合文本处理的机器学习算法中，基于朴素贝叶斯定理。一组测试文档被提供给模型，并预测类别。

探索一个无监督学习算法的例子，我们将讨论 k 均值算法对一些数据进行聚类。

# 无监督学习示例

无监督学习算法能够发现数据中可能存在的固有模式，并以这样的方式将它们聚类成组，使得一个组中的数据点非常相似，而来自两个不同组的数据点在性质上非常不相似。这些算法的一个例子就是 k 均值算法。

# k 均值算法

k 均值算法使用给定数据集中的均值点来对数据进行聚类并发现数据集中的组。`K`是我们希望发现的聚类的数量。k 均值算法生成了分组/聚类之后，我们可以将未知数据传递给该模型，以预测新数据应该属于哪个聚类。

请注意，在这种算法中，只有原始的未分类数据被输入到算法中，没有任何与数据相关联的标签。算法需要找出数据是否具有固有的组。

k 均值算法通过迭代地根据提供的特征之间的相似性将数据点分配到聚类中。k 均值聚类使用均值点将数据点分组成 k 个聚类/组。它的工作方式如下。首先，我们创建 k 个非空集合，并计算数据点与聚类中心之间的距离。接下来，我们将数据点分配给具有最小距离且最接近的聚类。然后，我们重新计算聚类点，并迭代地遵循相同的过程，直到所有数据都被聚类。

为了理解这个算法的工作原理，让我们检查包含 x 和 y 值的 100 个数据点（假设有两个属性）。我们将把这些值传递给学习算法，并期望算法将数据聚类成两组。我们将对这两组进行着色，以便看到聚类。

让我们创建一个包含 100 条*x*和*y*对的样本数据：

```py
    import numpy as np 
    import matplotlib.pyplot as plt 
    original_set = -2 * np.random.rand(100, 2) 
    second_set = 1 + 2 * np.random.rand(50, 2) 
    original_set[50: 100, :] = second_set 
```

首先，我们创建 100 条记录，其中包含`-2 * np.random.rand(100, 2)`。在每条记录中，我们将使用其中的数据来表示最终将绘制的*x*和*y*值。

`original_set`中的最后 50 个数字将被`1+2*np.random.rand(50, 2)`替换。实际上，我们已经创建了两个数据子集，其中一个集合中的数字为负数，而另一个集合中的数字为正数。现在算法的责任是适当地发现这些段。

我们实例化`KMeans`算法类，并传递`n_clusters=2`。这使得算法将其所有数据聚类成两组。在 k 均值算法中，簇的数量必须事先知道。使用`scikit`库实现 k 均值算法如下所示：

```py
    from sklearn.cluster import KMeans 
    kmean = KMeans(n_clusters=2) 

    kmean.fit(original_set) 

    print(kmean.cluster_centers_) 

    print(kmean.labels_) 
```

数据集被传递给`kmean`的`fit`函数，`kmean.fit(original_set)`。算法生成的聚类将围绕某个平均点旋转。定义这两个平均点的点是通过`kmean.cluster_centers_`获得的。

打印出的平均点如下所示：

```py
[[ 2.03838197 2.06567568]
 [-0.89358725 -0.84121101]]
```

`original_set`中的每个数据点在我们的 k 均值算法完成训练后将属于一个簇。k 均值算法将它发现的两个簇表示为 1 和 0。如果我们要求算法将数据分成四个簇，这些簇的内部表示将是 0、1、2 和 3。要打印出每个数据集所属的不同簇，我们执行以下操作：

```py
    print(kmean.labels_) 
```

这将产生以下输出：

```py
[1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 
 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 
 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
```

有`100`个 1 和 0。每个显示每个数据点所属的簇。通过使用`matplotlib.pyplot`，我们可以绘制每个组的点并适当着色以显示簇：

```py
    import matplotlib.pyplot as plt 
    for i in set(kmean.labels_): 
        index = kmean.labels_ == i 
        plt.plot(original_set[index,0], original_set[index,1], 'o')
```

`index = kmean.labels_ == i`是一种巧妙的方法，通过它我们选择与组`i`对应的所有点。当`i=0`时，所有属于零组的点都返回到变量`index`。对于`index =1, 2`，依此类推。

`plt.plot(original_set[index,0], original_set[index,1], 'o')`然后使用`o`作为绘制每个点的字符绘制这些数据点。

接下来，我们将绘制形成簇的质心或平均值：

```py
    plt.plot(kmean.cluster_centers_[0][0],kmean.cluster_centers_[0][1], 
             '*', c='r', ms=10) 
    plt.plot(kmean.cluster_centers_[1][0],kmean.cluster_centers_[1][1], 
             '*', c='r', ms=10) 
```

最后，我们使用代码片段`plt.show()`显示整个图形，其中两个平均值用红色星号表示，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/9130b340-90ee-4cee-b5ff-ca93c2b01e27.png)

该算法在我们的样本数据中发现了两个不同的簇。

# 预测

有了我们得到的两个簇，我们可以预测新一组数据可能属于哪个组。

让我们预测点`[[-1.4, -1.4]]`和`[[2.5, 2.5]]`将属于哪个组：

```py
    sample = np.array([[-1.4, -1.4]]) 
    print(kmean.predict(sample)) 

    another_sample = np.array([[2.5, 2.5]]) 
    print(kmean.predict(another_sample)) 
```

输出如下：

```py
[1]
[0] 
```

在这里，两个测试样本分配到了两个不同的簇。

# 数据可视化

数值分析有时不那么容易理解。在本节中，我们将向您展示一些可视化数据和结果的方法。图像是分析数据的一种快速方式。图像中大小和长度的差异是快速标记，可以得出结论。在本节中，我们将介绍表示数据的不同方法。除了这里列出的图表外，在处理数据时还可以实现更多。

# 条形图

要将值 25、5、150 和 100 绘制成条形图，我们将把这些值存储在一个数组中，并将其传递给`bar`函数。图中的条代表*y*轴上的大小：

```py
    import matplotlib.pyplot as plt 

    data = [25., 5., 150., 100.] 
    x_values = range(len(data)) 
    plt.bar(x_values, data) 

    plt.show()
```

`x_values`存储由`range(len(data))`生成的值数组。此外，`x_values`将确定在*x*轴上绘制条形的点。第一根条将在*x*轴上绘制，其中*x*为零。第二根带有数据 5 的条将在*x*轴上绘制，其中*x*为 1：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/5c2618e0-70aa-41eb-aa32-ff94e8b3f8c6.png)

通过修改以下行可以改变每个条的宽度：

```py
    plt.bar(x_values, data, width=1.)  
```

这应该产生以下图形：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/9cd8e72f-79e7-4c7e-9cfc-e80a375153f0.png)

然而，这样做并不直观，因为条之间不再有空间，这使得看起来很笨拙。每个条现在在*x*轴上占据一个单位。

# 多条形图

在尝试可视化数据时，堆叠多个条使人能够进一步了解一条数据或变量相对于另一条数据或变量的变化：

```py
    data = [ 
            [8., 57., 22., 10.], 
            [16., 7., 32., 40.],
           ] 

    import numpy as np 
    x_values = np.arange(4) 
    plt.bar(x_values + 0.00, data[0], color='r', width=0.30) 
    plt.bar(x_values + 0.30, data[1], color='y', width=0.30) 

    plt.show() 
```

第一批数据的`y`值为`[8., 57., 22., 10.]`。第二批数据为`[16., 7., 32., 40.]`。当条形图绘制时，8 和 16 将占据相同的`x`位置，侧边相邻。

`x_values = np.arange(4)`生成值为`[0, 1, 2, 3]`的数组。第一组条形图首先绘制在位置`x_values + 0.30`。因此，第一个 x 值将被绘制在`0.00, 1.00, 2.00 和 3.00`。

第二组`x_values`将被绘制在`0.30, 1.30, 2.30`和`3.30`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/d0624b77-b67d-470b-96fb-22a604eafad6.png)

# 箱线图

箱线图用于可视化分布的中位数值和低高范围。它也被称为箱线图。

让我们绘制一个简单的箱线图。

我们首先生成`50`个来自正态分布的数字。然后将它们传递给`plt.boxplot(data)`进行绘图：

```py
    import numpy as np 
    import matplotlib.pyplot as plt 

    data = np.random.randn(50) 

    plt.boxplot(data) 
    plt.show() 
```

以下图表是产生的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/05876ad6-cc46-4141-bfa8-bb3b119b6c0e.png)

对于前面的图表，一些注释——箱线图的特点包括跨越四分位距的箱子，用于测量离散度；数据的外围由连接到中心箱子的须表示；红线代表中位数。

箱线图可用于轻松识别数据集中的异常值，以及确定数据集可能偏向的方向。

# 饼图

饼图解释和直观地表示数据，就像适合放在圆圈里一样。个别数据点被表示为圆圈的扇形，总和为 360 度。这种图表适合显示分类数据和总结：

```py
    import matplotlib.pyplot as plt 
    data = [500, 200, 250] 

    labels = ["Agriculture", "Aide", "News"] 

    plt.pie(data, labels=labels,autopct='%1.1f%%') 
    plt.show() 
```

图表中的扇形用标签数组中的字符串标记：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/17ea1d44-5589-427c-8c5c-0d37c801d374.png)

# 气泡图

散点图的另一种变体是气泡图。在散点图中，我们只绘制数据的`x`和`y`点。气泡图通过展示点的大小添加了另一个维度。这第三个维度可以表示市场的规模甚至利润：

```py
    import numpy as np 
    import matplotlib.pyplot as plt 

    n = 10 
    x = np.random.rand(n) 
    y = np.random.rand(n) 
    colors = np.random.rand(n) 
    area = np.pi * (60 * np.random.rand(n))**2 

    plt.scatter(x, y, s=area, c=colors, alpha=0.5) 
    plt.show() 
```

通过`n`变量，我们指定了随机生成的`x`和`y`值的数量。这个数字也用于确定我们的`x`和`y`坐标的随机颜色。随机气泡大小由`area = np.pi * (60 * np.random.rand(n))**2`确定。

以下图表显示了这个气泡图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-dsal-py/img/9b77b68c-6fed-44e9-93f5-c9f23357954a.png)

# 总结

在本章中，我们探讨了数据和算法如何结合起来帮助机器学习。通过数据清洗技术和缩放和归一化过程，我们首先对大量数据进行了整理。将这些数据输入到专门的学习算法中，我们能够根据算法从数据中学到的模式来预测未知数据的类别。我们还讨论了机器学习算法的基础知识。

我们详细解释了监督和无监督的机器学习算法，使用朴素贝叶斯和 k 均值聚类算法。我们还使用基于 Python 的`scikit-learn`机器学习库提供了这些算法的实现。最后，我们讨论了一些重要的可视化技术，因为对压缩数据进行图表化和绘图有助于更好地理解和做出有见地的发现。

希望您在阅读本书时有一个愉快的体验，并且它能够帮助您在未来的数据结构和 Python 3.7 的学习中取得成功！
