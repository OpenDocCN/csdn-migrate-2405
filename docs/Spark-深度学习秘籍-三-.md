# Spark 深度学习秘籍（三）

> 原文：[`zh.annas-archive.org/md5/D22F0E873CEFD5D61BC00E51F025B8FB`](https://zh.annas-archive.org/md5/D22F0E873CEFD5D61BC00E51F025B8FB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 XGBoost 进行房地产价值预测

房地产市场是定价最具竞争力的市场之一。这往往会根据诸多因素而显著变化，如位置、物业年龄、大小等。因此，准确预测房地产价格（特别是房地产市场中的价格）已成为一个现代挑战，以便做出更好的投资决策。本章将处理这个问题。

阅读完本章后，您将能够：

+   下载金县房屋销售数据集

+   进行探索性分析和可视化

+   绘制价格与其他特征之间的相关性

+   预测房屋价格

# 下载金县房屋销售数据集

在没有数据集的情况下，我们无法构建模型。我们将在本节中下载我们的数据。

# 准备工作

Kaggle ([`www.kaggle.com/`](https://www.kaggle.com/))是一个用于预测建模和分析竞赛的平台，统计学家和数据挖掘者在这里竞争，以产生最佳的模型来预测和描述由公司和用户上传的数据集。金县房屋销售数据集包含了在 1900 年至 2015 年间在纽约金县出售的 21,613 套房屋的记录。数据集还包含了每套房屋的 21 个不同变量，如位置、邮政编码、卧室数量、生活空间面积等。

# 如何做...

1.  可以从以下网站访问数据集：[`www.kaggle.com/harlfoxem/housesalesprediction`](https://www.kaggle.com/harlfoxem/housesalesprediction)。数据集来自金县的公共记录，可以免费下载和在任何分析中使用。

1.  一旦您到达网站，您可以点击下载按钮，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00217.jpeg)

金县房屋销售数据集

1.  从压缩下载的文件`housesalesprediction.zip`中出现一个名为`kc_house_data.csv`的文件。

1.  将名为`kc_house_data.csv`的文件保存在当前工作目录中，因为这将是我们的数据集。这将被加载到 IPython 笔记本中进行分析和预测。

# 它是如何工作的...

1.  使用以下代码安装本章所需的必要库：

```scala
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import mpl_toolkits
from sklearn import preprocessing
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.feature_selection import RFE
from sklearn import linear_model
from sklearn.cross_validation import train_test_split %matplotlib inline
```

1.  前面的步骤应该会产生一个输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00218.jpeg)

1.  检查当前工作目录并将其设置为存储数据集的目录是一个好主意。如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00219.jpeg)

在我们的案例中，名为`Chapter 10`的文件夹被设置为当前工作目录。

1.  使用`read_csv()`函数将文件中的数据读入名为`dataframe`的 Pandas 数据框中，并使用`list(dataframe)`命令列出特征/标题，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00220.jpeg)

您可能已经注意到，数据集包含 21 个不同的变量，如 id、日期、价格、卧室、浴室等。

# 还有更多...

本章中使用的库及其函数如下：

+   `Numpy`，用于整理数组形式的数据以及以数组形式存储名称列表

+   `Pandas`，用于所有数据整理和数据框形式的数据管理

+   `Seaborn`，这是一种用于探索性分析和绘图的可视化库

+   `MPL_Toolkits`，其中包含`Matplotlib`所需的许多函数和依赖项

+   本章所需的主要科学和统计库`Scikit Learn`库中的函数

+   我们还需要一些其他库，如`XGBoost`，但这些将在构建模型时根据需要导入。

# 另请参阅

有关不同库的更多文档可以通过访问以下链接找到：

+   [`scikit-learn.org/stable/modules/preprocessing.html`](http://scikit-learn.org/stable/modules/preprocessing.html)

+   [`scikit-learn.org/stable/modules/generated/sklearn.feature_selection.RFE.html`](http://scikit-learn.org/stable/modules/generated/sklearn.feature_selection.RFE.html)

+   [`seaborn.pydata.org/`](https://seaborn.pydata.org/)

+   [`matplotlib.org/mpl_toolkits/index.html`](https://matplotlib.org/mpl_toolkits/index.html)

# 进行探索性分析和可视化

在预测`price`等变量时，可视化数据并了解因变量受其他变量影响的方式有助于预测。探索性分析提供了许多数据中不容易获得的见解。本章的这一部分将描述如何从大数据中可视化并得出见解。

# 准备工作

+   可以使用`dataframe.head()`函数打印`dataframe`的头部，产生如下屏幕截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00221.jpeg)

+   同样，可以使用`dataframe.tail()`函数打印`dataframe`的尾部，产生如下屏幕截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00222.jpeg)

+   `dataframe.describe()`函数用于获得一些基本统计数据，如每列的最大值、最小值和平均值。如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00223.jpeg)

dataframe.describe()函数输出

+   正如您所看到的，数据集中有 21,613 条记录，记录了 1900 年至 2015 年间售出的房屋。

+   仔细观察统计数据，我们意识到大多数售出的房屋平均有大约三间卧室。我们还可以看到房屋中卧室数量的最小值为 0，最大的房屋有 33 间卧室，占地面积为 13,540 平方英尺。

# 如何做到...

1.  让我们绘制整个数据集中卧室数量的计数，以了解三居室房屋与两居室或一居室房屋的情况。使用以下代码完成：

```scala
dataframe['bedrooms'].value_counts().plot(kind='bar') plt.title('No. of bedrooms')
plt.xlabel('Bedrooms')
plt.ylabel('Count')
sns.despine
```

1.  我们也可以使用以下命令绘制相同数据的饼图：

```scala
 dataframe['bedrooms'].value_counts().plot(kind='pie')
plt.title('No. of bedrooms')
```

1.  接下来，让我们尝试看看金县最常售出的房屋有多少层。这可以通过使用以下命令绘制条形图来完成：

```scala
dataframe['floors'].value_counts().plot(kind='bar') plt.title('Number of floors')
plt.xlabel('No. of floors')
plt.ylabel('Count')
sns.despine
```

1.  接下来，我们需要了解哪些地点售出的房屋数量最多。我们可以使用数据集中的`latitude`和`longitude`变量来做到这一点，如下代码所示：

```scala
plt.figure(figsize=(20,20))
sns.jointplot(x=dataframe.lat.values, y=dataframe.long.values, size=9)
plt.xlabel('Longitude', fontsize=10)
plt.ylabel('Latitude', fontsize=10)
plt.show()
sns.despine()
```

1.  让我们也看看不同卧室数量的房屋价格如何相比，执行以下命令：

```scala
 plt.figure(figsize=(20,20))
sns.jointplot(x=dataframe.lat.values, y=dataframe.long.values, size=9)
plt.xlabel('Longitude', fontsize=10)
plt.ylabel('Latitude', fontsize=10)
plt.show()
sns.despine()
```

1.  使用以下命令获得房屋价格与卧室数量的图：

```scala
plt.figure(figsize=(20,20))
sns.jointplot(x=dataframe.lat.values, y=dataframe.long.values, size=9)
plt.xlabel('Longitude', fontsize=10)
plt.ylabel('Latitude', fontsize=10)
plt.show()
sns.despine()
```

1.  同样，让我们看看价格与所有售出房屋的居住面积的比较。这可以通过使用以下命令来完成：

```scala
plt.figure(figsize=(8,8))
plt.scatter(dataframe.price, dataframe.sqft_living)
plt.xlabel('Price')
plt.ylabel('Square feet')
plt.show()
```

1.  售出的房屋的条件也给了我们一些重要的信息。让我们将其与价格绘制在一起，以更好地了解一般趋势。使用以下命令完成：

```scala
plt.figure(figsize=(5,5))
plt.bar(dataframe.condition, dataframe.price)
plt.xlabel('Condition')
plt.ylabel('Price')
plt.show()
```

1.  我们可以使用以下命令查看哪些邮政编码在金县有最多的房屋销售：

```scala
plt.figure(figsize=(8,8))
plt.scatter(dataframe.zipcode, dataframe.price)
plt.xlabel('Zipcode')
plt.ylabel('Price')
plt.show()
```

1.  最后，绘制每个房屋的等级与价格的关系，以了解基于每个房屋的等级的房屋销售趋势，使用以下命令：

```scala
plt.figure(figsize=(10,10))
plt.scatter(dataframe.grade, dataframe.price)
plt.xlabel('Grade')
plt.ylabel('Price')
plt.show()
```

# 工作原理...

1.  卧室数量的图必须给出输出，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00224.jpeg)

1.  很明显，三居室的房屋销售最多，其次是四居室，然后是两居室，然后是令人惊讶的五居室和六居室。

1.  卧室数量的饼图输出如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00225.jpeg)

1.  您会注意到，三居室房屋大约占金县所有售出房屋的 50%。大约 25%是四居室房屋，其余 25%由两居室、五居室、六居室等房屋组成。

1.  运行脚本以查看按楼层分类的最常售出的房屋时，我们注意到以下输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00226.jpeg)

1.  很明显，单层房屋销售量最大，其次是两层房屋。超过两层的房屋数量相当少，这可能是家庭规模和居住在金县的居民收入的指示。

1.  检查不同位置出售房屋的密度后，我们得到了一个输出，如下面的屏幕截图所示。很明显，一些地方的房屋销售密度比其他地方要高：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00227.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00228.jpeg)

1.  从前述图表中观察到的趋势，很容易注意到在纬度-122.2 和-122.4 之间销售的房屋数量更多。同样，在经度 47.5 和 47.8 之间销售的房屋密度比其他经度更高。这可能是其他社区相比，更安全、更宜居社区的指示。

1.  在绘制房屋价格与房屋卧室数量的关系时，我们意识到房屋卧室数量与价格之间的趋势与价格成正比，直到六个卧室，然后变为反比，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00229.jpeg)

1.  将每个房屋的居住面积与价格进行对比，我们发现价格随着房屋面积的增加而增加的趋势。最昂贵的房屋似乎有 12000 平方英尺的居住面积，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00230.jpeg)

# 还有更多...

1.  在绘制房屋状况与价格的关系时，我们再次注意到了一个预期的趋势，即随着房屋状况评分的提高，价格也在增加，如下面的屏幕截图所示。有趣的是，五卧室房屋的平均价格比四卧室房屋要低，这可能是因为对这么大的房子的购买者较少：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00231.jpeg)

1.  房屋邮政编码与价格的图表显示了不同邮政编码地区房屋价格的趋势。您可能已经注意到，某些邮政编码，如 98100 至 98125 之间的邮政编码，比其他地区有更多的房屋销售密度，而 98040 邮政编码地区的房屋价格高于平均价格，可能表明这是一个更富裕的社区，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00232.jpeg)

1.  房屋等级与价格的图表显示，随着等级的提高，价格呈一致增长的趋势。两者之间似乎存在明显的线性关系，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00233.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00234.jpeg)

# 另请参阅

在对数据进行任何模型运行之前，以下链接很好地解释了为什么数据可视化如此重要：

+   [`www.slideshare.net/Centerline_Digital/the-importance-of-data-visualization`](https://www.slideshare.net/Centerline_Digital/the-importance-of-data-visualization)

+   [`data-visualization.cioreview.com/cxoinsight/what-is-data-visualization-and-why-is-it-important-nid-11806-cid-163.html`](https://data-visualization.cioreview.com/cxoinsight/what-is-data-visualization-and-why-is-it-important-nid-11806-cid-163.html)

+   [`www.techchange.org/2015/05/19/data-visualization-analysis-international-development/`](https://www.techchange.org/2015/05/19/data-visualization-analysis-international-development/)

# 绘制价格与其他特征之间的相关性

现在初步的探索性分析已经完成，我们对不同变量如何影响每个房屋的价格有了更好的了解。然而，我们不知道每个变量在预测价格时的重要性。由于我们有 21 个变量，如果将所有变量合并到一个模型中，建模就会变得困难。因此，一些变量可能需要被丢弃或忽略，如果它们的重要性不如其他变量。

# 准备工作

相关系数在统计学中用于衡量两个变量之间的关系强度。特别是，在进行线性回归时，皮尔逊相关系数是最常用的系数。相关系数通常取-1 到+1 之间的值：

+   相关系数为 1 意味着对于一个变量的正增加，另一个变量也会以固定比例正增加。例如，鞋子尺寸几乎与脚长完美相关。

+   相关系数为-1 意味着对于一个变量的正增加，另一个变量会以固定比例负减少。例如，油箱中的汽油量几乎与加速度或齿轮机构完美相关（在一档行驶的时间较长时，与四档相比，汽油的使用量减少）。

+   零意味着对于每次增加，没有正面或负面的增加。两者之间没有关系。

# 如何做...

1.  通过使用以下命令从数据集中删除`id`和`date`特征开始。在我们的预测中，我们不会使用它们，因为 ID 变量都是唯一的，在我们的分析中没有价值，而日期需要使用不同的函数来正确处理它们。这留给读者自己练习：

```scala
 x_df = dataframe.drop(['id','date',], axis = 1)
 x_df
```

1.  使用以下命令将因变量（在本例中为房价）复制到新的`dataframe`中：

```scala
 y = dataframe[['price']].copy()
 y_df = pd.DataFrame(y)
 y_df
```

1.  价格和其他每个变量之间的相关性可以通过以下脚本手动找到：

```scala
 print('Price Vs Bedrooms: %s' % x_df['price'].corr(x_df['bedrooms']))
 print('Price Vs Bathrooms: %s' % x_df['price'].corr(x_df['bathrooms']))
 print('Price Vs Living Area: %s' % x_df['price'].corr(x_df['sqft_living']))
 print('Price Vs Plot Area: %s' % x_df['price'].corr(x_df['sqft_lot']))
 print('Price Vs No. of floors: %s' % x_df['price'].corr(x_df['floors']))
 print('Price Vs Waterfront property: %s' % x_df['price'].corr(x_df['waterfront']))
 print('Price Vs View: %s' % x_df['price'].corr(x_df['view']))
 print('Price Vs Grade: %s' % x_df['price'].corr(x_df['grade']))
 print('Price Vs Condition: %s' % x_df['price'].corr(x_df['condition']))
 print('Price Vs Sqft Above: %s' % x_df['price'].corr(x_df['sqft_above']))
 print('Price Vs Basement Area: %s' % x_df['price'].corr(x_df['sqft_basement']))
 print('Price Vs Year Built: %s' % x_df['price'].corr(x_df['yr_built']))
 print('Price Vs Year Renovated: %s' % x_df['price'].corr(x_df['yr_renovated']))
 print('Price Vs Zipcode: %s' % x_df['price'].corr(x_df['zipcode']))
 print('Price Vs Latitude: %s' % x_df['price'].corr(x_df['lat']))
 print('Price Vs Longitude: %s' % x_df['price'].corr(x_df['long']))
```

1.  除了前面的方法，还可以通过以下方式使用一个命令在一个`dataframe`中找到一个变量与所有其他变量（或列）之间的相关性：

`x_df.corr().iloc[:,-19]`

1.  相关变量可以使用`seaborn`库和以下脚本绘制：

```scala
 sns.pairplot(data=x_df,
 x_vars=['price'],
 y_vars=['bedrooms', 'bathrooms', 'sqft_living',
 'sqft_lot', 'floors', 'waterfront','view',
 'grade','condition','sqft_above','sqft_basement',
 'yr_built','yr_renovated','zipcode','lat','long'],
 size = 5)
```

# 它是如何工作的...

1.  删除`id`和`date`变量后，新的名为`x_df`的`dataframe`包含 19 个变量或列，如以下截图所示。对于本书的目的，只打印出前十个条目：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00235.jpeg)

输出的前 10 个条目

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00236.jpeg)

1.  创建一个只包含因变量（价格）的新`dataframe`，您将看到以下输出。这个新的`dataframe`名为`y_df`。同样，为了说明，只打印价格列的前十个条目：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00237.jpeg)

1.  价格和其他变量之间的相关性显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00238.jpeg)

1.  您可能已经注意到，`sqft_living`变量与价格的相关性最高，相关系数为 0.702035。其次是`grade`，相关系数为 0.667434，其次是`sqft_above`，相关系数为 0.605567。`Zipcode`与价格的相关性最低，相关系数为-0.053202。

# 还有更多...

+   使用简化代码找到的相关系数给出了完全相同的值，但也给出了价格与自身的相关性，结果是 1.0000，这是预期的。如以下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00239.jpeg)

+   使用`seaborn`库绘制的相关系数在以下截图中呈现。请注意，每个图中价格都在 x 轴上：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00240.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00241.jpeg)

相关系数的绘制

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00242.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00243.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00244.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00245.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00246.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00247.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00248.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00249.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00250.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00251.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00252.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00253.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00254.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00255.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00256.jpeg)

# 另请参阅

以下链接提供了对皮尔逊相关系数的出色解释以及如何手动计算它：

[`en.wikipedia.org/wiki/Pearson_correlation_coefficient`](https://en.wikipedia.org/wiki/Pearson_correlation_coefficient)

[`www.statisticshowto.com/probability-and-statistics/correlation-coefficient-formula/`](http://www.statisticshowto.com/probability-and-statistics/correlation-coefficient-formula/)

# 预测房价

本节将使用当前`数据框`中的所有特征构建一个简单的线性模型来预测房价。然后，我们将评估模型，并尝试在本节的后半部分使用更复杂的模型来提高准确性。

# 准备工作

访问以下链接以了解线性回归的工作原理以及如何在 Scikit Learn 库中使用线性回归模型：

[`en.wikipedia.org/wiki/Linear_regression`](https://en.wikipedia.org/wiki/Linear_regression)

[`www.stat.yale.edu/Courses/1997-98/101/linreg.htm`](http://www.stat.yale.edu/Courses/1997-98/101/linreg.htm)

[`newonlinecourses.science.psu.edu/stat501/node/251/`](https://newonlinecourses.science.psu.edu/stat501/node/251/)

[`scikit-learn.org/stable/modules/generated/sklearn.linear_model.LinearRegression.html`](http://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LinearRegression.html)

[`scikit-learn.org/stable/modules/linear_model.html`](http://scikit-learn.org/stable/modules/linear_model.html)

# 如何做...

1.  使用以下脚本从`x_df`数据框中删除`Price`列，并将其保存到名为`x_df2`的新`数据框`中：

```scala
 x_df2 = x_df.drop(['price'], axis = 1)
```

1.  声明一个名为`reg`的变量，并使用以下脚本将其等于 Scikit Learn 库中的`LinearRegression()`函数：

```scala
 reg=linear_model.LinearRegression()
```

1.  使用以下脚本将数据集分割为测试集和训练集：

```scala
 x_train,x_test,y_train,y_test = train_test_split(x_df2,y_df,test_size=0.4,random_state=4)
```

1.  使用以下脚本在训练集上拟合模型：

```scala
 reg.fit(x_train,y_train)
```

1.  通过使用`reg.coef_`命令打印应用线性回归到训练集和测试集生成的系数。

1.  使用以下脚本生成的模型预测列进行查看：

```scala
 predictions=reg.predict(x_test)
 predictions
```

1.  使用以下命令打印模型的准确性：

```scala
 reg.score(x_test,y_test)
```

# 它是如何工作的...

1.  将回归模型拟合到训练集后的输出必须如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00257.jpeg)

1.  `reg.coeff_`命令生成了 18 个系数，每个系数对应数据集中的一个变量，如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00258.jpeg)

1.  具有最正值的特征/变量的系数在价格预测中具有更高的重要性，与具有负值的特征/变量的系数相比。这是回归系数的主要重要性。

1.  打印预测时，您必须看到一个输出，其中包含从 1 到 21,612 的值数组，数据集中的每一行都有一个值，如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00259.jpeg)

1.  最后，打印模型的准确性，我们获得了 70.37%的准确性，对于线性模型来说并不差。如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00260.jpeg)

# 还有更多...

线性模型在第一次尝试时表现不错，但如果我们希望模型更准确，我们将不得不使用一个带有一些非线性的更复杂模型，以便很好地拟合所有数据点。XGBoost 是我们将在本节中使用的模型，以尝试通过线性回归提高准确性。这是以下方式完成的：

1.  使用`import xgboost`命令导入`XGBoost`库。

1.  如果出现错误，您将不得不通过终端进行库的 pip 安装。这可以通过打开一个新的终端窗口并发出以下命令来完成：

```scala
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  在这个阶段，您必须看到一个输出，其外观如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00261.jpeg)

1.  在这个阶段，您将被提示输入密码。安装 Homebrew 后，您将看到如下截屏所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00262.jpeg)

1.  接下来，使用以下命令安装 Python：

`brew install python`

1.  使用`brew doctor`命令检查您的安装并遵循 homebrew 的建议。

1.  一旦安装了`Homebrew`，请使用以下命令 pip 安装 XGBoost：

`pip install xgboost`

1.  安装完成后，您应该能够将 XGBoost 导入到 IPython 环境中。

一旦 XGBoost 成功导入到 Jupyter 环境中，您就可以使用库中的函数声明和存储模型。可以按以下步骤完成：

1.  声明一个名为`new_model`的变量来存储模型，并使用以下命令声明所有超参数：

```scala
new_model = xgboost.XGBRegressor(n_estimators=750, learning_rate=0.09,         gamma=0, subsample=0.65, colsample_bytree=1, max_depth=7)
```

1.  上述命令的输出必须看起来像以下截图中显示的那样：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00263.jpeg)

1.  将数据分割为测试集和训练集，并使用以下命令将新模型拟合到拆分数据中：

```scala
 from sklearn.model_selection import train_test_split
 traindf, testdf = train_test_split(x_train, test_size = 0.2)
 new_model.fit(x_train,y_train)
```

1.  在这一点上，您将看到类似以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00264.jpeg)

1.  最后，使用新拟合的模型预测房屋价格，并使用以下命令评估新模型：

```scala
 from sklearn.metrics import explained_variance_score
 predictions = new_model.predict(x_test)
 print(explained_variance_score(predictions,y_test))
```

1.  执行上述命令时，您必须看到类似以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00265.jpeg)

1.  请注意，新模型的准确性现在为 87.79%，约为 88%。这被认为是最佳的。

1.  在这种情况下，`估计器数量`设置为 750。在 100 到 1,000 之间进行实验后，确定 750 个估计器给出了最佳准确性。`学习率`设置为 0.09。`子采样率`设置为 65%。`最大深度`设置为 7。`max_depth`对模型准确性似乎没有太大影响。然而，使用较慢的学习率确实提高了准确性。通过尝试各种超参数，我们能够进一步将准确性提高到 89%。

1.  未来的步骤涉及对诸如卧室、浴室、楼层、邮政编码等变量进行独热编码，并在模型拟合之前对所有变量进行归一化。尝试调整超参数，如学习率、XGBoost 模型中的估计器数量、子采样率等，以查看它们如何影响模型准确性。这留给读者作为练习。

1.  此外，您可能希望尝试结合 XGBoost 和交叉验证，以找出模型中树的最佳数量，从而进一步提高准确性。

1.  可以进行的另一个练习是使用不同大小的测试和训练数据集，以及在训练过程中合并`date`变量。在我们的情况下，我们将其分割为 80%的训练数据和 20%的测试数据。尝试将测试集增加到 40%，看看模型准确性如何变化。

# 另请参阅

访问以下链接以了解如何调整 XGBoost 模型中的超参数以及如何在 XGBoost 中实现交叉验证：

[`xgboost.readthedocs.io/en/latest/python/index.html`](https://xgboost.readthedocs.io/en/latest/python/index.html)

[`xgboost.readthedocs.io/en/latest/get_started/`](http://xgboost.readthedocs.io/en/latest/get_started/)

[`www.kaggle.com/cast42/xg-cv`](https://www.kaggle.com/cast42/xg-cv)


# 第九章：使用 LSTM 预测苹果股票市场成本

多年来一直有股票市场预测，并且已经产生了整个预言家行业。这并不奇怪，因为如果预测正确，它可以带来可观的利润。了解何时是买入或卖出股票的好时机是在华尔街占据上风的关键。本章将专注于使用 Keras 上的 LSTM 创建深度学习模型来预测 AAPL 的股票市场报价。

本章将涵盖以下配方：

+   下载苹果的股票市场数据

+   探索和可视化苹果的股票市场数据

+   为模型性能准备股票数据

+   构建 LSTM 模型

+   评估 LSTM 模型

# 下载苹果的股票市场数据

有许多资源可用于下载苹果的股票市场数据。对于我们的目的，我们将使用 Yahoo! Finance 网站。

# 准备工作

本节将需要初始化一个 Spark 集群，该集群将用于本章中的所有配方。可以在终端使用`sparknotebook`初始化 Spark 笔记本，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00266.jpeg)

可以使用以下脚本在 Jupyter 笔记本中初始化`SparkSession`：

```scala
spark = SparkSession.builder \
    .master("local") \
    .appName("StockMarket") \
    .config("spark.executor.memory", "6gb") \
    .getOrCreate()
```

# 如何做到...

以下部分将介绍下载苹果的历史股票市场数据的步骤。

1.  访问以下网站，跟踪苹果的每日历史调整收盘股票价值，其股票代码为 AAPL：[`finance.yahoo.com/quote/AAPL/history`](https://finance.yahoo.com/quote/AAPL/history)

1.  设置并应用以下参数到历史数据选项卡：

1.  时间段：2000 年 1 月 1 日至 2018 年 4 月 30 日。

1.  显示：历史价格。

1.  频率：每日。

1.  通过单击下载数据链接，使用指定参数将数据集下载到`.csv`文件中，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00267.jpeg)

1.  下载文件`AAPL.csv`，然后使用以下脚本将相同的数据集上传到 Spark 数据框中：

```scala
df =spark.read.format('com.databricks.spark.csv')\
   .options(header='true', inferschema='true')\
   .load('AAPL.csv')
```

# 工作原理...

以下部分解释了如何将股票市场数据纳入 Jupyter 笔记本。

1.  Yahoo! Finance 是公开交易公司股票市场报价的重要来源。苹果的股票报价 AAPL 在纳斯达克交易，可以捕获历史报价以进行模型开发和分析。Yahoo! Finance 提供了在每日、每周或每月快照上捕获股票报价的选项。

1.  本章的目的是在每日级别预测股票，因为这将为我们的训练模型带来最多的数据。我们可以通过追溯数据到 2000 年 1 月 1 日，一直到 2018 年 4 月 30 日来实现这一点。

1.  一旦我们设置了下载参数，我们就会从 Yahoo! Finance 收到一个格式良好的逗号分隔值文件，可以很容易地转换为具有最少问题的 Spark 数据框。

1.  数据框将允许我们每天查看股票的日期、开盘价、最高价、最低价、收盘价、调整收盘价和成交量。数据框中的列跟踪开盘和收盘股票价值，以及当天交易的最高和最低价值。还捕获了当天交易的股票数量。Spark 数据框的输出`df`可以通过执行`df.show()`来显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00268.jpeg)

# 还有更多...

Python 有股票市场 API，允许您自动连接并拉取公开交易公司（如苹果）的股票市场报价。您需要输入参数并检索可以存储在数据框中的数据。然而，截至 2018 年 4 月，*Yahoo! Finance* API 不再运作，因此不是提取本章数据的可靠解决方案。

# 另请参阅

`Pandas_datareader` 是一个非常强大的库，可以从网站上提取数据，例如 Yahoo! Finance。要了解更多关于该库以及它如何在恢复在线后与 Yahoo! Finance 连接的信息，请访问以下网站：

[`github.com/pydata/pandas-datareader`](https://github.com/pydata/pandas-datareader)

# 探索和可视化苹果股票市场数据

在对数据进行任何建模和预测之前，首先探索和可视化手头的数据是很重要的，以发现任何隐藏的宝藏。

# 准备工作

在本节中，我们将对数据框进行转换和可视化。这将需要在 Python 中导入以下库：

+   `pyspark.sql.functions`

+   `matplotlib`

# 如何做...

以下部分将介绍探索和可视化股票市场数据的步骤。

1.  使用以下脚本通过删除时间戳来转换数据框中的 `Date` 列：

```scala
import pyspark.sql.functions as f
df = df.withColumn('date', f.to_date('Date'))
```

1.  创建一个循环来向数据框添加三个额外的列。循环将把 `date` 字段分解为 `year`、`month` 和 `day`，如下面的脚本所示：

```scala
date_breakdown = ['year', 'month', 'day']
for i in enumerate(date_breakdown):
    index = i[0]
    name = i[1]
    df = df.withColumn(name, f.split('date', '-')[index])
```

1.  使用以下脚本将 Spark 数据框的子集保存到名为 `df_plot` 的 `pandas` 数据框中：`df_plot = df.select('year', 'Adj Close').toPandas()`.

1.  使用以下脚本在笔记本中绘制和可视化 `pandas` 数据框 `df_plot`：

```scala
from matplotlib import pyplot as plt
%matplotlib inline

df_plot.set_index('year', inplace=True)
df_plot.plot(figsize=(16, 6), grid=True)
plt.title('Apple stock')
plt.ylabel('Stock Quote ($)')
plt.show()
```

1.  使用以下脚本计算我们的 Spark 数据框的行和列数：`df.toPandas().shape`。

1.  执行以下脚本来确定数据框中的空值：`df.dropna().count()`。

1.  执行以下脚本来获取 `Open`、`High`、`Low`、`Close` 和 `Adj Close` 的统计数据：

```scala
df.select('Open', 'High', 'Low', 'Close', 'Adj Close').describe().show()
```

# 它是如何工作的...

以下部分解释了探索性数据分析所使用的技术和获得的见解。

1.  数据框中的日期列更像是一个带有时间值的日期时间列，所有时间值都以 00:00:00 结尾。这对于我们建模过程中的需求是不必要的，因此可以从数据集中删除。幸运的是，PySpark 有一个 `to_date` 函数可以很容易地做到这一点。数据框 `df` 使用 `withColumn()` 函数进行转换，现在只显示日期列而没有时间戳，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00269.jpeg)

1.  为了分析目的，我们想要从日期列中提取 `day`、`month` 和 `year`。我们可以通过枚举一个自定义列表 `date_breakdown` 来实现这一点，通过 `-` 分割日期，然后使用 `withColumn()` 函数为年、月和日添加新列。更新后的数据框中可以看到新添加的列，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00270.jpeg)

一个重要的要点是，`PySpark` 也有一个用于日期的 SQL 函数，可以从日期时间戳中提取日、月或年。例如，如果我们要向数据框添加一个月份列，我们将使用以下脚本：`df.withColumn("month",f.month("date")).show()`。这是为了突出在 Spark 中有多种方法可以转换数据。

1.  Spark 数据框的可视化功能比 `pandas` 数据框更有限。因此，我们将从 Spark 数据框 `df` 中提取两列，并将它们转换为 `pandas` 数据框，以绘制线形或时间序列图。y 轴将是股票的调整收盘价，x 轴将是日期的年份。

1.  准备好的 pandas 数据框 df_plot 可以在设置一些格式特性后使用 matplotlib 进行绘制，例如网格可见性、绘图的图形大小以及标题和轴的标签。此外，我们明确指出数据框的索引需要指向年份列。否则，默认索引将出现在 x 轴上而不是年份。最终的时间序列图可以在下面的屏幕截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00271.jpeg)

1.  在过去的 18 年中，苹果经历了广泛的增长。虽然有几年出现了一些下跌，但总体趋势是稳步上升，过去几年的股票报价在 150 美元和 175 美元之间徘徊。

1.  到目前为止，我们对数据框进行了一些更改，因此重要的是要对行和列的总数进行清点，因为这将影响后面在本章中对数据集进行测试和训练的方式。如下截图所示，我们总共有 10 列和 4,610 行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00272.jpeg)

1.  当执行`df.dropna().count()`时，我们可以看到行数仍然是 4,610，与上一步的行数相同，表明没有任何行具有空值。

1.  最后，我们可以得到每个将用于模型的列的行数、均值、标准差、最小值和最大值的良好读数。这可以帮助确定数据中是否存在异常。需要注意的一点是，将用于模型的五个字段的标准差都高于均值，表明数据更分散，而不是围绕均值聚集。可以在以下截图中看到 Open、High、Low、Close 和 Adj Close 的统计数据：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00273.jpeg)

# 还有更多...

虽然 Spark 中的数据框没有`pandas`数据框中的本地可视化功能，但有些公司可以通过笔记本提供高级可视化功能，而无需使用诸如`matplotlib`之类的库。Databricks 是一家提供此功能的公司之一。

以下是使用 Databricks 笔记本中内置功能的可视化示例：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00274.jpeg)

# 另请参阅

要了解有关 Databricks 的更多信息，请访问以下网站：[`databricks.com/`](https://databricks.com/)。

要了解 Databricks 笔记本中的可视化更多信息，请访问以下网站：[`docs.databricks.com/user-guide/visualizations/index.html`](https://docs.databricks.com/user-guide/visualizations/index.html)。

要了解如何通过 Microsoft Azure 订阅访问 Databricks 的更多信息，请访问以下网站：

[`azure.microsoft.com/en-us/services/databricks/`](https://azure.microsoft.com/en-us/services/databricks/)

# 为模型性能准备股票数据

我们几乎准备好为苹果的股票价值表现构建预测算法了。手头剩下的任务是以确保最佳预测结果的方式准备数据。

# 准备工作

在本节中，我们将对数据框执行转换和可视化。这将需要在 Python 中导入以下库：

+   `numpy`

+   `MinMaxScaler()`

# 如何做...

本节将介绍为我们的模型准备股票市场数据的步骤。

1.  执行以下脚本将年份列按`Adj Close`计数分组：

```scala
df.groupBy(['year']).agg({'Adj Close':'count'})\
     .withColumnRenamed('count(Adj Close)', 'Row Count')\
     .orderBy(["year"],ascending=False)\
     .show()
```

1.  执行以下脚本创建两个新的用于训练和测试的数据框：

```scala
trainDF = df[df.year < 2017]
testDF = df[df.year > 2016]
```

1.  使用以下脚本将两个新数据框转换为`pandas`数据框，以获取行和列计数：

```scala
trainDF.toPandas().shape
testDF.toPandas().shape
```

1.  与`df`之前所做的一样，我们使用以下脚本可视化`trainDF`和`testDF`：

```scala
trainDF_plot = trainDF.select('year', 'Adj Close').toPandas()
trainDF_plot.set_index('year', inplace=True)
trainDF_plot.plot(figsize=(16, 6), grid=True)
plt.title('Apple Stock 2000-2016')
plt.ylabel('Stock Quote ($)')
plt.show()

testDF_plot = testDF.select('year', 'Adj Close').toPandas()
testDF_plot.set_index('year', inplace=True)
testDF_plot.plot(figsize=(16, 6), grid=True)
plt.title('Apple Stock 2017-2018')
plt.ylabel('Stock Quote ($)')
plt.show()
```

1.  我们根据以下脚本创建两个新数组`trainArray`和`testArray`，除了日期列以外的数据框的数据：

```scala
import numpy as np
trainArray = np.array(trainDF.select('Open', 'High', 'Low',                     'Close','Volume', 'Adj Close' ).collect())
testArray = np.array(testDF.select('Open', 'High', 'Low', 'Close','Volume',     'Adj Close' ).collect())
```

1.  为了将数组缩放到 0 到 1 之间，从`sklearn`导入`MinMaxScaler`并创建一个函数调用`MinMaxScale`，使用以下脚本：

```scala
from sklearn.preprocessing import MinMaxScaler
minMaxScale = MinMaxScaler()
```

1.  然后在`trainArray`上拟合`MinMaxScaler`并使用以下脚本创建两个新数组，以便进行缩放：

```scala
minMaxScale.fit(trainArray)

testingArray = minMaxScale.transform(testArray)
trainingArray = minMaxScale.transform(trainArray)
```

1.  使用以下脚本将`testingArray`和`trainingArray`拆分为特征`x`和标签`y`：

```scala
xtrain = trainingArray[:, 0:-1]
xtest = testingArray[:, 0:-1]
ytrain = trainingArray[:, -1:]
ytest = testingArray[:, -1:]
```

1.  执行以下脚本以检索所有四个数组的最终形状清单：

```scala
print('xtrain shape = {}'.format(xtrain.shape))
print('xtest shape = {}'.format(xtest.shape))
print('ytrain shape = {}'.format(ytrain.shape))
print('ytest shape = {}'.format(ytest.shape))
```

1.  执行以下脚本来绘制报价`open`、`high`、`low`和`close`的训练数组：

```scala
plt.figure(figsize=(16,6))
plt.plot(xtrain[:,0],color='red', label='open')
plt.plot(xtrain[:,1],color='blue', label='high')
plt.plot(xtrain[:,2],color='green', label='low')
plt.plot(xtrain[:,3],color='purple', label='close')
plt.legend(loc = 'upper left')
plt.title('Open, High, Low, and Close by Day')
plt.xlabel('Days')
plt.ylabel('Scaled Quotes')
plt.show()
```

1.  此外，我们使用以下脚本绘制`volume`的训练数组：

```scala
plt.figure(figsize=(16,6))
plt.plot(xtrain[:,4],color='black', label='volume')
plt.legend(loc = 'upper right')
plt.title('Volume by Day')
plt.xlabel('Days')
plt.ylabel('Scaled Volume')
plt.show()
```

# 工作原理...

本节将解释数据在模型中使用时所需的转换。

1.  建立模型的第一步之一是将数据分割为训练和测试数据集，以进行模型评估。我们的目标是使用 2000 年至 2016 年的所有股票报价来预测 2017 年至 2018 年的股票趋势。我们知道从前面的部分我们有总共 4,610 天的股票报价，但我们不知道每年有多少。我们可以使用数据框中的`groupBy()`函数来获取每年股票报价的唯一计数，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00275.jpeg)

1.  2016 年和 2017 年的合并数据大约占总数据的 7%，这对于测试数据集来说有点小。但是，对于这个模型的目的来说，应该是足够的。剩下的 93%的数据将用于 2000 年至 2016 年的训练。因此，使用筛选器创建了两个数据框，以确定是否包括或排除 2016 年之前或之后的行。

1.  我们现在可以看到测试数据集`testDF`包含 333 行，而训练数据集`trainDF`包含 4,277 行。当两者合并时，我们可以得到原始数据框`df`的总行数为 4,610。最后，我们看到`testDF`仅由 2017 年和 2018 年的数据组成，2017 年有 251 行，2018 年有 82 行，总共 333 行，如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00276.jpeg)

请注意，每当我们将 Spark 数据框转换为`pandas`数据框时，它可能不适用于大数据。虽然对于我们的特定示例它可以工作，因为我们使用的是相对较小的数据集，但是将数据转换为`pandas`数据框意味着所有数据都加载到驱动程序的内存中。一旦发生这种转换，数据就不会存储在 Spark 工作节点中，而是存储在主驱动节点中。这并不是最佳的做法，可能会产生内存不足的错误。如果您发现需要将 Spark 转换为`pandas`数据框来可视化数据，建议从 Spark 中提取一个随机样本，或者将 Spark 数据聚合到一个更易管理的数据集中，然后在`pandas`中进行可视化。

1.  一旦将数据的子集转换为`toPandas()`以利用`pandas`的内置绘图功能，就可以使用`matplotlib`可视化测试和训练数据框。将数据框并排可视化展示了当未缩放调整收盘价的 y 轴时，图表看起来相似。实际上，我们可以看到`trainDF_plot`从 0 开始，而`testDF_plot`从 110 开始，如下两个截图所示。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00277.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00278.jpeg)

1.  目前我们的股票价值不适合深度学习建模，因为没有归一化或标准化的基线。在使用神经网络时，最好将值保持在 0 到 1 之间，以匹配 Sigmoid 或 Step 函数中的结果，这些函数用于激活。为了实现这一点，我们必须首先将`pyspark`数据框`trainDF`和`testDF`转换为`numpy`数组，即`trainArray`和`testArray`。由于这些现在是数组而不是数据框，我们将不再使用日期列，因为神经网络只对数值感兴趣。每个数组的第一个值可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00279.jpeg)

1.  有许多方法可以将数组值缩放到 0 到 1 之间的范围。它涉及使用以下公式：`缩放后的数组值 = (数组值 - 最小数组值) / (最大数组值 - 最小数组值)`。幸运的是，我们不需要手动计算数组的值。我们可以利用`sklearn`中的`MinMaxScaler()`函数来缩放这两个数组。

1.  `MinMaxScaler()`函数适用于训练数组`trainArray`，然后应用于创建两个全新的数组`trainingArray`和`testingArray`，它们的值在 0 到 1 之间进行了缩放。每个数组的第一行可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00280.jpeg)

1.  现在，我们准备通过将数组切片为测试和训练目的的 x 和 y 来设置我们的标签和特征变量。数组中的前五个元素是特征或 x 值，最后一个元素是标签或 y 值。特征由 Open、High、Low、Close 和 Volume 的值组成。标签由 Adj Close 组成。`trainingArray`的第一行的拆分可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00281.jpeg)

1.  最后，我们将查看我们在模型中将要使用的四个数组的形状，以确认我们有 4,227 个训练数据矩阵行，333 个测试数据矩阵行，5 个特征元素(`x`)和 1 个标签元素(`y`)，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00282.jpeg)

1.  训练数组`xtrain`的 open、low、high 和 close 的值可以使用新调整的 0 到 1 之间的标度绘制报价，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00283.jpeg)

1.  此外，`volume`也可以使用 0 到 1 之间的缩放体积得分绘制，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00284.jpeg)

# 还有更多...

虽然我们使用了来自`sklearn`的`MinMaxScaler`，但也很重要的是要了解，`pyspark.ml.feature`中也有一个`MinMaxScaler`函数可供使用。它的工作方式与`sklearn`完全相同，通过将每个特征重新缩放为 0 到 1 之间的值。如果我们在本章中使用了 PySpark 中的机器学习库来进行预测，我们将使用`pyspark.ml.feature`中的`MinMaxScaler`。

# 另请参阅

要了解来自`sklearn`的`MinMaxScaler`的更多信息，请访问以下网站：

[`scikit-learn.org/stable/modules/generated/sklearn.preprocessing.MinMaxScaler.html.`](http://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.MinMaxScaler.html)

要了解来自`pyspark`的`MinMaxScaler`的更多信息，请访问以下网站：

[`spark.apache.org/docs/2.2.0/ml-features.html#minmaxscaler.`](https://spark.apache.org/docs/2.2.0/ml-features.html#minmaxscaler)

# 构建 LSTM 模型

现在数据以符合 Keras 用于 LSTM 建模的模型开发格式。因此，我们将在本节中设置和配置深度学习模型，以预测 2017 年和 2018 年苹果股票报价。

# 准备工作

在本节中，我们将对模型进行模型管理和超参数调整。这将需要在 Python 中导入以下库：

```scala
from keras import models
from keras import layers
```

# 如何做...

本节将介绍设置和调整 LSTM 模型的步骤。

1.  使用以下脚本从`keras`导入以下库：

```scala
from keras import models, layers
```

1.  使用以下脚本构建一个`Sequential`模型：

```scala
model = models.Sequential()
model.add(layers.LSTM(1, input_shape=(1,5)))
model.add(layers.Dense(1))
model.compile(loss='mean_squared_error', optimizer='adam')
```

1.  使用以下脚本将测试和训练数据集转换为三维数组：

```scala
xtrain = xtrain.reshape((xtrain.shape[0], 1, xtrain.shape[1]))
xtest = xtest.reshape((xtest.shape[0], 1, xtest.shape[1]))
```

1.  使用以下脚本使用名为`loss`的变量来`fit`模型：

```scala
loss = model.fit(xtrain, ytrain, batch_size=10, epochs=100)
```

1.  使用以下脚本创建一个新数组`predicted`：

```scala
predicted = model.predict(xtest)
```

1.  使用以下脚本将`predicted`和`ytest`数组合并成一个统一的数组`combined_array`：

```scala
combined_array = np.concatenate((ytest, predicted), axis = 1)
```

# 它是如何工作的...

本节解释了如何配置 LSTM 神经网络模型以在我们的数据集上进行训练。

1.  大部分用于构建 LSTM 模型的`keras`功能将来自`models`和`layers`。

1.  构建的`LSTM`模型将使用`Sequential`类进行定义，该类与依赖于序列的时间序列非常匹配。LSTM 模型的`input_shape = (1,5)`，表示我们的训练数据集中有一个因变量和五个自变量。只使用一个`Dense`层来定义神经网络，因为我们希望保持模型简单。在 keras 中编译模型时需要一个损失函数，由于我们正在对递归神经网络进行操作，因此最好使用`mean_squared_error`计算来确定预测值与实际值的接近程度。最后，在编译模型时还需要定义一个优化器来调整神经网络中的权重。`adam`在递归神经网络中表现良好，尤其是在使用时。

1.  我们当前的数组`xtrain`和`xtest`目前是二维数组；然而，为了将它们纳入 LSTM 模型中，它们需要使用`reshape()`转换为三维数组，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00285.jpeg)

1.  LSTM 模型使用`xtrain`和`ytrain`进行拟合，批量大小设置为 10，时期数设置为 100。批量大小是定义一起训练的对象数量的设置。我们可以根据需要设置批量大小的大小，但要记住，批量数量越低，需要的内存就越多。此外，时期是模型遍历整个数据集的次数的度量。最终，这些参数可以根据时间和内存分配进行调整。

每个时期的均方误差损失都被捕获并可视化。在第五或第六个时期之后，我们可以看到损失逐渐减小，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00286.jpeg)

1.  我们现在可以创建一个新数组`predicted`，基于应用于`xtest`的拟合模型，然后将其与`ytest`结合在一起，以便进行准确性比较。

# 另请参阅

要了解更多关于 keras 中参数调整模型的信息，请访问以下网站：[`keras.io/models/model/`](https://keras.io/models/model/)

# 评估模型

现在到了关键时刻：我们将看看我们的模型是否能够为 2017 年和 2018 年的 AAPL 股票提供良好的预测。

# 准备工作

我们将使用均方误差进行模型评估。因此，我们需要导入以下库：

```scala
import sklearn.metrics as metrics
```

# 如何做...

本节介绍了可视化和计算 2017 年和 2018 年苹果公司预测与实际股票报价的过程。

1.  绘制`Actual`与`Predicted`股票的并排比较图，使用以下脚本：

```scala
plt.figure(figsize=(16,6))
plt.plot(combined_array[:,0],color='red', label='actual')
plt.plot(combined_array[:,1],color='blue', label='predicted')
plt.legend(loc = 'lower right')
plt.title('2017 Actual vs. Predicted APPL Stock')
plt.xlabel('Days')
plt.ylabel('Scaled Quotes')
plt.show()
```

1.  使用以下脚本计算实际`ytest`与`predicted`股票之间的均方误差：

```scala
import sklearn.metrics as metrics
np.sqrt(metrics.mean_squared_error(ytest,predicted))
```

# 工作原理...

本节解释了 LSTM 模型评估的结果。

1.  从图形上看，我们可以看到我们的预测与 2017 年至 2018 年的实际股票报价非常接近，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00287.jpeg)

1.  我们的模型显示，对于 2017 年和 2018 年的前几天，预测值与实际值更接近。总的来说，虽然我们的预测值和实际得分似乎非常接近，但最好还是进行均方误差计算，以了解两者之间的偏差有多大。正如我们所看到的，我们的均方误差为 0.05841，约为 5.8%。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00288.jpeg)

# 另请参阅

要了解更多关于 sklearn 中如何计算均方误差的信息，请访问以下网站：

[`scikit-learn.org/stable/modules/generated/sklearn.metrics.mean_squared_error.html`](http://scikit-learn.org/stable/modules/generated/sklearn.metrics.mean_squared_error.html)。


# 第十章：使用深度卷积网络进行人脸识别

在本章中，我们将涵盖以下配方：

+   下载并将 MIT-CBCL 数据集加载到内存中

+   从目录中绘制和可视化图像

+   图像预处理

+   模型构建、训练和分析

# 介绍

在当今世界，维护信息安全的需求变得越来越重要，同时也变得越来越困难。有各种方法可以强制执行此安全性（密码、指纹 ID、PIN 码等）。然而，就易用性、准确性和低侵入性而言，人脸识别算法一直表现得非常出色。随着高速计算的可用性和深度卷积网络的发展，进一步增加了这些算法的稳健性成为可能。它们已经变得如此先进，以至于现在它们被用作许多电子设备（例如 iPhoneX）甚至银行应用程序中的主要安全功能。本章的目标是开发一个稳健的、姿势不变的人脸识别算法，用于安全系统。为了本章的目的，我们将使用公开可用的`MIT-CBCL`数据集，其中包含 10 个不同主题的人脸图像。

# 下载并将 MIT-CBCL 数据集加载到内存中

在这个配方中，我们将了解如何下载 MIT-CBCL 数据集并将其加载到内存中。

到 2025 年，生物识别行业的预测价值将达到 150 亿美元，这意味着它将前所未有地增长。用于生物识别认证的一些生理特征的例子包括指纹、DNA、面部、视网膜或耳朵特征和声音。虽然 DNA 认证和指纹等技术相当先进，但人脸识别也带来了自己的优势。

由于深度学习模型的最新发展，易用性和稳健性是人脸识别算法如此受欢迎的驱动因素之一。

# 准备工作

对于这个配方，需要考虑以下关键点：

+   `MIT-CBCL`数据集由 3,240 张图像组成（每个主题 324 张图像）。在我们的模型中，我们将安排增加数据以增加模型的稳健性。我们将采用诸如移动主题、旋转、缩放和剪切主题等技术来获得这些增强的数据。

+   我们将使用数据集的 20%（648 张图像）来测试我们的模型，通过从数据集中随机选择这些图像。同样，我们随机选择数据集中 80%的图像，并将其用作我们的训练数据集（2,592 张图像）。

+   最大的挑战是裁剪图像到完全相同的大小，以便它们可以被馈送到神经网络中。

+   众所周知，当所有输入图像的大小相同时，设计网络要容易得多。然而，由于这些图像中的一些主题具有侧面轮廓或旋转/倾斜轮廓，我们必须使我们的网络适应接受不同大小的输入图像。

# 操作方法...

步骤如下。

1.  通过访问人脸识别主页下载`MIT-CBCL`数据集，该主页包含用于人脸识别实验的多个数据库。链接以及主页的屏幕截图如下所示：

[`www.face-rec.org/databases/`](http://www.face-rec.org/databases/)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00289.jpeg)

1.  向下导航到名为 MIT-CBCL 人脸识别数据库的链接，并单击它，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00290.jpeg)

1.  一旦你点击它，它会带你到一个许可页面，在这个页面上你需要接受许可协议并转到下载页面。一旦在下载页面上，点击`立即下载`。这将下载一个大约 116MB 的 zip 文件。继续提取内容到工作目录中。

# 工作原理...

功能如下：

1.  许可协议要求在任何项目中使用数据库时进行适当引用。该数据库是由麻省理工学院的研究团队开发的。

1.  特此感谢麻省理工学院和生物计算学习中心提供面部图像数据库。许可证还要求提及题为*Component-based Face Recognition with 3D Morphable Models, First IEEE Workshop on Face Processing in Video,* Washington, D.C., 2004, B. Weyrauch, J. Huang, B. Heisele, and V. Blanz 的论文。

1.  以下截图描述了许可协议以及下载数据集的链接：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00291.jpeg)

面部识别数据库主页

1.  数据集下载并提取后，您将看到一个名为 MIT-CBCL-facerec-database 的文件夹。

1.  为本章的目的，我们将仅使用**`training-synthetic`**文件夹中的图像，该文件夹包含所有 3,240 张图像，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00292.jpeg)

# 还有更多...

对于本章，您将需要 Python 导入以下库：

+   `os`

+   `matplotlib`

+   `numpy`

+   `keras`

+   `TensorFlow`

本章的以下部分将涉及导入必要的库和预处理图像，然后构建神经网络模型并将其加载到其中。 

# 另请参阅

有关本章中使用的软件包的完整信息，请访问以下链接：

+   [`matplotlib.org/`](https://matplotlib.org/)

+   [`docs.python.org/2/library/os.html`](https://docs.python.org/2/library/os.html)

+   [`www.tensorflow.org/get_started/`](https://www.tensorflow.org/get_started/)

+   [`keras.io/layers/about-keras-layers/`](https://keras.io/layers/about-keras-layers/)

+   [`docs.scipy.org/doc/numpy-1.9.1/reference/`](https://docs.scipy.org/doc/numpy-1.9.1/reference/)

# 绘制和可视化目录中的图像

本节将描述如何在对图像进行预处理并输入到神经网络进行训练之前，如何读取和可视化下载的图像。这是本章中的重要步骤，因为需要可视化图像以更好地了解图像尺寸，以便可以准确裁剪以省略背景并仅保留必要的面部特征。

# 准备工作

在开始之前，完成导入必要库和函数以及设置工作目录路径的初始设置。

# 如何做...

步骤如下：

1.  使用以下代码行下载必要的库。输出必须产生一行，显示`Using TensorFlow backend`，如下截图所示：

```scala
%matplotlib inline
from os import listdir
from os.path import isfile, join
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import numpy as np
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation, Flatten, Conv2D
from keras.optimizers import Adam
from keras.layers.normalization import BatchNormalization
from keras.utils import np_utils
from keras.layers import MaxPooling2D
from keras.preprocessing.image import ImageDataGenerator
```

导入库如下所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00293.jpeg)

1.  按照以下截图中所示的方式打印并设置当前工作目录。在我们的案例中，桌面被设置为工作目录：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00294.jpeg)

1.  通过使用以下截图中说明的命令直接从文件夹中读取所有图像：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00295.jpeg)

1.  使用`plt.imshow(images[])`命令从数据集中打印一些随机图像，如下截图所示，以更好地了解图像中的面部轮廓。这也将给出图像的大小的概念，这将在后期需要：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00296.jpeg)

1.  这里显示了来自第一张图像的不同测试对象的图像。

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00297.jpeg)![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00298.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00299.jpeg)

# 工作原理...

功能如下：

1.  `mypath`变量设置要从中读取所有文件的路径。在此步骤中指定了`training-synthetic`文件夹，因为本章仅使用该文件夹中的文件。

1.  `onlyfiles`变量用于通过循环遍历文件夹中包含的所有文件来计算文件夹中的所有文件的数量。这将在下一步中用于读取和存储图像。

1.  `images`变量用于创建一个大小为 3,240 的空数组，以存储所有尺寸为 200 x 200 像素的图像。

1.  接下来，通过在 for 循环中使用`onlyfiles`变量作为参数来循环遍历所有文件，将文件夹中包含的每个图像读取并存储到先前定义的`images`数组中，使用`matplotlib.image`函数。

1.  最后，通过指定不同索引的图像来打印随机选择的图像，您将注意到每个图像都是一个 200 x 200 像素的数组，每个主题可能是面向前方，也可能在两侧之间旋转零至十五度。

# 还有更多...

以下几点值得注意：

+   该数据库的一个有趣特点是，每个文件名的第四个数字描述了相应图像中的主题是谁。

+   图像的名称在某种意义上是唯一的，第四个数字代表了相应图像中的个体。图像名称的两个示例是`0001_-4_0_0_60_45_1.pgm`和`0006_-24_0_0_0_75_15_1.pgm`。可以很容易地理解，第四个数字分别代表了第二个和第七个个体。

+   我们需要存储这些信息以备将来在进行预测时使用。这将有助于神经网络在训练过程中了解它正在学习哪个主题的面部特征。

+   可以通过以下代码将每个图像的文件名读入数组，并使用以下代码将十个主题中的每一个分隔开：

```scala
y =np.empty([3240,1],dtype=int)
for x in range(0, len(onlyfiles)):
    if onlyfiles[x][3]=='0': y[x]=0
    elif onlyfiles[x][3]=='1': y[x]=1
    elif onlyfiles[x][3]=='2': y[x]=2
    elif onlyfiles[x][3]=='3': y[x]=3
    elif onlyfiles[x][3]=='4': y[x]=4
    elif onlyfiles[x][3]=='5': y[x]=5
    elif onlyfiles[x][3]=='6': y[x]=6
    elif onlyfiles[x][3]=='7': y[x]=7
    elif onlyfiles[x][3]=='8': y[x]=8
    elif onlyfiles[x][3]=='9': y[x]=9
```

+   上述代码将初始化一个大小为 3,240 的空的一维`numpy`数组（`training-synthetic`文件夹中的图像数量），并通过循环遍历整个文件集，将相关主题存储在不同的数组中。

+   `if`语句基本上是在检查每个文件名下的第四个数字，并将该数字存储在初始化的`numpy`数组中。

+   在 iPython 笔记本中的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00300.jpeg)

# 另请参阅

以下博客描述了 Python 中裁剪图像的方法，并可用于图像预处理，这将在下一节中需要：

+   [`www.blog.pythonlibrary.org/2017/10/03/how-to-crop-a-photo-with-python/`](https://www.blog.pythonlibrary.org/2017/10/03/how-to-crop-a-photo-with-python/)

有关 Adam Optimizer 及其用例的更多信息，请访问以下链接：

+   [`www.tensorflow.org/api_docs/python/tf/train/AdamOptimizer`](https://www.tensorflow.org/api_docs/python/tf/train/AdamOptimizer)

+   [`arxiv.org/abs/1412.6980`](https://arxiv.org/abs/1412.6980)

+   [`www.coursera.org/lecture/deep-neural-network/adam-optimization-algorithm-w9VCZ`](https://www.coursera.org/lecture/deep-neural-network/adam-optimization-algorithm-w9VCZ)

# 图像预处理

在前一节中，您可能已经注意到所有图像都不是脸部正面视图，还有些略微旋转的侧面轮廓。您可能还注意到每个图像中都有一些不必要的背景区域需要去除。本节将描述如何预处理和处理图像，使其准备好被馈送到网络进行训练。

# 准备工作

考虑以下内容：

+   许多算法被设计用来裁剪图像的重要部分；例如 SIFT、LBP、Haar-cascade 滤波器等。

+   然而，我们将用一个非常简单的天真代码来解决这个问题，从图像中裁剪出面部部分。这是该算法的一个新颖之处。

+   我们发现不必要的背景部分的像素强度为 28。

+   请记住，每个图像都是一个三通道的 200 x 200 像素矩阵。这意味着每个图像包含三个矩阵或张量，红色、绿色和蓝色像素的强度范围从 0 到 255。

+   因此，我们将丢弃图像中仅包含像素强度为 28 的行或列。

+   我们还将确保所有图像在裁剪操作后具有相同的像素大小，以实现卷积神经网络的最高并行性。

# 操作步骤如下：

步骤如下：

1.  定义`crop()`函数以裁剪图像，仅获取重要部分，如下代码所示：

```scala
 #function for cropping images to obtain only the significant part
 def crop(img):
      a=28*np.ones(len(img)) 
      b=np.where((img== a).all(axis=1)) 
      img=np.delete(img,(b),0) 
      plt.imshow(img)
      img=img.transpose()
      d=28*np.ones(len(img[0]))
      e=np.where((img== d).all(axis=1))
      img=np.delete(img,e,0) 
      img=img.transpose()
      print(img.shape) 
      super_threshold_indices = img < 29 
      img[super_threshold_indices] = 0
      plt.imshow (img)
      return img[0:150, 0:128]
```

1.  使用以下代码循环遍历文件夹中的每个图像并使用前面定义的函数进行裁剪：

```scala
#cropping all the images
 image = np.empty([3240,150,128],dtype=int)
 for n in range(0, len(images)):
     image[n]=crop(images[n])
```

1.  接下来，随机选择一幅图像并打印它，以检查它是否已从 200 x 200 大小的图像裁剪到不同的大小。在我们的案例中，我们选择了图像 23。可以使用以下代码完成：

```scala
 print (image[22])
 print (image[22].shape)
```

1.  接下来，使用文件夹中`80%`的图像作为训练集，剩余的`20%`作为测试集，将数据分割为测试集和训练集。可以使用以下命令完成：

```scala
# Split data into 80/20 split for testing and training
test_ind=np.random.choice(range(3240), 648, replace=False) train_ind=np.delete(range(0,len(onlyfiles)),test_ind)
```

1.  一旦数据完成拆分，使用以下命令将训练和测试图像分开：

```scala
 # slicing the training and test images 
 y1_train=y[train_ind]
 x_test=image[test_ind]
 y1_test=y[test_ind]
```

1.  接下来，将所有裁剪后的图像重塑为 128 x 150 的大小，因为这是要馈送到神经网络中的大小。可以使用以下命令完成：

```scala
#reshaping the input images
 x_train = x_train.reshape(x_train.shape[0], 128, 150, 1)
 x_test = x_test.reshape(x_test.shape[0], 128, 150, 1)
```

1.  一旦数据完成重塑，将其转换为`float32`类型，这将使其在下一步中更容易处理。可以使用以下命令从 int 转换为 float32：

```scala
 #converting data to float32
 x_train = x_train.astype('float32')
 x_test = x_test.astype('float32')
```

1.  在重塑和将数据转换为 float32 类型后，必须对其进行归一化，以调整所有值到相似的范围。这是防止数据冗余的重要步骤。使用以下命令执行归一化：

```scala
 #normalizing data
 x_train/=255
 x_test/=255
 #10 digits represent the 10 classes
 number_of_persons = 10
```

1.  最后一步是将重塑、归一化的图像转换为向量，因为这是神经网络理解的唯一输入形式。使用以下命令将图像转换为向量：

```scala
 #convert data to vectors
 y_train = np_utils.to_categorical(y1_train, number_of_persons)
 y_test = np_utils.to_categorical(y1_test, number_of_persons)
```

# 工作原理如下：

功能如下：

1.  `crop()`函数执行以下任务：

1.  将所有像素强度为 28 的像素乘以一个 numpy 数组 1，并存储在变量`a`中。

1.  检查所有实例，其中整列仅由像素强度为 28 的像素组成，并存储在变量`b`中。

1.  删除所有列（或*Y*轴）中像素强度为 28 的整列。

1.  绘制生成的图像。

1.  1.  转置图像，以便对所有行（或*X*轴）执行类似的操作。

1.  1.  将所有像素强度为 28 的像素乘以一个`numpy`数组 1，并存储在变量`d`中。

1.  检查所有实例，其中整列仅由像素强度为 28 的像素组成，并存储在变量`e`中。

1.  删除所有列（从转置图像中）中像素强度为 28 的整列。

1.  转置图像以恢复原始图像。

1.  打印图像的形状。

1.  在发现像素强度小于 29 的地方，将这些像素强度替换为零，这将导致通过使它们变白来裁剪所有这些像素。

1.  绘制生成的图像。

1.  将生成的图像重塑为 150 x 128 像素的大小。

`crop()`函数的输出，如在 Jupyter 笔记本执行期间所见，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00301.jpeg)

1.  接下来，通过循环遍历`training-synthetic`文件夹中包含的所有文件，将定义的`crop()`函数应用于所有文件。这将导致如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00302.jpeg)

输出如下：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00303.jpeg)

注意，仅保留了相关的面部特征，并且所有裁剪后的图像的形状都小于 200 x 200，这是初始大小。

1.  打印任意图像的图像和形状，您会注意到每个图像现在都被调整为一个 150 x 128 像素的数组，并且您将看到以下输出：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00304.jpeg)

1.  将图像分割为测试集和训练集，并将它们分隔为名为`x_train`、`y1_train`、`x_test`和`y1_test`的变量，将导致以下截图中看到的输出：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00305.jpeg)

1.  数据的分离如下进行：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00306.jpeg)

1.  对训练和测试图像进行重塑并将数据类型转换为 float32 将导致以下截图中看到的输出：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00307.jpeg)

# 还有更多...

考虑以下内容：

+   一旦图像完成预处理，它们仍然需要被规范化并转换为向量（在本例中是张量），然后才能被输入到网络中。

+   在最简单的情况下，规范化意味着调整在不同尺度上测量的值到一个概念上的共同尺度，通常是在平均之前。规范化数据总是一个好主意，以防止梯度在梯度下降过程中爆炸或消失，如梯度消失和爆炸问题所示。规范化还确保没有数据冗余。

+   通过将每个图像中的每个像素除以`255`来对数据进行规范化，因为像素值的范围在 0 和`255`之间。这将导致以下截图中看到的输出：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00308.jpeg)

+   接下来，使用`numpy_utils`中的`to_categorical()`函数将图像转换为具有十个不同类的输入向量，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00309.jpeg)

# 另请参阅

以下是其他资源：

+   有关数据规范化的更多信息，请查看以下链接：

[`www.quora.com/What-is-normalization-in-machine-learning`](https://www.quora.com/What-is-normalization-in-machine-learning)

+   有关过拟合以及为什么数据被分成测试集和训练集的信息，请访问以下链接：

[`towardsdatascience.com/train-test-split-and-cross-validation-in-python-80b61beca4b6`](https://towardsdatascience.com/train-test-split-and-cross-validation-in-python-80b61beca4b6)

+   有关编码变量及其重要性的更多信息，请访问以下链接：

[`pbpython.com/categorical-encoding.html`](http://pbpython.com/categorical-encoding.html)

# 模型构建、训练和分析

我们将使用`keras`库中的标准顺序模型来构建 CNN。该网络将包括三个卷积层，两个最大池化层和四个全连接层。输入层和随后的隐藏层有 16 个神经元，而最大池化层包含(2,2)的池大小。四个全连接层包括两个密集层和一个扁平层和一个 dropout 层。使用 0.25 的 dropout 来减少过拟合问题。该算法的另一个新颖之处是使用数据增强来对抗过拟合现象。数据增强通过旋转、移位、剪切和缩放图像到不同程度来适应模型。

在输入和隐藏层中，使用`relu`函数作为激活函数，而在输出层中使用`softmax`分类器来根据预测的输出对测试图像进行分类。

# 准备工作

将构建的网络可视化如下图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00310.jpeg)

# 如何做...

步骤如下：

1.  使用以下命令在 Keras 框架中使用`Sequential()`函数定义模型：

```scala
model = Sequential()
model.add(Conv2D(16, (3, 3), input_shape=(128,150,1)))  
model.add(Activation('relu')) 
model.add(Conv2D(16, (3, 3))) 
model.add(Activation('relu'))
model.add(MaxPooling2D(pool_size=(2,2))) 
model.add(Conv2D(16,(3, 3))) 
model.add(Activation('relu'))
model.add(MaxPooling2D(pool_size=(2,2))) 
model.add(Flatten()) 

model.add(Dense(512))
model.add(Activation('relu'))
model.add(Dropout(0.25)) 
model.add(Dense(10))

model.add(Activation('softmax')) 
```

1.  打印模型的摘要以更好地了解模型的构建方式，并确保它是根据前述规格构建的。这可以通过使用`model.summary()`命令来完成。

1.  接下来，使用以下命令编译模型：

```scala
model.compile(loss='categorical_crossentropy', optimizer=Adam(), metrics=        ['accuracy'])
```

1.  为了防止过拟合并进一步提高模型的准确性，实现某种形式的数据增强。在这一步中，图像将被剪切、水平和垂直轴上移动、放大和旋转。模型学习和识别这些异常的能力将决定模型的鲁棒性。使用以下命令增强数据：

```scala
# data augmentation to minimize overfitting
gen = ImageDataGenerator(rotation_range=8, 
        width_shift_range=0.08, shear_range=0.3,
        height_shift_range=0.08,zoom_range=0.08)
test_gen = ImageDataGenerator()
train_generator = gen.flow(x_train, y_train, batch_size=16) 
test_generator = test_gen.flow(x_test, y_test, batch_size=16)
```

1.  最后，使用以下命令进行数据增强后拟合和评估模型：

```scala
model.fit_generator(train_generator, epochs=5, validation_data=test_generator)

scores = model.evaluate(x_test, y_test, verbose=0)
print("Recognition Error: %.2f%%" % (100-scores[1]*100))
```

# 工作原理...

功能如下：

1.  通过使用 sequential 函数，定义了一个九层卷积神经网络，每一层执行以下功能：

1.  第一层是一个具有 16 个神经元的卷积层，并对输入张量/矩阵进行卷积。特征图的大小被定义为一个 3 x 3 的矩阵。由于神经网络需要知道期望的输入类型，因此需要为第一层指定输入形状。由于所有图像都被裁剪为 128 x 150 像素的大小，这也将是网络第一层定义的输入形状。在这一层中使用的激活函数是**修正线性单元**（**relu**）。

1.  网络的第二层（第一个隐藏层）是另一个具有 16 个神经元的卷积层。同样，这一层的激活函数将使用`relu`。

1.  网络的第三层（第二个隐藏层）是一个具有 2 x 2 池大小的最大池化层。这一层的功能是提取通过前两层卷积学习到的所有有效特征，并减小包含所有学习到的特征的矩阵的大小。卷积无非是特征图和输入矩阵（在我们的情况下是图像）之间的矩阵乘法。网络将存储卷积过程中产生的结果值。这些存储的值中的最大值将定义输入图像中的某个特征。这些最大值将由最大池化层保留，该层将省略不相关的特征。

1.  网络的第四层（第三个隐藏层）是另一个 3 x 3 的特征图的卷积层。在这一层中使用的激活函数将再次是`relu`函数。

1.  网络的第五层（第四个隐藏层）是一个具有 2 x 2 池大小的最大池化层。

1.  网络的第六层（第五个隐藏层）是一个扁平化层，它将包含所有学习到的特征（以数字形式存储）的矩阵转换为单行，而不是多维矩阵。

1.  1.  网络中的第七层（第六个隐藏层）是一个具有 512 个神经元和`relu`激活的密集层。每个神经元基本上会处理特定的权重和偏差，这无非是对特定图像中所有学习到的特征的表示。这是为了通过在密集层上使用`softmax`分类器轻松对图像进行分类。

1.  网络中的第八层（第七个隐藏层）是一个具有 0.25 或 25%的丢弃概率的丢弃层。这一层将在训练过程中随机丢弃 25%的神经元，并通过鼓励网络使用许多替代路径来防止过拟合。

1.  网络中的最后一层是一个只有 10 个神经元和`softmax`分类器的密集层。这是第八个隐藏层，也将作为网络的输出层。

1.  在定义模型后的输出必须如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00311.jpeg)

1.  在打印`model.summary()`函数时，必须看到如下截图中的输出：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00312.jpeg)

1.  该模型使用分类交叉熵进行编译，这是一个函数，用于在将信息从一个层传输到后续层时测量和计算网络的损失。模型将使用 Keras 框架中的`Adam()`优化器函数，它基本上会指导网络在学习特征时如何优化权重和偏差。`model.compile()`函数的输出必须如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00313.jpeg)

1.  由于神经网络非常密集，总图像数量仅为 3,240，因此我们设计了一种方法来防止过拟合。这是通过执行数据增强从训练集生成更多图像来完成的。在这一步中，图像是通过`ImageDataGenerator()`函数生成的。该函数通过以下方式对训练和测试集进行图像增强：

+   旋转它们

+   剪切它们

+   移动宽度，基本上是扩大图像

+   在水平轴上移动图像

+   在垂直轴上移动图像

前述函数的输出必须如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00314.jpeg)

1.  最后，模型在训练 5 个时期后适应数据并进行评估。我们获得的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00315.jpeg)

1.  如您所见，我们获得了 98.46%的准确性，导致错误率为 1.54%。这相当不错，但是卷积网络已经进步了很多，我们可以通过调整一些超参数或使用更深的网络来改进这个错误率。

# 还有更多...

使用 12 层更深的 CNN（一个额外的卷积和一个额外的最大池化层）将准确性提高到 99.07%，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00316.jpeg)

在模型构建过程中每两层之后使用数据归一化后，我们进一步将准确性提高到 99.85%，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00317.jpeg)

您可能会得到不同的结果，但可以随意运行几次训练步骤。以下是您可以采取的一些步骤，以便在将来实验网络以更好地了解它：

+   尝试更好地调整超参数，并实施更高的丢失百分比，看看网络的响应如何。

+   当我们尝试使用不同的激活函数或更小（不太密集）的网络时，准确性大大降低。

+   此外，更改特征图和最大池化层的大小，并查看这如何影响训练时间和模型准确性。

+   尝试在不太密集的 CNN 中包含更多的神经元并进行调整以提高准确性。这也可能导致更快的网络，训练时间更短。

+   使用更多的训练数据。探索其他在线存储库，找到更大的数据库来训练网络。当训练数据的大小增加时，卷积神经网络通常表现更好。

# 另请参见

以下已发表的论文是了解卷积神经网络的更好资源。它们可以作为进一步阅读，以更多地了解卷积神经网络的各种应用：

+   [`papers.nips.cc/paper/4824-imagenet-classification-with-deep-convolutional-neural-networks`](http://papers.nips.cc/paper/4824-imagenet-classification-with-deep-convolutional-neural-networks)

+   [`arxiv.org/abs/1408.5882`](https://arxiv.org/abs/1408.5882)

+   [`www.cv-foundation.org/openaccess/content_cvpr_2014/papers/Karpathy_Large-scale_Video_Classification_2014_CVPR_paper.pdf`](https://www.cv-foundation.org/openaccess/content_cvpr_2014/papers/Karpathy_Large-scale_Video_Classification_2014_CVPR_paper.pdf)

+   [`www.cs.cmu.edu/~bhiksha/courses/deeplearning/Fall.2016/pdfs/Simard.pdf`](http://www.cs.cmu.edu/~bhiksha/courses/deeplearning/Fall.2016/pdfs/Simard.pdf)

+   [`dl.acm.org/citation.cfm?id=2807412`](https://dl.acm.org/citation.cfm?id=2807412)

+   [`ieeexplore.ieee.org/abstract/document/6165309/`](https://ieeexplore.ieee.org/abstract/document/6165309/)

+   [`openaccess.thecvf.com/content_cvpr_2014/papers/Oquab_Learning_and_Transferring_2014_CVPR_paper.pdf`](http://openaccess.thecvf.com/content_cvpr_2014/papers/Oquab_Learning_and_Transferring_2014_CVPR_paper.pdf)

+   [`www.aaai.org/ocs/index.php/IJCAI/IJCAI11/paper/download/3098/3425`](http://www.aaai.org/ocs/index.php/IJCAI/IJCAI11/paper/download/3098/3425)

+   [`ieeexplore.ieee.org/abstract/document/6288864/`](https://ieeexplore.ieee.org/abstract/document/6288864/)


# 第十一章：使用 Word2Vec 创建和可视化单词向量

在本章中，我们将涵盖以下内容：

+   获取数据

+   导入必要的库

+   准备数据

+   构建和训练模型

+   进一步可视化

+   进一步分析

# 介绍

在对文本数据进行神经网络训练并使用 LSTM 单元生成文本之前，重要的是要了解文本数据（如单词、句子、客户评论或故事）在输入神经网络之前是如何转换为单词向量的。本章将描述如何将文本转换为语料库，并从语料库生成单词向量，这样就可以使用欧几里得距离计算或余弦距离计算等技术轻松地对相似单词进行分组。

# 获取数据

第一步是获取一些要处理的数据。在本章中，我们需要大量的文本数据，将其转换为标记并进行可视化，以了解神经网络如何根据欧几里得距离和余弦距离对单词向量进行排名。这是了解不同单词如何相互关联的重要步骤。反过来，这可以用于设计更好、更高效的语言和文本处理模型。

# 准备工作

考虑以下内容：

+   模型的文本数据需要以`.txt`格式的文件存在，并且您必须确保文件放置在当前工作目录中。文本数据可以是来自 Twitter 动态、新闻动态、客户评论、计算机代码或以`.txt`格式保存在工作目录中的整本书。在我们的案例中，我们已经将《权力的游戏》书籍作为模型的输入文本。然而，任何文本都可以替换书籍，并且相同的模型也会起作用。

+   许多经典文本已不再受版权保护。这意味着您可以免费下载这些书籍的所有文本，并将它们用于实验，比如创建生成模型。获取不再受版权保护的免费书籍的最佳途径是 Project Gutenberg（[`www.gutenberg.org/`](https://www.gutenberg.org/)）。

# 操作方法...

步骤如下：

1.  首先访问 Project Gutenberg 网站并浏览您感兴趣的书籍。单击书籍，然后单击 UTF-8，这样您就可以以纯文本格式下载书籍。链接如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00318.jpeg)

Project Gutenberg 数据集下载页面

1.  点击纯文本 UTF-8 后，您应该会看到一个类似以下截图的页面。右键单击页面，然后单击“另存为...”接下来，将文件重命名为您选择的任何名称，并保存在您的工作目录中：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00319.jpeg)

1.  现在，您应该在当前工作目录中看到一个带有指定文件名的`.txt`文件。

1.  Project Gutenberg 为每本书添加了标准的页眉和页脚；这不是原始文本的一部分。在文本编辑器中打开文件，然后删除页眉和页脚。

# 工作原理...

功能如下：

1.  使用以下命令检查当前工作目录：`pwd`。

1.  可以使用`cd`命令更改工作目录，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00320.jpeg)

1.  请注意，在我们的案例中，文本文件包含在名为`USF`的文件夹中，因此这被设置为工作目录。您可以类似地将一个或多个`.txt`文件存储在工作目录中，以便作为模型的输入。

1.  UTF-8 指定了文本文件中字符的编码类型。**UTF-8**代表**Unicode 转换格式**。**8**表示它使用**8 位**块来表示一个字符。

1.  UTF-8 是一种折衷的字符编码，可以像 ASCII 一样紧凑（如果文件只是纯英文文本），但也可以包含任何 Unicode 字符（文件大小会略有增加）。

1.  不需要文本文件以 UTF-8 格式，因为我们将在稍后阶段使用 codecs 库将所有文本编码为 Latin1 编码格式。

# 还有更多...

有关 UTF-8 和 Latin1 编码格式的更多信息，请访问以下链接：

+   [`en.wikipedia.org/wiki/UTF-8`](https://en.wikipedia.org/wiki/UTF-8)

+   [`www.ic.unicamp.br/~stolfi/EXPORT/www/ISO-8859-1-Encoding.html`](http://www.ic.unicamp.br/~stolfi/EXPORT/www/ISO-8859-1-Encoding.html)

# 另请参阅

访问以下链接以更好地了解神经网络中单词向量的需求：

[`medium.com/deep-math-machine-learning-ai/chapter-9-1-nlp-word-vectors-d51bff9628c1`](https://medium.com/deep-math-machine-learning-ai/chapter-9-1-nlp-word-vectors-d51bff9628c1)

以下是与将单词转换为向量相关的一些其他有用文章：

[`monkeylearn.com/blog/word-embeddings-transform-text-numbers/`](https://monkeylearn.com/blog/word-embeddings-transform-text-numbers/)

[`towardsdatascience.com/word-to-vectors-natural-language-processing-b253dd0b0817`](https://towardsdatascience.com/word-to-vectors-natural-language-processing-b253dd0b0817)

# 导入必要的库

在开始之前，我们需要导入以下库和依赖项，这些库需要导入到我们的 Python 环境中。这些库将使我们的任务变得更加容易，因为它们具有现成的可用函数和模型，可以代替我们自己进行操作。这也使得代码更加简洁和可读。

# 做好准备

以下库和依赖项将需要创建单词向量和绘图，并在 2D 空间中可视化 n 维单词向量：

+   `未来`

+   `codecs`

+   `glob`

+   ``multiprocessing``

+   `os`

+   ``pprint``

+   `re`

+   `nltk`

+   `Word2Vec`

+   `sklearn`

+   `numpy`

+   `matplotlib`

+   `pandas`

+   `seaborn`

# 如何做...

步骤如下：

1.  在 Jupyter 笔记本中键入以下命令以导入所有所需的库： 

```scala
from __future__ import absolute_import, division, print_function
import codecs
import glob
import logging
import multiprocessing
import os
import pprint
import re
import nltk
import gensim.models.word2vec as w2v
import sklearn.manifold
import numpy
as np
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
%pylab inline
```

1.  您应该看到一个类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00321.jpeg)

1.  接下来，使用以下命令导入`stopwords`和`punkt`库：

```scala
nltk.download("punkt")
nltk.download("stopwords")
```

1.  您看到的输出必须看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00322.jpeg)

# 它是如何工作的...

本节将描述用于此配方的每个库的目的。

1.  `future`库是 Python 2 和 Python 3 之间的缺失链接。它充当两个版本之间的桥梁，并允许我们使用两个版本的语法。

1.  `codecs`库将用于对文本文件中所有单词进行编码。这构成了我们的数据集。

1.  Regex 是用于快速查找文件的库。`glob`函数允许快速高效地在大型数据库中搜索所需的文件。

1.  `multiprocessing`库允许我们执行并发，这是一种运行多个线程并使每个线程运行不同进程的方式。这是一种通过并行化使程序运行更快的方式。

1.  `os`库允许与操作系统进行简单交互，如 Mac、Windows 等，并执行诸如读取文件之类的功能。

1.  `pprint`库提供了一种能够以可用作解释器输入的形式对任意 Python 数据结构进行漂亮打印的功能。

1.  `re`模块提供了类似于 Perl 中的正则表达式匹配操作。

1.  NLTK 是一个自然语言工具包，能够在非常简短的代码中对单词进行标记。当输入整个句子时，`nltk`函数会分解句子并输出每个单词的标记。基于这些标记，单词可以被组织成不同的类别。NLTK 通过将每个单词与一个名为**词汇表**的巨大预训练单词数据库进行比较来实现这一点。

1.  `Word2Vec`是 Google 的模型，它在一个巨大的单词向量数据集上进行了训练。它将语义上相似的单词归为一类。这将是本节中最重要的库。

1.  `sklearn.manifold`允许使用**t-分布随机邻居嵌入**（**t-SNE**）技术对数据集进行降维。由于每个单词向量是多维的，我们需要某种形式的降维技术，将这些单词的维度降低到一个较低的维度空间，以便在 2D 空间中进行可视化。

# 还有更多...

`Numpy`是常用的`math`库。`Matplotlib`是我们将利用的`plotting`库，而`pandas`通过允许轻松重塑、切片、索引、子集和操纵数据，提供了很大的灵活性。

`Seaborn`库是另一个统计数据可视化库，我们需要与`matplotlib`一起使用。`Punkt`和`Stopwords`是两个数据处理库，简化了诸如将语料库中的文本拆分为标记（即通过标记化）和删除`stopwords`等任务。

# 另请参阅

有关使用的一些库的更多信息，请访问以下链接：

+   [`docs.python.org/3/library/codecs.html`](https://docs.python.org/3/library/codecs.html)

+   [`docs.python.org/2/library/pprint.html`](https://docs.python.org/2/library/pprint.html)

+   [`docs.python.org/3/library/re.html`](https://docs.python.org/3/library/re.html)

+   [`www.nltk.org/`](https://www.nltk.org/)

+   [`www.tensorflow.org/tutorials/word2vec`](https://www.tensorflow.org/tutorials/word2vec)

+   [`scikit-learn.org/stable/modules/manifold.html`](http://scikit-learn.org/stable/modules/manifold.html)

# 准备数据

在将数据馈送到模型之前，需要执行一些数据预处理步骤。本节将描述如何清理数据并准备数据，以便将其馈送到模型中。

# 准备就绪

首先将所有`.txt`文件中的文本转换为一个大的语料库。这是通过从每个文件中读取每个句子并将其添加到一个空语料库中来完成的。然后执行一些预处理步骤，以删除诸如空格、拼写错误、`stopwords`等不规则性。然后必须对清理后的文本数据进行标记化，并通过循环将标记化的句子添加到一个空数组中。

# 如何做...

步骤如下：

1.  键入以下命令以在工作目录中搜索`.txt`文件并打印找到的文件的名称：

```scala
book_names = sorted(glob.glob("./*.txt"))
print("Found books:")
book_names
```

在我们的案例中，工作目录中保存了五本名为`got1`、`got2`、`got3`、`got4`和`got5`的书籍。

1.  创建一个`corpus`，读取每个句子，从第一个文件开始，对其进行编码，并使用以下命令将编码字符添加到`corpus`中：

```scala
corpus = u''
for book_name in book_names:
print("Reading '{0}'...".format(book_name))
with codecs.open(book_name,"r","Latin1") as book_file:
corpus += book_file.read()
print("Corpus is now {0} characters long".format(len(corpus)))
print()
```

1.  执行前面步骤中的代码，应该会产生以下截图中的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00323.jpeg)

1.  使用以下命令从`punkt`加载英语 pickle`tokenizer`：

```scala
tokenizer = nltk.data.load('tokenizers/punkt/english.pickle')
```

1.  使用以下命令将整个`corpus`标记化为句子：

```scala
raw_sentences = tokenizer.tokenize(corpus)
```

1.  以以下方式定义将句子拆分为其组成单词并删除不必要字符的函数：

```scala
def sentence_to_wordlist(raw):
     clean = re.sub("[^a-zA-Z]"," ", raw)
     words = clean.split()
     return words
```

1.  将每个句子的每个单词标记化的原始句子全部添加到一个新的句子数组中。使用以下代码完成：

```scala
sentences = []
for raw_sentence in raw_sentences:
  if len(raw_sentence) > 0:
  sentences.append(sentence_to_wordlist(raw_sentence))
```

1.  从语料库中打印一个随机句子，以直观地查看`tokenizer`如何拆分句子并从结果创建一个单词列表。使用以下命令完成：

```scala
print(raw_sentences[50])
print(sentence_to_wordlist(raw_sentences[50]))
```

1.  使用以下命令计算数据集中的总标记数：

```scala
token_count = sum([len(sentence) for sentence in sentences])
print("The book corpus contains {0:,} tokens".format(token_count))
```

# 工作原理...

执行分词器并对语料库中的所有句子进行分词应该会产生以下截图中的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00324.jpeg)

接下来，删除不必要的字符，如连字符和特殊字符，是以以下方式完成的。使用用户定义的`sentence_to_wordlist()`函数拆分所有句子会产生以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00325.jpeg)

将原始句子添加到名为`sentences[]`的新数组中，将产生如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00326.jpeg)

在打印语料库中的总标记数时，我们注意到整个语料库中有 1,110,288 个标记。这在以下截图中有所说明：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00327.jpeg)

功能如下：

1.  使用 NLTK 中的预训练`tokenizer`通过将每个句子计为一个标记来标记整个语料库。每个标记化的句子都被添加到变量`raw_sentences`中，该变量存储了标记化的句子。

1.  接下来，常见的停用词被移除，并且通过将每个句子分割成单词来清理文本。

1.  打印一个随机句子以及其单词列表，以了解其工作原理。在我们的案例中，我们选择打印`raw_sentences`数组中的第 50 个句子。

1.  计算并打印句子数组中的总标记数（在我们的案例中是句子）。在我们的案例中，我们看到`tokenizer`创建了 1,110,288 个标记。

# 还有...

有关将段落和句子标记化的更多信息，请访问以下链接：

+   [`textminingonline.com/dive-into-nltk-part-ii-sentence-tokenize-and-word-tokenize`](https://textminingonline.com/dive-into-nltk-part-ii-sentence-tokenize-and-word-tokenize)

+   [`stackoverflow.com/questions/37605710/tokenize-a-paragraph-into-sentence-and-then-into-words-in-nltk`](https://stackoverflow.com/questions/37605710/tokenize-a-paragraph-into-sentence-and-then-into-words-in-nltk)

+   [`pythonspot.com/tokenizing-words-and-sentences-with-nltk/`](https://pythonspot.com/tokenizing-words-and-sentences-with-nltk/)

# 另请参阅

有关正则表达式工作原理的更多信息，请访问以下链接：

[`stackoverflow.com/questions/13090806/clean-line-of-punctuation-and-split-into-words-python`](https://stackoverflow.com/questions/13090806/clean-line-of-punctuation-and-split-into-words-python)

# 构建和训练模型

一旦我们将文本数据以数组形式的标记输入到模型中，我们就能够为模型定义一些超参数。本节将描述如何执行以下操作：

+   声明模型超参数

+   使用`Word2Vec`构建模型

+   在准备好的数据集上训练模型

+   保存和检查点训练好的模型

# 准备工作

需要声明的一些模型超参数包括以下内容：

+   生成的单词向量的维度

+   最小词数阈值

+   在训练模型时运行的并行线程数

+   上下文窗口长度

+   降采样（对于频繁出现的单词）

+   设置种子

一旦前面提到的超参数被声明，就可以使用`Gensim`库中的`Word2Vec`函数构建模型。

# 如何做...

步骤如下：

1.  使用以下命令声明模型的超参数：

```scala
num_features = 300
min_word_count = 3
num_workers = multiprocessing.cpu_count()
context_size = 7
downsampling = 1e-3
seed = 1
```

1.  使用声明的超参数，使用以下代码行构建模型：

```scala
got2vec = w2v.Word2Vec(
    sg=1,
    seed=seed,
    workers=num_workers,
    size=num_features,
    min_count=min_word_count,
    window=context_size,
    sample=downsampling
)
```

1.  使用标记化的句子构建模型的词汇表，并通过所有标记进行迭代。这是使用以下方式的`build_vocab`函数完成的：

```scala
got2vec.build_vocab(sentences,progress_per=10000, keep_raw_vocab=False, trim_rule=None)
```

1.  使用以下命令训练模型：

```scala
got2vec.train(sentences, total_examples=got2vec.corpus_count, total_words=None, epochs=got2vec.iter, start_alpha=None, end_alpha=None, word_count=0, queue_factor=2, report_delay=1.0, compute_loss=False)
```

1.  如果尚不存在，请创建一个名为 trained 的目录。使用以下命令保存和检查点`trained`模型：

```scala
if not os.path.exists("trained"):
     os.makedirs("trained")
got2vec.wv.save(os.path.join("trained", "got2vec.w2v"), ignore=[])
```

1.  要在任何时候加载保存的模型，请使用以下命令：

```scala
got2vec = w2v.KeyedVectors.load(os.path.join("trained", "got2vec.w2v"))
```

# 它是如何工作的...

功能如下：

1.  模型参数的声明不会产生任何输出。它只是在内存中留出空间来存储变量作为模型参数。以下截图描述了这个过程：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00328.jpeg)

1.  模型是使用前述超参数构建的。在我们的案例中，我们将模型命名为`got2vec`，但模型可以根据您的喜好进行命名。模型定义如下截图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00329.jpeg)

1.  在模型上运行`build_vocab`命令应该会产生如下截图所示的输出：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00330.jpeg)

1.  通过定义以下截图中所见的参数来训练模型：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00331.jpeg)

1.  上述命令产生如下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00332.jpeg)

1.  保存、检查点和加载模型的命令产生如下输出，如截图所示：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00333.jpeg)

# 还有更多...

考虑以下内容：

+   在我们的案例中，我们注意到`build_vocab`函数从 1,110,288 个单词的列表中识别出 23,960 个不同的单词类型。然而，对于不同的文本语料库，这个数字会有所不同。

+   每个单词都由一个 300 维向量表示，因为我们已经声明维度为 300。增加这个数字会增加模型的训练时间，但也会确保模型很容易地泛化到新数据。

+   发现 1e![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00334.jpeg)3 的下采样率是一个很好的比率。这是为了让模型知道何时对频繁出现的单词进行下采样，因为它们在分析时并不重要。这些单词的例子包括 this, that, those, them 等。

+   设置一个种子以使结果可重现。设置种子也使得调试变得更容易。

+   由于模型不是很复杂，使用常规 CPU 计算训练模型大约需要 30 秒。

+   当检查点被检查时，模型被保存在工作目录内的`trained`文件夹下。

# 另请参阅

有关`Word2Vec`模型和 Gensim 库的更多信息，请访问以下链接：[`radimrehurek.com/gensim/models/word2vec.html`](https://radimrehurek.com/gensim/models/word2vec.html)

[`radimrehurek.com/gensim/models/word2vec.html`](https://radimrehurek.com/gensim/models/word2vec.html)

# 进一步可视化

本节将描述如何压缩所有训练过的单词的维度，并将其全部放入一个巨大的矩阵以进行可视化。由于每个单词都是一个 300 维的向量，所以需要将其降低到更低的维度，以便我们在 2D 空间中进行可视化。

# 准备工作

一旦模型在训练后保存和检查点后，开始将其加载到内存中，就像在上一节中所做的那样。在本节中将使用的库和模块有：

+   `tSNE`

+   `pandas`

+   `Seaborn`

+   `numpy`

# 如何做...

步骤如下：

1.  使用以下命令压缩 300 维单词向量的维度：

```scala
 tsne = sklearn.manifold.TSNE(n_components=2, random_state=0)
```

1.  将所有单词向量放入一个巨大的矩阵（命名为`all_word_vectors_matrix`），并使用以下命令查看它：

```scala
 all_word_vectors_matrix = got2vec.wv.syn0
 print (all_word_vectors_matrix)
```

1.  使用以下命令将所有学习到的表示拟合到二维空间中：

```scala
 all_word_vectors_matrix_2d =  tsne.fit_transform(all_word_vectors_matrix)
```

1.  使用以下代码收集所有单词向量及其相关单词：

```scala
 points = pd.DataFrame(
     [
            (word, coords[0], coords[1])
             for word, coords in [
              (word, all_word_vectors_matrix_2d[got2vec.vocab[word].index])
                for word in got2vec.vocab
         ]
    ],
    columns=["word", "x", "y"]
)
```

1.  使用以下命令可以获取前十个点的`X`和`Y`坐标以及相关单词：

```scala
points.head(10)
```

1.  使用以下命令绘制所有点：

```scala
sns.set_context("poster")
points.plot.scatter("x", "y", s=10, figsize=(15, 15))
```

1.  可以放大绘图图表的选定区域以进行更仔细的检查。通过使用以下函数对原始数据进行切片来实现这一点：

```scala
def plot_region(x_bounds, y_bounds):
    slice = points[
        (x_bounds[0] <= points.x) &
        (points.x <= x_bounds[1]) &
        (y_bounds[0] <= points.y) &
        (points.y <= y_bounds[1])
        ]
    ax = slice.plot.scatter("x", "y", s=35, figsize=(10, 8))
        for i, point in slice.iterrows():
            ax.text(point.x + 0.005, point.y + 0.005, point.word,                                                  fontsize=11)
```

1.  使用以下命令绘制切片数据。切片数据可以被视为原始所有数据点的放大区域：

```scala
plot_region(x_bounds=(20.0, 25.0), y_bounds=(15.5, 20.0))
```

# 工作原理...

功能如下：

1.  t-SNE 算法是一种非线性降维技术。计算机在计算过程中很容易解释和处理许多维度。然而，人类一次只能可视化两到三个维度。因此，当试图从数据中得出见解时，这些降维技术非常有用。

1.  将 300 维向量应用 t-SNE 后，我们能够将其压缩为只有两个维度来绘制和查看。

1.  通过将 `n_components` 指定为 2，我们让算法知道它必须将数据压缩到二维空间。完成此操作后，我们将所有压缩后的向量添加到一个名为 `all_word_vectors_matrix` 的巨大矩阵中，如下图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00335.jpeg)

1.  t-SNE 算法需要对所有这些单词向量进行训练。在常规 CPU 上，训练大约需要五分钟。

1.  一旦 t-SNE 完成对所有单词向量的训练，它会为每个单词输出 2D 向量。可以通过将它们全部转换为数据框架来将这些向量绘制为点。如下图所示完成此操作：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00336.jpeg)

1.  我们看到上述代码生成了许多点，其中每个点代表一个单词及其 X 和 Y 坐标。检查数据框架的前二十个点时，我们看到如下图所示的输出：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00337.jpeg)

1.  通过使用 `all_word_vectors_2D` 变量绘制所有点，您应该会看到类似以下截图的输出：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00338.jpeg)

1.  上述命令将生成从整个文本生成的所有标记或单词的绘图，如下图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00339.jpeg)

1.  我们可以使用 `plot_region` 函数来放大绘图中的某个区域，以便我们能够实际看到单词及其坐标。这一步骤如下图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00340.jpeg)

1.  通过设置 `x_bounds` 和 `y_bounds` 的值，可以可视化绘图的放大区域，如下图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00341.jpeg)

1.  可以通过改变 `x_bounds` 和 `y_bounds` 的值来可视化相同绘图的不同区域，如下两个截图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00342.jpeg)

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00343.jpeg)

# 另请参阅

还有以下额外的要点：

+   有关 t-SNE 算法工作原理的更多信息，请访问以下链接：

+   [`www.oreilly.com/learning/an-illustrated-introduction-to-the-t-sne-algorithm`](https://www.oreilly.com/learning/an-illustrated-introduction-to-the-t-sne-algorithm)

+   有关余弦距离相似性和排名的更多信息，请访问以下链接：

[`code.google.com/archive/p/word2vec/`](https://code.google.com/archive/p/word2vec/)

+   使用以下链接来探索 `Seaborn` 库的不同功能：

[`seaborn.pydata.org/`](https://seaborn.pydata.org/)

# 进一步分析

本节将描述可在可视化后对数据执行的进一步分析。例如，探索不同单词向量之间的余弦距离相似性。

# 准备工作

以下链接是关于余弦距离相似性工作原理的出色博客，并讨论了一些涉及的数学内容：

[`blog.christianperone.com/2013/09/machine-learning-cosine-similarity-for-vector-space-models-part-iii/`](http://blog.christianperone.com/2013/09/machine-learning-cosine-similarity-for-vector-space-models-part-iii/)

# 如何做...

考虑以下内容：

+   可以使用 `Word2Vec` 的不同功能执行各种自然语言处理任务。其中之一是在给定某个单词时找到最语义相似的单词（即具有高余弦相似性或它们之间的欧几里德距离较短的单词向量）。可以使用 `Word2Vec` 的 `most_similar` 函数来执行此操作，如下图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00344.jpeg)此截图显示了与单词 `Lannister` 相关的所有最接近的单词：

![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00345.jpeg)此截图显示了与单词 `Jon` 相关的所有单词的列表：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00346.jpeg)

# 工作原理...

考虑以下内容：

+   有各种方法来衡量单词之间的语义相似性。我们在本节中使用的方法是基于余弦相似性的。我们还可以通过以下代码来探索单词之间的线性关系：

```scala
 def nearest_similarity_cosmul(start1, end1, end2):
    similarities = got2vec.most_similar_cosmul(
        positive=[end2, start1],
        negative=[end1]
)
start2 = similarities[0][0]
print("{start1} is related to {end1}, as {start2} is related to         {end2}".format(**locals()))
return start2
```

+   要找到给定一组词的最近词的余弦相似度，请使用以下命令：

```scala
nearest_similarity_cosmul("Stark", "Winterfell", "Riverrun")
nearest_similarity_cosmul("Jaime", "sword", "wine")
nearest_similarity_cosmul("Arya", "Nymeria", "dragons")
```

+   上述过程如下截图所示：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00347.jpeg)

+   结果如下：![](https://github.com/OpenDocCN/freelearn-bigdata-zh/raw/master/docs/spark-dl-cb/img/00348.jpeg)

+   如本节所示，词向量是所有自然语言处理任务的基础。在深入研究更复杂的自然语言处理模型（如循环神经网络和长短期记忆（LSTM）单元）之前，了解它们以及构建这些模型所涉及的数学是很重要的。

# 另请参阅

可以进一步阅读有关使用余弦距离相似性、聚类和其他机器学习技术在排名词向量中的应用的内容，以更好地理解。以下是一些有用的关于这个主题的已发表论文的链接：

+   [`s3.amazonaws.com/academia.edu.documents/32952068/pg049_Similarity_Measures_for_Text_Document_Clustering.pdf?AWSAccessKeyId=AKIAIWOWYYGZ2Y53UL3A&Expires=1530163881&Signature=YG6YjvJb2z0JjmfHzaYujA2ioIo%3D&response-content-disposition=inline%3B%20filename%3DSimilarity_Measures_for_Text_Document_Cl.pdf`](https://s3.amazonaws.com/academia.edu.documents/32952068/pg049_Similarity_Measures_for_Text_Document_Clustering.pdf?AWSAccessKeyId=AKIAIWOWYYGZ2Y53UL3A&Expires=1530163881&Signature=YG6YjvJb2z0JjmfHzaYujA2ioIo%3D&response-content-disposition=inline%3B%20filename%3DSimilarity_Measures_for_Text_Document_Cl.pdf)

+   [`csis.pace.edu/ctappert/dps/d861-12/session4-p2.pdf`](http://csis.pace.edu/ctappert/dps/d861-12/session4-p2.pdf)
