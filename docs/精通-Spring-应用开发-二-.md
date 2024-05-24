# 精通 Spring 应用开发（二）

> 原文：[`zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C`](https://zh.annas-archive.org/md5/A95A09924E8304BAE696F70C7C92A54C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Spring Batch 的作业

企业应用程序通常需要通过应用复杂的业务规则来处理大量信息。一些应用程序需要自动运行作业并提供大量数据作为进一步处理的输入。这些功能总是基于时间的作业，不需要任何用户干预。批处理广泛应用于银行和保险领域，在那里大量数据在预定时间进行处理。一个**作业**是一个过程，而**批处理作业**意味着一组进程，它们在预定时间运行以执行任务。

# Spring Batch 简介

Spring Batch 本身是一个用于开发批处理作业的批处理框架。它支持批处理优化和作业分区，并且具有高度可扩展性，这促使我们在批处理应用程序的开发中考虑它。

## 使用 Spring Batch 的用例

让我们列举一些可以在应用程序中使用 Spring 批处理的用例：

+   在预定时间向用户发送批量邮件

+   从队列中读取消息

+   在给定时间更新交易

+   在给定时间处理用户接收到的所有文件

## 批处理处理的目标

批处理的主要目标是按顺序完成以下一系列步骤以完成批处理作业：

1.  查找作业。

1.  识别输入。

1.  调度作业。

1.  启动作业。

1.  处理作业。

1.  转到第 2 步（获取新输入）。

# 批处理作业的架构

让我们描述一下批处理处理器的基本架构；我们还可以看到批处理处理中涉及的组件。从下图中，您可以找出 Spring Batch 的主要组件：

![批处理作业的架构](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr-app-dev/img/7320OS_04_01.jpg)

现在让我们逐个查看组件。

+   `JobRepository`：这个容器是我们需要注册作业或进程的地方。

+   `JobOperator`：这是触发已注册作业的对象。它还提供了访问注册的 API。这是一个接口。

+   `Job`：它是`jobRepository`中的一个进程或任务。这包括一个以上的步骤。

+   `Step`：实际上包含需要执行的逻辑。每个步骤包括一个`ItemReader`，`ItemProcessor`和`ItemWriter`接口。首先，`ItemReader`接口一次读取一个步骤的作业并将其传递给`ItemProcessor`进行处理。例如，它可能收集一些所需的数据。然后，`ItemWriter`接口将数据写入数据库，或者执行事务或记录消息。有两种类型的步骤：

+   `ChunkStyle`：`ChunkStyle`步骤具有一个`ItemReader`，一个`ItemProcessor`和一个`ItemWriter`。

+   `BatchLet`：在 Spring 中，`BatchLet`被称为`TaskLetStep`。`BatchLet`是一个自定义步骤，可用于发送批量邮件或短信。

现在我们知道了批处理的基础知识，在下一节中我们将看到如何实现或使用批处理。

## 使用企业批处理

我们有以下两种实现批处理的选项：

+   使用 JVM 并为每个作业运行启动 JVM

+   在 J2EE 容器中部署批处理作业管理应用程序

JSR-352 是可用于实现批处理的标准规范。Spring 框架在很大程度上支持这个规范。大多数 JEE 容器，如**Glassfish**，**Jboss- JMX**和 Web Sphere 都支持 JSR-352 规范。作为开发人员，我们可以选择 Spring 框架并在 J2EE 容器上部署批处理。

您还可以使用 restful API 将数据池化到批处理应用程序中并从中取出。在下一节中，让我们使用 Spring Batch 框架创建一个作业。我们首先来看一下依赖关系。

# Spring Batch 的依赖项

要开始使用 Spring Batch，我们需要查看依赖关系。假设用户熟悉 Maven 应用程序，我们可以查看需要添加到`pom.xml`文件中以使用 Spring Batch 的以下依赖项：

```java
<dependency>
  <groupId>org.springframework.batch</groupId>
  <artifactId>spring-batch-core</artifactId>
  <version>3.0.0.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-core</artifactId>
  <version>${spring.version}</version>
</dependency>

<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-context</artifactId>
  <version>${spring.version}</version>
</dependency>
```

## Spring Batch 的关键组件

你可以看到，Spring Batch 的关键组件与 Java 中的批处理的 JSR 规范非常相似。

+   `JobRepository`：这又是一个作业的存储库。但是，在 Spring Batch 框架中，核心 API 有`JobRepository`。它为`JobLauncher`、`JobReader`、`ItemProcessor`和`ItemWriter`提供`create`、`update`、`read`和`delete`方法。在 Spring 框架中负责`JobRepository`的类是`SimpleJobRepository`。有两种存储作业的方式：一种是在数据库中，另一种是在内存中（这将不得不使用`HashMaps`）。

`SimpleJobRepositoryConstructor`看起来像这样：

```java
public SimpleJobRepository(JobInstanceDao jobInstanceDao,
  JobExecutionDao jobExecutionDao,
  StepExecutionDao stepExecutionDao,
  ExecutionContextDao ecDao) 
```

+   `JobLauncher`：`JobLauncher`只是一个用于启动作业的简单接口。作业在`jobRepository`中注册。

```java
public interface JobLauncher {
  public JobExecution run(Job job, JobParameters jobParameters)
  throws JobExecutionAlreadyRunningException, JobRestartException;
}
```

`SimpleJobLauncher`类实现了`JobLauncher`接口。这个类有一个`setJobRepository`方法。

```java
public void setJobRepository(JobRepository jobRepository)
```

+   `ItemReader`：它是`org.springframework.batch.item`包中的一个接口。ItemReader 用于提供数据。数据可以来自数据库、XML 或平面文件。

实现类预计是有状态的，并且将在每个批次中被多次调用，每次调用`read()`都会返回一个不同的值，最终在所有输入数据耗尽时返回 null。实现类不需要是线程安全的，`ItemReader`接口的客户端需要意识到这一点。

```java
public interface ItemReader<T> {
  T read() throws Exception, UnexpectedInputException, ParseException;
}
```

+   `ItemProcessor`：这是一个用于处理数据并进行中间处理的接口。在交给`ItemWriter`之前，`ItemProcessor`可以用于实现某些业务逻辑。

```java
public interface ItemProcessor<I, O> {
  O process(I item) throws Exception;
}
public class ProductBean {}

public class RelatedProductsBean {
  public RelatedProductsBean(ProductBean productBean) {}
}
public class ProductBeanProcessor implements ItemProcessor<ProductBean, RelatedProductsBean >{
  public RelatedProductsBean process(ProductBean productBean) throws Exception {
    //Perform simple transformation, convert a ProductBean to a RelatedProductsBean
    return new RelatedProductsBean(productBean);
  }
}
public class ProductBeanWriter implements ItemWriter<ProductBean>{
  public void write(List<? extends ProductBean> productBeans) throws Exception {
    //write productBeans
  }
}
```

假设`ItemReader`接口提供了一个类型为`ProductBean`的类，这个类需要在写出之前转换为类型`RelatedProductsBean`。可以编写一个`ItemProcessor`来执行转换。在这个非常简单的例子中，有一个`ProductBean`类，一个`RelatedProductsBean`类，以及一个符合`ItemProcessor`接口的`ProductBeanProcessor`类。转换很简单，但任何类型的转换都可以在这里完成。`RelatedProductsBean`写入程序将用于写出`RelatedProductsBean`对象，如果提供了任何其他类型的对象，则会抛出异常。同样，如果提供的不是`ProductBean`，`ProductBeanProcessor`也会抛出异常。

`ProductBeanProcessor`然后可以被注入到一个步骤中：

```java
<job id="ioSampleJob">
  <step name="step1">
  <tasklet>
  <chunk reader="ProductReader" processor="ProductProcessor" writer="RelatedProductsWriter" commit-interval="2"/>
  </tasklet>
  </step>
</job>
```

+   `Item Writer`：这是一个接口，这里是它经常使用的实现类。

`write`方法定义了`ItemWriter`接口的最基本契约。只要它是打开的，它将尝试写出传入的项目列表。由于预期项目将被批处理到一起形成一个块，然后给出输出，接口接受项目列表而不是单独的项目。一旦项目被写出，可以在从`write`方法返回之前执行任何必要的刷新。例如，如果写入到 Hibernate DAO，可以进行多次对`write`的调用，每次对应一个项目。

然后写入程序可以在返回之前关闭 hibernate 会话。

这是`ItemWriter`的一个经常使用的实现：

+   `FlatFileItemWriter`：这将数据写入文件或流。它使用缓冲写入程序来提高性能。

```java
StaxEventItemWriter: This is an implementation of ItemWriter that uses StAX and Marshaller for serializing objects to XML.
```

# 开发一个样本批处理应用

现在我们已经介绍了批处理的基础知识和 Spring Batch 的组件，让我们开发一个简单的例子，在这个例子中，以`$$`开头的名称被识别为非素食食品，以`##`开头的名称被识别为素食食品。不以这两个字符开头的名称需要被忽略。我们的作业必须生成一个 HTML 字符串，对于非素食食谱使用红色字体颜色，对于素食食谱使用绿色字体颜色。

您需要创建一个名为`recipeMarker`的 Maven 项目，并添加先前提到的依赖项。还要添加所有 Spring Framework 核心依赖项。我们将在`context.xml`文件上工作。我们需要配置作业存储库和作业启动器。

看看`applicationContext.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-2.5.xsd
  http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context-2.5.xsd">
  <bean id="transactionManager" class="org.springframework.batch.support.transaction.ResourcelessTransactionManager"/>
  <bean id="jobLauncher" class="org.springframework.batch.core.launch.support.SimpleJobLauncher">
    <property name="jobRepository" ref="jobRepository"/>
  </bean>
  <bean id="jobRepository" class="org.springframework.batch.core.repository.support.MapJobRepositoryFactoryBean">
    <property name="transactionManager" ref="transactionManager"/>
  </bean>
  <bean id="simpleJob" class="org.springframework.batch.core.job.SimpleJob" abstract="true">
    <property name="jobRepository" ref="jobRepository" />
  </bean>
</beans>
```

您可以看到我们使用`MapJobRepositoryFactoryBean`来创建作业存储库。它是一个`FactoryBean`，可以使用非持久性的内存中的**数据访问对象**（**DAO**）实现自动创建`SimpleJobRepository`。该存储库实际上仅用于测试和快速原型设计。在这种设置中，您可能会发现`ResourcelessTransactionManager`很有用（只要您的业务逻辑不使用关系数据库）。它不适用于具有拆分的多线程作业，尽管在多线程步骤中使用应该是安全的。

接下来，我们将使用`ItemReader`和`ItemWriter`接口创建实现类。

1.  以下是`ItemReader`实现类。它在重写的`read()`方法中读取数据，该方法返回一个对象。

```java
package com.packt.batchjob;
import java.util.List;
import org.springframework.batch.item.ItemReader;
import org.springframework.batch.item.ParseException;
import org.springframework.batch.item.UnexpectedInputException;
public class CustomItemReader implements ItemReader {
  private int index = 0;
  private List<String> itemList;
  public Object read() throws Exception, UnexpectedInputException,
    ParseException {
    if (index < itemList.size()) {
      String str = itemList.get(index++);
      System.out.println("Read[ " + index + " ] = " + str);
      return str;
    } else {return null;}
  }
  public List<String> getItemList() {
    return itemList;
  }
  public void setItemList(List<String> itemList) {
    this.itemList = itemList;}
}
```

1.  在这里我们有`ItemProcessor`。它应用了将食谱列表标记为红色和绿色的逻辑。

```java
package com.packt.batchjob;
import org.springframework.batch.item.ItemProcessor;
public class CustomItemProcessor implements ItemProcessor {
  public Object process(Object arg0) throws Exception {
    String input = (String) arg0;
    if (input.contains("$$")) {
      input = input.substring(3, input.length());
      input = "<font colour="red">(.Non-Veg)</font> " + input;
    } else if (input.contains("##")) {
    input = input.substring(3, input.length());
    input = "<font colour="green">(.Veg)</font> " + input;
    } else
    return null;
    System.out.println("Process : " + input);
    return input;
  }
}
```

1.  最后，让我们编写实现类，从`ItemProcessor`中读取修改后的数据并写入。

```java
import java.util.List;
import org.springframework.batch.item.ItemWriter;
public class CustomItemWriter implements ItemWriter {
  public void write(List arg0) throws Exception {
    System.out.println("Write   : " + arg0 + "\n");
  }
}
```

在下一步中，我们将`ItemReader`，`ItemProcessor`和`ItemWriter`组合成一个作业。

让我们创建一个`itemreaderprocessorwriter.xml`文件。我们将在 XML 文件中传递食谱列表。我们已经包含了`applicationContext.xml`文件。已定义提交间隔，以表示写入两个元素后写入器应该提交。您还可以观察到步骤包括`reader`，`writer`和`jobRepository`。

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans
  http://www.springframework.org/schema/beans/spring-beans-2.5.xsd
  http://www.springframework.org/schema/context
  http://www.springframework.org/schema/context/spring-context-2.5.xsd">
  <import resource="applicationContext.xml"/>
  <bean id="customReader" class="com.packt.batchjob.CustomItemReader" >
    <property name="itemList" >
    <list>
    <value>$$Chicken65</value>
    <value>$$ChickenTikkaMasala</value>
    <value>$$GingerChicken</value>
    <value>$$GarlicChicken</value>
    <value>##Dal Makani</value>
    <value>##Stuffed Capsicum</value>
    <value>##Bendi Fry</value>
    <value>##Alo Bartha</value>
    </list>
    </property>
  </bean>
  <bean id="customProcessor" class="com.packt.batchjob.CustomItemProcessor" />
  <bean id="customWriter" class="com.packt.batchjob.CustomItemWriter" />    
  <bean id="simpleStep" class="org.springframework.batch.core.step.item.SimpleStepFactoryBean">
    <property name="transactionManager" ref="transactionManager" />
    <property name="jobRepository" ref="jobRepository" />
    <property name="itemReader" ref="customReader"/>
    <property name="itemProcessor" ref="customProcessor"/>
    <property name="itemWriter" ref="customWriter"/>
    <property name="commitInterval" value="2" />
  </bean>
  <bean id="readerWriterJob" parent="simpleJob">
    <property name="steps">
    <list>
    <ref bean="simpleStep"/>
    </list>
    </property>
  </bean>
</beans>
```

下一步是使用 Spring Batch 框架提供的命令行界面启动作业。

```java
D:\SpringBatch\receipeMarker>java -classpath "lib\*;src"
org.springframework.batch.core.launch.support.CommandLineJobRunner
  itemReaderWriter.xml readerWriterJob
```

让我们创建一个名为`itemreaderprocessorwriter.xml`的文件。我们将在 XML 文件中传递食谱列表。我们已经包含了`applicationContext.xml`文件。已定义提交间隔，以表示写入两个元素后写入器应该提交。您还可以观察到步骤包括`reader`，`writer`和`jobRepository`。

```java
OUTPUT:
Read[ 1 ] = $$Chicken65
Read[ 2 ] = $$ChickenTikkaMasala
Process : "<font colour="red">(.Non-Veg)</font> $$Chicken65
Process : "<font colour="red">(.Non-Veg)</font>$$ChickenTikkaMasala
Write   : [<font colour="red">(.Non-Veg)</font>$$Chicken65 , <font colour="red">(.Non-Veg)</font> $$ChickenTikkaMasala
Read[ 3 ] = $$GingerChicken
Read[ 4 ] = $$GarlicChicken
Process : "<font colour="red">(.Non-Veg)</font> $$GingerChicken
Process : "<font colour="red">(.Non-Veg)</font>$$GarlicChicken
Write   : [<font colour="red">(.Non-Veg)</font>$$GingerChicken , <font colour="red">(.Non-Veg)</font> $$GarlicChicken
Read[ 5 ] = ##Dal Makani
Read[ 6 ] = ##Stuffed Capsicum
Process : "<font colour="green">(. Veg)</font> ##Dal Makani
Process : "<font colour=" green ">(.Non-Veg)</font>##Stuffed Capsicum
Write   : [<font colour=" green ">(.Veg)</font>##Dal Makani , <font colour=" green ">(. Veg)</font> ##Stuffed Capsicum
Read[ 7 ] = ##Bendi Fry
Read[ 8 ] = ##Alo Bartha
Process : "<font colour=" green ">(. Veg)</font> ##Bendi Fry
Process : "<font colour=" green ">(. Veg)</font>##Alo Bartha
Write   : <font colour=" green ">(. Veg)</font>##Bendi Fry , <font colour="red">(.Non-Veg)</font> ##Alo Bartha
```

## 使用 Tasklet 接口创建示例批处理应用程序

让我们创建另一个在命令行上运行的批处理应用程序。该批处理应用程序打印消息。我们已经在本章开头讨论了 Tasklet。作业由步骤组成，步骤可以是两种类型之一：块样式步骤和 Tasklet。

在本示例中，我们使用`Tasklet`接口。在 Spring Batch 中，`Tasklet`是一个接口，用于执行单个任务，例如在步骤执行之前或之后清理或设置资源。该接口带有一个名为`executeStatus`的方法，应该由实现它的类重写。

```java
RepeatStatus execute(StepContribution contribution,
                     ChunkContext chunkContext)
              throws java.lang.Exception
RepeatStatus: CONTINUABLE and FINISHED
```

在以下示例中，`TaskLetImpl`实现了`Tasklet`接口。我们还在配置文件中使用了`TaskLetStep`类来配置`JobRepository`。公共类`TaskletStep`扩展了`AbstractStep`。

`TaskletStep`是执行步骤的`Tasklet`的简单实现，可能是重复的，并且每次调用都被事务包围。因此，结构是一个循环，循环内有事务边界。循环由步骤操作（`setStepOperations(RepeatOperations)`）控制。

客户端可以在步骤操作中使用拦截器来拦截或监听步骤范围的迭代，例如在步骤完成时获取回调。那些希望在单个任务级别获得回调的人可以为块操作指定拦截器。

让我们通过以下图表了解流程：

![使用 Tasklet 接口创建示例批处理应用程序

让我们创建一个名为`Chapter4-SpringBatchCommandLine`的简单 Java 批处理应用程序项目

1.  为`Chapter4-SpringBatchCommandLine`创建一个 Maven 文件夹结构，如下所示：

+   `src`/`main`/`java`

+   `src`/`main`/`resources`

+   `src`/`pom.xml`

1.  创建一个名为`com.packt.example`的包。

1.  创建一个名为`TaskletImpl`的类。这个类实现了`Tasklet`接口并重写了`execute()`方法。

```java
import org.springframework.batch.core.step.tasklet.Tasklet;
import org.springframework.batch.repeat.ExitStatus;
public class TaskletImpl implements Tasklet{
  private String message;
  public void setMessage(String message) {
    this.message = message;
  }
  public ExitStatus execute() throws Exception {
    System.out.print(message);
    return ExitStatus.FINISHED;
  }
}
```

1.  配置`simpleJob.xml`文件。

1.  将此文件放入`resources`文件夹中。

1.  您可以看到我们创建了`TaskletImpl`类的三个实例：`object1`，`object2`和`object3`。

1.  在每个实例中，我们设置了消息属性。我们将对象实例传递给`TaskletStep`。

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans
  http://www.springframework.org/schema/beans/spring-beans-4.0.xsd">
  <import resource="applicationContext.xml"/>

  <bean id="object1" class="com.packt.example.TaskletImpl">
    <property name="message" value="Dad not well"/>
  </bean>

  <bean id="object2" class="com.packt.example.TaskletImpl">
    <property name="message" value="Call the doctor"/>
  </bean>

  <bean id="object3" class="com.packt.example.TaskletImpl">
    <property name="message" value="He is sweating"/>
  </bean>

  <bean id="taskletStep" abstract="true" class="org.springframework.batch.core.step.tasklet.TaskletStep">
    <property name="jobRepository" ref="jobRepository"/>
  </bean>

  <bean id="simpleJob" class="org.springframework.batch.core.job.SimpleJob">
    <property name="name" value="simpleJob" />
    <property name="steps">
    <list>
    <bean parent="taskletStep">
    <property name="tasklet" ref="object1"/>
    </bean>
    <bean parent="taskletStep">
    <property name="tasklet" ref="object2"/>
    </bean>
    <bean parent="taskletStep">
    <property name="tasklet" ref="object3"/>
    </bean>
    </list>
    </property>
    <property name="jobRepository" ref="jobRepository"/>
  </bean>
</beans>
```

1.  配置`jobLauncher`和`JobRepository`。

```java
  <bean id="jobLauncher" class="org.springframework.batch.core.launch.support.SimpleJobLauncher">
    <property name="jobRepository" ref="jobRepository"/>
  </bean>
  <bean id="jobRepository" class="org.springframework.batch.core.repository.support.SimpleJobRepository">
    <constructor-arg>
      <bean class="org.springframework.batch.core.repository.dao.MapJobInstanceDao"/>
    </constructor-arg>
    <constructor-arg>
      <bean class="org.springframework.batch.core.repository.dao.MapJobExecutionDao" />
    </constructor-arg>
    <constructor-arg>
      <bean class="org.springframework.batch.core.repository.dao.MapStepExecutionDao"/>
    </constructor-arg>
  </bean>
```

1.  您可以使用 MVN Compile 运行项目，如下所示：

```java
mvn clean compile exec:java -Dexec.mainClass=org.springframework.batch.core.launch.support.CommandLineJobRunner -Dexec.args="simpleJob.xml simpleJob"
OUTPUT:
Dad not well
Call the Doctor
He is sweating

```

## 使用 Spring Batch 读取 CSV 文件

让我们创建另一个批处理应用程序，从目录中读取 CSV 文件，并使用`commandlinerunner`运行作业。输出再次是一个 CSV 文件，将在`output`文件夹中可用。

这个例子是关于展示 Spring Batch 框架中可用的`ItemWriter`和`ItemReader`实现的各种选项。我们在这里使用了 Spring Framework 中可用的`flatFileItemReader`和`flatFileItemWriter`实现。

我们将从应用程序开发开始，看看这些`ItemReader`实现类是如何使用的。

1.  使用 Maven 创建一个名为`SpringBatchCommandLine-Chapter4Example2`的 Spring Java 应用程序。

1.  创建一个领域类`Employee`，具有两个实例变量`empId`和`name`，以及 getter 和 setter：

```java
package com.packt;
public class Employee {

  int empId;
  String name;
  public int getEmpId() {
    return empId;
  }
  public void setEmpId(int empId) {
    this.empId = empId;
  }
  public String getName() {
    return name;
  }
  public void setName(String name) {
    this.name = name;
  }
}
```

1.  使用`ItemWriter`接口并实现一个`CustomeItemWriter`类。这个类重写了`ItemWriter`接口中定义的`write`方法。

1.  您将观察到`write`方法接受`List`作为输入。在`write`方法中，我们只是解析列表并将列表索引值强制转换为`Employee`对象并打印它。

```java
package com.packt;
import java.util.List;
import org.springframework.batch.item.ItemWriter;
public class CustomItemWriter<T> implements ItemWriter<T> {
  @Override
  public void write(List<? extends T> items) throws Exception {
    for (int i = 0; items.size() > i; i++) {
      Employee obj = (Employee) items.get(i);
      System.out.println(obj.getEmpId() + ":" + obj.getName());
    }

  }

}
```

1.  创建一个带有`public static void main()`和`jobrun()`方法的`Main`类：

```java
public class Main {
  public static void main(String[] args) {
    Main obj = new Main();
    obj.run();
  }

  private void run() {
    /*config files are present in the resource folder*/
    String[] springConfig = { "spring/batch/config/context.xml", "spring/batch/jobs/job-read-files.xml" };

    ApplicationContext context = new ClassPathXmlApplicationContext(springConfig);

    JobLauncher jobLauncher = (JobLauncher) context.getBean("jobLauncher");
    Job job = (Job) context.getBean("readMultiFileJob");
    try {
      JobExecution execution = jobLauncher.run(job, new JobParameters());
      System.out.println("Exit Status : " + execution.getStatus());
      System.out.println("Exit Status : " + execution.getAllFailureExceptions());

    } catch (Exception e) {
      e.printStackTrace();

    }

    System.out.println("COMPLETED");

  }
}
/*config files are present in the resource folder*/
```

1.  让我们在`context.xml`文件中将`bean id`设置为`JobRepository`：

```java
<bean id="jobRepository" class="org.springframework.batch.core.repository.support.MapJobRepositoryFactoryBean">
  <property name="transactionManager" ref="transactionManager" />
</bean>

<bean id="transactionManager" class="org.springframework.batch.support.transaction.ResourcelessTransactionManager" />

<bean id="jobLauncher" class="org.springframework.batch.core.launch.support.SimpleJobLauncher">
<property name="jobRepository" ref="jobRepository" />
</bean>

/*
```

`Job Read files.xml`文件位于资源文件夹`*/Job Read files.xml`中。

我们使用了`flatfileItemReader`和`FlatFileItemWriter`。这些类读取输入并在`output`文件夹中重新创建文件。

让我们看一下`FlatFileItemReader`的原型，并了解它在应用程序中的作用：

```java
public class FlatFileItemReader<T> extends AbstractItemCountingItemStreamItemReader<T>
implements ResourceAwareItemReaderItemStream<T>, org.springframework.beans.factory.InitializingBean
```

可重新启动的`ItemReader`从输入`setResource(Resource)`中读取行。一行由`setRecordSeparatorPolicy(RecordSeparatorPolicy)`定义，并使用`setLineMapper(LineMapper)`映射到一个项目。

如果在行映射期间抛出异常，则将其作为`FlatFileParseException`重新抛出，并添加有关有问题的行及其行号的信息。

```java
public class FlatFileItemWriter<T>
extends AbstractItemStreamItemWriter<T>
implements ResourceAwareItemWriterItemStream<T>, org.springframework.beans.factory.InitializingBean
```

这个类是一个将数据写入文件或流的项目写入器。写入器还提供了重新启动。输出文件的位置由资源定义，并且必须表示可写文件，并使用缓冲写入器以提高性能。该实现不是线程安全的。

在文件中，我们做了以下事情：

+   我们已经配置了名为`readMultiFileJob`的作业

+   我们必须观察到`tasklet`有一个步骤，该步骤配置了`ItemReader`和`ItemWriter`类

+   我们再次使用了`tasklet`，但我们使用了步骤作为一个接受`MultiResourceReader`的`chunk`读取器

为了理解`MultiResourceReader`，我们将看一下原型：

```java
public class MultiResourceItemReader<T>extends AbstractItemStreamItemReader<T>
```

`MultiResourceReader`从多个资源中顺序读取项目。资源列表由`setResources(Resource[])`给出，实际读取委托给`setDelegate(ResourceAwareItemReaderItemStream)`。输入资源使用`setComparator(Comparator)`进行排序，以确保在重新启动场景中作业运行之间保留资源排序。

现在，让我们看看`chunk`类型的步骤是什么。在一个`chunk`中，读取器和写入器是必需的！但是，`ItemProcessor`是可选的。

```java
<import resource="../config/context.xml"/>
  <bean id="employee" class="com.packt.Employee" />
  <job id="readMultiFileJob" >

    <step id="step1">
    <tasklet>
    <chunk reader="multiResourceReader" writer="flatFileItemWriter" commit-interval="1" />
    </tasklet>
    </step>

  </job>
<! --create folder structure in the project root csv/inputsand add the csv files-->
  <bean id="multiResourceReader"class=" org.springframework.batch.item.file.MultiResourceItemReader">
    <property name="resources" value="file:csv/inputs/employee-*.csv" /> 
    <property name="delegate" ref="flatFileItemReader" />
  </bean>

  <bean id="flatFileItemReader" class="org.springframework.batch.item.file.FlatFileItemReader">

    <property name="lineMapper">
    <bean class="org.springframework.batch.item.file.mapping.DefaultLineMapper">

      <property name="lineTokenizer">
      <bean class="org.springframework.batch.item.file.transform.DelimitedLineTokenizer">
        <property name="names" value="id, name" />
      </bean>
      </property>
      <property name="fieldSetMapper">
      <bean class="org.springframework.batch.item.file.mapping.BeanWrapperFieldSetMapper">
        <property name="prototypeBeanName" value="domain" />
      </bean>
      </property>
    </bean>
    </property>

  </bean>

  <bean id="flatFileItemWriter" class="org.springframework.batch.item.file.FlatFileItemWriter" >
    <!--create folder structure in the project root csv/outputs -->

    <property name="resource" value="file:csv/outputs/employee.all.csv" /> 
    <property name="appendAllowed" value="true" />
    <property name="lineAggregator">
    <bean class="org.springframework.batch.item.file.transform.DelimitedLineAggregator">
      <property name="delimiter" value="," />
      <property name="fieldExtractor">
      <bean class="org.springframework.batch.item.file.transform.BeanWrapperFieldExtractor">
        <property name="names" value="id, domain" />
      </bean>
      </property>
    </bean>
    </property>

  </bean> 
```

创建几个名为`employee*.csv`的 CSV 文件，用不同的数字替换`*`。每个文件将有两个值：`employeeId`和`name`。

CSV 文件中的分隔符也可以在 XML 中进行配置，如下所示：

```java
<bean class="org.springframework.batch.item.file.transform.DelimitedLineAggregator">
  <property name="delimiter" value="," />
  <property name="fieldExtractor">
  <bean class="org.springframework.batch.item.file.transform.BeanWrapperFieldExtractor">
    <property name="names" value="id, domain" />
  </bean>
  </property>
```

这些值将与**普通的 Java 对象**（**Pojo**）`Employee.java`进行映射，并且输出将被处理。文件位置作为输入传递给`MultiResourceItemReader`类。

在下一节中，我们将看到如何在 Spring 中安排批处理作业。

## 使用 Spring 调度程序的 Spring Batch

在本节中，让我们看看如何在 Spring Batch 框架中安排批处理。我们将看到如何配置调度程序。这是一个示例的`jobproduct.xml`文件，需要在类路径中可用。如果您正在使用 Maven 项目，请将其放在资源文件夹中。您需要使用间隔和方法名`run()`来注入`joblauncher`以在预定时间运行作业。

要使用调度程序，我们需要配置`job-product.xml`文件。该文件也用于在下一节中配置外部调度程序的调度程序详细信息。

安排每 600 秒间隔运行任务：

```java
<task:scheduled-tasks>
  <task:scheduled ref="MyJobScheduler" method="run" cron="*/600 * * * * *" />
</task:scheduled-tasks>
```

让我们在`MyJobScheduler.class`中使用`@Component`和`@Autowired`注解。

```java
@Component
public class MyJobScheduler {
  @Autowired
  private JobLauncher jobLauncher;
  @Autowired
  private Job job;
  public void run() {
    try {
      String dateParam = new Date().toString();
      JobParameters param = new JobParametersBuilder().addString("date", dateParam).toJobParameters();
      JobExecution execution = jobLauncher.run(job, param);
      System.out.println("Exit Status  of the Job: " + execution.getStatus());

    } catch (Exception e) {
    e.printStackTrace();
    }

  }
}
```

## 使用 Quartz 调度程序配置 Spring Batch

Spring Batch 框架提供了将外部调度程序配置到应用程序中的选项。

让我们将 Quartz 调度程序集成到 Spring Batch 应用程序中。Quartz 是一个开源的基于 Java 的调度程序。我们将使该应用程序读取一个文件，但我们将集成 Quartz 调度程序来进行调度。

1.  创建一个名为`SpringBatchQuartzExample`的简单 Maven 应用程序。

1.  使用与之前应用程序相同的`pom.xml`文件。

1.  在`pom.xml`文件的依赖项中添加 Quartz JAR 文件。

1.  添加这些属性：

```java
<quartz.version>1.8.6</quartz.version>
```

1.  然后，添加这些依赖项：

```java
<dependency>
  <groupId>org.quartz-scheduler</groupId>
  <artifactId>quartz</artifactId>
  <version>${quartz.version}</version>
</dependency>
```

让我们创建一个名为`quartz-job.xml`的文件。这应该存在于 Maven 项目的资源文件夹中。要配置批处理每分钟运行一次，使用以下代码中的配置：

```java
<bean class="org.springframework.scheduling.quartz.SchedulerFactoryBean">
  <property name="triggers">
  <bean id="cronTrigger" class="org.springframework.scheduling.quartz.CronTriggerBean">
  <property name="jobDetail" ref="jobDetail" />
  <property name="cronExpression" value="*/60 * * * * ?" />
  </bean>
  </property>
</bean>
```

要将 Spring Batch 与 Quartz 调度程序集成，使用以下代码：

```java
<bean id="jobDetailBean" class="org.springframework.scheduling.quartz.JobDetailBean">
  <property name=" jobQuartzLauncherDetails " value="com.packt.quartz.JobQuartzLauncherDetails" />
  <property name="group" value="quartz-batch" />
  <property name="jobDataAsMap">
  <map>
    <entry key="jobName" value="reportJob" />
    <entry key="jobLocator" value-ref="jobRegistry" />
    <entry key="jobLauncher" value-ref="jobLauncher" />
    <entry key="param1" value="anjana" />
    <entry key="param2" value="raghu" />
  </map>
  </property>
</bean>
```

`JobQuartzLauncherDetails`是一个扩展`QuartzJobBean`的 bean。

### 提示

`QuartzJobBean`位于`org.springframework.scheduling.quartz.QuartzJobBean`包中。

该类具有`JobLauncher`和`JobLocator`的 setter：

```java
public class JobQuartzLauncherDetails extends QuartzJobBean {
  static final String JOB_NAME = "jobName";
  private JobLocator jobLocator;
  private JobLauncher jobLauncher;
  public void setJobLocator(JobLocator jobLocator) {
    this.jobLocator = jobLocator;
  }
  public void setJobLauncher(JobLauncher jobLauncher) {
    this.jobLauncher = jobLauncher;
  }
```

为了从配置中读取`JobMapDetails`，我们创建了另一个方法，如下所示。我们可以看到，基于从地图中读取的值，这里处理了不同的数据类型，并创建了`JobParametersBuilder`。

```java
private JobParameters getJobParametersFromJobMap(Map<String, Object> jobDataMap) {
  JobParametersBuilder builder = new JobParametersBuilder();
  for (Entry<String, Object> entry : jobDataMap.entrySet()) {
    String key = entry.getKey();
    Object value = entry.getValue();
    if (value instanceof String && !key.equals(JOB_NAME)) {
      builder.addString(key, (String) value);
    } else if (value instanceof Float || value instanceof Double){
      builder.addDouble(key, ((Number) value).doubleValue());
    } else if (value instanceof Integer || value instanceof Long){
      builder.addLong(key, ((Number) value).longValue());
    } else if (value instanceof Date) {
      builder.addDate(key, (Date) value);
    } else {

    }
  }

  builder.addDate("run date", new Date());
  return builder.toJobParameters();
}
```

正如我们所知，`JobName`和`JobParamters`是`JobLauncher`运行作业所需的输入。在前面的代码片段中，我们已经得到了`JobParameters`。接下来，我们将使用以下代码片段使用`JobExecutionContext`获取`JobName`：

```java
protected void executeInternal(JobExecutionContext context) {
  Map<String, Object> jobDataMap = context.getMergedJobDataMap();
  String jobName = (String) jobDataMap.get(JOB_NAME);
  JobParameters jobParameters = getJobParametersFromJobMap(jobDataMap);

  try {
    jobLauncher.run(jobLocator.getJob(jobName), jobParameters);
  } catch (JobExecutionException e) {
    e.printStackTrace();
  }
}
```

`Product.java`是一个领域类，将其映射到`.csv`文件中的值。

```java
public class Product {
  private int id;
  private String name;
  public int getId() {
    return id;
  }
  public void setId(int id) {
    this.id = id;
  }
  public String getName() {
    return name;
  }
  public void setName(String name) {
    name = name;
  }
  @Override
  public String toString() {
    return "Product [id=" + id + ", name=" + name + "]";
  }
}
```

`CustomeItemWriter`的代码如下，用于写入产品 Pojo 对象的值。

```java
public class CustomItemWriter implements ItemWriter<Product> {
  @Override
  public void write(List<? extends Product> items) throws Exception {
    System.out.println("writer..." + items.size());
    for(Product item : items){
      System.out.println(item);
    }
  }
}
```

接下来，让我们创建`Main`类来加载`job-quartz.xml`文件，并且每 60 秒运行一次批处理作业，以使用`CustomItemWriter`读取 CSV 文件并写入。

```java
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
public class Main {
  public static void main(String[] args) {
    String springConfig = "spring/batch/jobs/job-quartz.xml";
    ApplicationContext context = new ClassPathXmlApplicationContext(springConfig);
  }
}
```

Spring Batch 框架使用 Quartz 调度程序来运行批处理作业，读取文件，将 CSV 值映射到产品 Pojo，并使用`CustomeItemWriter`进行写入。

在下一节中，让我们创建一个批处理作业，读取一个文件并更新数据库。

## 使用 Spring Batch 读取文件并更新 MongoDB 数据库

在这一部分，让我们创建一个批处理作业，读取一个 XML 文件并将其写入 MongoDB 数据库。想象一种情况，我们不断从一个来源获取一个 XML 文件，并且需要将该文件读取并更新到数据库中。

1.  XML 文件结构如下所示：

```java
<?xml version="1.0" encoding="UTF-8" ?>
<Products>
  <product id="1">
    <categoryId>3</categoryId>
    <brandId>1</brandId>
    <name>computer</name>
    <price>15000</price>
  </product>
  <product id="2">
  <categoryId>4</categoryId>
  <brandId>1</brandId>
  <name>mouse</name>
  <price>250</price>
  </record>
  </ product>
  < product id="3">
    <categoryId>5</categoryId>
    <brandId>1</brandId>
    <name>mouse</name>
    <price>23000</price>
  </ product>
</Products>
```

1.  创建一个基于 Maven 的 Java 项目。在`com.packt.model`包中，添加相应的产品 Pojo。

```java
public class Product {
  private int id;
  private int categoryId;
  private int brandId;
  private String name;
  private int price;
  public int getId() {
    return id;
  }
  public void setId(int id) {
    this.id = id;
  }
  public int getCategoryId() {
    return categoryId;
  }
  public void setCategoryId(int categoryId) {
    this.categoryId = categoryId;
  }
  public int getBrandId() {
    return brandId;
  }
  public void setBrandId(int brandId) {
    this.brandId = brandId;
  }
  public String getName() {
    return name;
  }
  public void setName(String name) {
    this.name = name;
  }
  public int getPrice() {
    return price;
  }
  public void setPrice(int price) {
    this.price = price;
  }

}
```

1.  添加与上一节中显示的相同的依赖项。

1.  更新`pom.xml`文件。

1.  添加 ORM 和 MongoDB 数据库依赖项：

```java
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-oxm</artifactId>
  <version>${spring.version}</version>
</dependency>
<dependency>
  <groupId>org.mongodb</groupId>
  <artifactId>mongo-java-driver</artifactId>
  <version>${mongodb.driver.version}</version>
</dependency>

  <!-- Spring data mongodb -->
<dependency>
  <groupId>org.springframework.data</groupId>
  <artifactId>spring-data-mongodb</artifactId>
  <version>${spring.data.version}</version>
</dependency>
```

1.  创建一个名为`mongodatabase.xml`的文件，并向其中添加以下配置：

```java
  <mongo:mongo host="127.0.0.1" port="27017" />
  <mongo:db-factory dbname="eshopdb" />

  <bean id="mongoTemplate" class="org.springframework.data.mongodb.core.MongoTemplate">
  <constructor-arg name="mongoDbFactory" ref="mongoDbFactory" />
  </bean>
```

1.  将以下配置添加到`job-product.xml`文件中。

+   `StaxEventItemReader`：这是一个读取`products.xml`文件的类。我们需要为这个类提供`rootElemenent`名称。

+   `fragmentRootElementName`：此属性接受提供的 XML 文件中的根元素的字符串参数。

我们还需要将 XML 文件名作为值提供给资源属性。需要传递的第三个属性是`unmarshaller`引用。这个类在 Spring OXM 框架中可用于对 XML 文件进行编组和取消编组。

```java
<bean id="xmlItemReader" class="org.springframework.batch.item.xml.StaxEventItemReader">
  <property name="fragmentRootElementName" value="product" />
  <property name="resource" value="classpath:xml/product.xml" />
  <property name="unmarshaller" ref="productUnmarshaller" />
</bean>
```

`XstreamMarshaller`接受三个属性来执行取消编组过程。它接受一个带有条目键和产品 Pojo 作为值的映射，以便在 XML 中，每个产品记录都被转换为`Product`对象并存储在映射中。第二个属性再次是一个创建的 bean，用于将 XML 转换为 POJO。这个名字叫`ProductXMLConverter`。

```java
<bean id="productUnmarshaller" class="org.springframework.oxm.xstream.XStreamMarshaller">

  <property name="aliases">
  <util:map id="aliases">
  <entry key="product" value="com.packt.model.Product" />
  </util:map>
  </property>
  <property name="converters">
  <array>
  <ref bean="productXMLConverter" />
  </array>
  </property>
</bean>

<bean id="productXMLConverter" class="com.packt.converter. ProductXMLConverter>	
```

让我们看看`ProductXMLConverter`类。这个类实现了`converter`接口，该接口位于`com.thoughtworks.xstream.converters.converter`包中。该类覆盖了接口中定义的三个方法：

+   `public boolean canConvert(Class type)`

+   `public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context)`

+   `public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context)`

1.  由于我们将在这里执行取消编组，因此我们将清楚地实现`unmarshall`方法。

```java
@Override
public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
  Product obj = new Product();
  obj.setId(Integer.valueOf(reader.getAttribute("id")));
  reader.moveDown(); //get id
  obj.setCategoryId(Integer.valueOf(reader.getAttribute("categoryId")));
  reader.moveDown(); //get categoryId
  obj.setBrandId(Integer.valueOf(reader.getAttribute("brandId")));
  reader.moveDown(); //get brandId
  obj.setName(String.valueOf(reader.getAttribute("name")));
  reader.moveDown(); //get name
  obj.setPrice(Integer.valueOf(reader.getAttribute("price")));
  reader.moveDown(); //get name
  return obj;
}
```

1.  在`job-product.xml`中配置`MongoDBItemWriter`以将 Pojo 对象写入 MongoDB 数据库：

```java
<bean id="mongodbItemWriter" class="org.springframework.batch.item.data.MongoItemWriter">
  <property name="template" ref="mongoTemplate" />
  <property name="collection" value="product" />
</bean>
```

1.  在`job-product.xml`文件中配置批处理作业：

```java
<batch:job id="productJob">
  <batch:step id="step1">
  <batch:tasklet>
  <batch:chunk reader="xmlItemReader" writer="mongodbItemWriter" commit-interval="1">
  </batch:chunk>
  </batch:tasklet>
  </batch:step>
</batch:job>
```

1.  编写`Main`类来运行批处理作业。

1.  在`Main`类中加载所有配置文件：

```java
public class Main {
  public static void main(String[] args) {
    String[] springConfig  = {"spring/batch/config/mongodatabase.xml", "spring/batch/config/context.xml", "spring/batch/jobs/job-product.xml" 
  };

  ApplicationContext context = new ClassPathXmlApplicationContext(springConfig);

  JobLauncher jobLauncher = (JobLauncher) context.getBean("jobLauncher");
  Job job = (Job) context.getBean("productJob");

  try {

    JobExecution execution = jobLauncher.run(job, new JobParameters());
    System.out.println("Exit Status of the ProductJOB: " + execution.getStatus());

    } catch (Exception e) {
      e.printStackTrace();
    }

    System.out.println("YES COMPLETED");

  }
}
```

因此，当我们运行`Main`类时，作业将被实例化，并且每 60 秒运行一次。作业将读取 XML 并将其转换为 Pojo `product.java`，然后将其插入到 MongoDB 数据库中。配置在 MongoDB 数据库 XML 文件中给出。

在下一节中，我们将看到如何创建一个多线程环境来处理多个作业。

## 使用 Spring Batch 和线程来分区作业

在 Spring 批处理过程中，一个线程按顺序处理请求。如果我们想要并行执行批处理作业，我们可以选择多线程环境。

想象一种情景，我们正在处理与`Employee` Pojo 映射的员工表中的 1000 条记录。我们需要一次读取 1000 条记录并写入 CSV 文件。

作业实际上被分成多个子作业，并且分配了一个单独的线程来处理每个子作业。因此，如果您有 1000 条记录需要读取，使用单个线程会花费更多时间。当我们将 1000 条记录分成 100 个子记录时，我们可以使用同时运行的 10 个不同线程来处理它们。

我们可以通过实现`Partitioner`接口来创建一个简单的分区器类。这个分区器将 1000 个作业分成 100 个子作业。您将观察到我们在分区范围中提供了`start_range`和`end_range`变量。

```java
public class MyJobPartioner implements Partitioner {
  @Override
  public Map<String, ExecutionContext> partition(int gridSize) {
    Map<String, ExecutionContext> result = new HashMap<String, ExecutionContext>();
    int range = 100;
    int start_range = 1;
    int end_range = range;
    for (int i = 1; i <= gridSize; i++) {
      ExecutionContext execution_context = new ExecutionContext();
      System.out.println("\Name: Thread" + i+"start_range : " + start_range+"end_range", end_range);
      execution_context.putInt("start_range", start_range);
      execution_context.putInt("end_range", end_range);
      execution_context.putString("name", "Thread" + i);
      result.put("partition" + i, execution_context);
      start_range = end_range + 1;
      end_range += range;
    }
    return result;
  }

}
```

在`Partitioner`类中使用的`ExecutionContext`对象与`ItemStream`一起工作，并充当映射的包装器。在 Spring Batch 中，我们可以获得两种类型的执行上下文对象。一个执行对象在作业级别工作，另一个在步骤级别工作。作业级别执行上下文用于在步骤之间共享数据或信息。

让我们实现一个处理分区记录的`ItemProcess`类。还要注意，我们在下面的代码中使用了步骤执行上下文。该类覆盖了`process`方法。

1.  这个类用于分块处理数据。

```java
@Component("itemProcessor")
@Scope(value = "step")
public class EmployeeProcessor implements ItemProcessor<Employee, Employee> {
  @Value("#{stepExecutionContext[name]}")
  private String threadName;
  @Override
  public Employee process(Employee emp) throws Exception {
    System.out.println(threadName + " processing : " + emp.getId() + " : " + emp.getName());
    return emp;
  }
  public String getThreadName() {
    return threadName;
  }
  public void setThreadName(String threadName) {
    this.threadName = threadName;
  }

}
```

1.  让我们配置`job-partioner.xml`文件。

```java
<job id="partitionJob" >
  <step id="masterStep">
  <partition step="slave" partitioner="myJobPartioner">
  <handler grid-size="100" task-executor="taskExecutor" />
  </partition>
  </step>

</job>
<step id="slave" >
  <tasklet>
  <chunk reader="pagingItemReader" writer="flatFileItemWriter"
  processor="itemProcessor" commit-interval="1" />
  </tasklet>
</step>

<!—below is the configuration of MyJobPartioner bean-->

<bean id="myJobPartioner" class="com.packt.partition.MyJobPartioner" />
<bean id="taskExecutor" class="org.springframework.core.task.SimpleAsyncTaskExecutor" />

<!—below is the configuration of EmployeeProcesser bean-->

<bean id="itemProcessor" class="com.packt.processor.EmployeeProcessor" scope="step">
  <property name="threadName" value="#{stepExecutionContext[name]}" />
</bean>
```

接下来，让我们配置`pagingItemReader`，它的作用与分页相同。它每页获取 100 条记录；它还使用提供的 JDBC 信息连接到数据源，并执行查询以获取指定范围的记录。它还将根据`emp_id`列对数据进行排序。

```java
<bean id="pagingItemReader" class="org.springframework.batch.item.database.JdbcPagingItemReader"scope="step">
  <property name="dataSource" ref="dataSource" />
  <property name="queryProvider">
  <bean class="org.springframework.batch.item.database.support.SqlPagingQueryProviderFactoryBean">
    <property name="dataSource" ref="dataSource" />
    <property name="selectClause" value="select emp_id, emp_name, emp_pass, emp_salary" />
    <property name="fromClause" value="from users" />
    <property name="whereClause" value="where emp_id &gt;= :fromId and id &lt;= :toId" />
    <property name="sortKey" value="emp_id" />
  </bean>
  </property>
 <!-- Inject via the ExecutionContext in MyJobPartioner -->
  <property name="parameterValues">
  <map>
    <entry key="fromId" value="#{stepExecutionContext[start_range]}" />
    <entry key="toId" value="#{stepExecutionContext[end_range]}" />
  </map>
  </property>
  <property name="pageSize" value="100" />
  <property name="rowMapper">
  <bean class="com.packt.EmployeeRowMapper" />
  </property>
  </bean>

<!--After reading it writes to  csv file using FlatfileItemwriter class-->

  <bean id="flatFileItemWriter" class="org.springframework.batch.item.file.FlatFileItemWriter" scope="step" >
    <property name="resource"
    value="file:csv/outputs/employee.processed#{stepExecutionContext[fromId]}-#{stepExecutionContext[toId]}.csv" />
    <property name="appendAllowed" value="false" />
    <property name="lineAggregator">
    <bean class="org.springframework.batch.item.file.transform.DelimitedLineAggregator">
      <property name="delimiter" value="," />
      <property name="fieldExtractor">
      <bean class="org.springframework.batch.item.file.transform.BeanWrapperFieldExtractor">
        <property name="names" value="emp_id, emp_name, emp_pass, emp_salary" />
      </bean>
      </property>
    </bean>
    </property>
  </bean>
<!--Configuring FlatfileItemwriter class- ends-->
```

1.  让我们编写`Main`类，它将加载配置文件，然后运行作业。

```java
public class Main {
  public static void main(String[] args) {
    Main obj = new Main();
    obj.run();
  }
  private void run() {
    String[] springConfig = { "spring/batch/jobs/job-partitioner.xml" };
    ApplicationContext context = new ClassPathXmlApplicationContext(springConfig);
    JobLauncher jobLauncher = (JobLauncher) context.getBean("jobLauncher");
    Job job = (Job) context.getBean("partitionJob");
    try {
      JobExecution execution = jobLauncher.run(job, new JobParameters());
      System.out.println("Exit Status : " + execution.getStatus());
      System.out.println("Exit Status : " + execution.getAllFailureExceptions());
    } catch (Exception e) {
      e.printStackTrace();
    }
    System.out.println("COMPLETED");
  }

}
```

因此，通过前面的配置和类，将创建多个线程来处理每个线程的 100 条记录。记录从数据库中读取并写入 CSV 文件。

在下一节中，我们将使用 Spring Batch 的事件监听器。

# 使用监听器拦截 Spring Batch 作业

Spring Batch 带有监听器。它们拦截作业执行以执行某些任务。`StepListener`是以下提到的监听器的`super`类：

+   `SkipListener`：`SkipListener`最常见的用例之一是记录跳过的项目，以便可以使用另一个批处理过程或甚至人工过程来评估和修复导致跳过的问题。因为有许多情况下原始事务可能被回滚，Spring Batch 提供了两个保证：

+   适当的`skip`方法（取决于错误发生的时间）每个项目只会被调用一次。

+   `SkipListener`将在事务提交之前始终被调用。这是为了确保监听器调用的任何事务资源不会因`ItemWriter`内部的失败而被回滚。

+   `ChunkListener`：这些监听器可以配置一个步骤，如果步骤是分块式步骤类型，它将同时具有`ItemReader`和`ItemWriter`。当`ItemReader`完成其读取任务时，监听器将通知`ItemWriter`。

```java
public interface ChunkListener extends StepListener {
  void beforeChunk();
  void afterChunk();
}
<step id="step1">
  <tasklet>
  <chunk reader="reader" writer="writer" commit-interval="10"/>
  <listeners>
    <listener ref="chunkListener"/>
  </listeners>
  </tasklet>
</step>
```

+   `ItemWriterListener`

+   `ItemReaderListener`

+   `ItemProcessListener`

+   `StepExecutionListener`：它代表步骤执行的最通用的监听器。它允许在步骤开始之前和结束之后通知，无论它是正常结束还是失败结束。

您将注意到为`ItemReader`、`ItemWriter`、`ItemProcess`和`StepExecution`接口和类配置了监听器。

现在我们可以看看如何在 spring `batch.xml`文件中配置监听器。请看：

1.  创建实现监听器并覆盖其方法的类。

```java
<bean id="packtStepListener" class="com.packt.listeners.PacktStepListener" />
<bean id="packtItemReaderListener" class="com.packt.listeners.PacktItemReaderListener" />
<bean id="packtItemWriterListener" class="com.packt.listeners.PacktItemWriterListener" />

<job id="readFileJob" >
  <step id="step1">
  <tasklet>
  <chunk reader="multiResourceReader" writer="flatFileItemWriter" commit-interval="1" />
  <listeners>
    <listener ref="packtStepListener" />
    <listener ref="packtItemReaderListener" />
    <listener ref="packtItemWriterListener" />
  </listeners>
  </tasklet>
  </step>
</job>
```

1.  让我们看看`PacktItemReaderListener`和`PacktItemWriterListner`监听器。`IteamReadListener`接口带有三个要实现的方法：

+   `beforeRead()`

+   `afterRead()`

+   `onReadError()`

```java
public class PacktItemReaderListener implements ItemReadListener<Product> {

  @Override
  public void beforeRead() {
    System.out.println("ItemReadListener - beforeRead");
  }

  @Override
  public void afterRead(Product product) {
    System.out.println("ItemReadListener - afterRead");
  }

  @Override
  public void onReadError(Exception ex) {
    System.out.println("ItemReadListener - onReadError");
  }

}
```

1.  接下来让我们看看`PackItemWriterListener`。`ItemWriter`接口带有三个`abstract`方法：

+   `beforeWrite`

+   `afterWrite`

+   `onWriteError`

```java
public class PacktItemWriterListener implements ItemWriteListener<Product> {
  @Override
  public void beforeWrite(List<? extends Product> products) {
    System.out.println("ItemWriteListener - beforeWrite");
  }
  @Override
  public void afterWrite(List<? extends Product> products) {
    System.out.println("ItemWriteListener - afterWrite");
  }
  @Override
  public void onWriteError(Exception exception, List<? extends Product> products) {
    System.out.println("ItemWriteListener - onWriteError");
  }
}
```

到目前为止，我们已经看到了如何在`spring-job`文件中创建自定义监听器和监听器配置。

现在，让我们尝试将其与读取目录中的多个文件并删除文件的情景集成。

1.  我们将再次考虑产品 Pojo，带有`id`和`name`作为实例变量，并带有 getter 和 setter。

```java
public class Product {
  int id;
  String name;
  public int getId() {
    return id;
  }
  public void setId(int id) {
    this.id = id;
  }
  public String getName() {
    return name;
  }
  public void setName(String Name) {
    this.name = name;
  }
}
```

1.  我们需要在 XML 中将 Pojo 定义为一个 bean。

```java
  <bean id="product" class="com.packt.Product" />
```

1.  接下来是文件删除任务类文件。在读取文件后，需要从目录中删除它们。

```java
<bean id="fileDeletingTasklet" class="com.packt.tasklet.FileDeletingTasklet" >
  <property name="directory" value="file:csv/inputs/" />
</bean>
```

1.  让我们来看一下`FileDeletingTasklet`类。这个类实现了`TaskLet`接口。这将根据指定的目录删除文件。

```java
public class FileDeletingTasklet implements Tasklet, InitializingBean {
  private Resource directory;
  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(directory, "directory must be set");
  }

  @Override
  public RepeatStatus execute(StepContribution contribution, ChunkContext chunkContext) throws Exception {
    File dir = directory.getFile();
    Assert.state(dir.isDirectory());
    File[] files = dir.listFiles();
    for (int i = 0; i < files.length; i++) {
      boolean deleted = files[i].delete();
      if (!deleted) {
        throw new UnexpectedJobExecutionException("Could not delete file " + files[i].getPath());
      } else {
        System.out.println(files[i].getPath() + " is deleted!");
      }
    }
    return RepeatStatus.FINISHED;
  }
  public Resource getDirectory() {
    return directory;
  }
  public void setDirectory(Resource directory) {
    this.directory = directory;
  }
}
```

1.  需要在创建的作业配置文件中设置 bean 属性。

```java
<bean id="fileDeletingTasklet" class="com.packt.tasklet.FileDeletingTasklet" >
  <property name="directory" value="file:csv/inputs/" />
</bean>
```

下一个任务将是读取目录中可用的多个文件。由于有多个需要读取的资源，我们将在 bean 中使用`MultiResourceReader`配置。

```java
<bean id="multiResourceReader" class=" org.springframework.batch.item.file.MultiResourceItemReader">
  <property name="resources" value="file:csv/inputs/product-*.csv" />
  <property name="delegate" ref="flatFileItemReader" />
</bean>
```

`flatfileItemReader`将 CSV 值映射到产品 Pojo。因此，请在`jobs.xml`文件中提供以下配置：

```java
<bean id="flatFileItemReader" class="org.springframework.batch.item.file.FlatFileItemReader">
  <property name="lineMapper">
  <bean class="org.springframework.batch.item.file.mapping.DefaultLineMapper">
    <property name="lineTokenizer">
    <bean class="org.springframework.batch.item.file.transform.DelimitedLineTokenizer">
      <property name="names" value="id, name" />
    </bean>
    </property>
    <property name="fieldSetMapper">
    <bean class="org.springframework.batch.item.file.mapping.BeanWrapperFieldSetMapper">
      <property name="prototypeBeanName" value="product" />
    </bean>
    </property>
  </bean>
  </property>

</bean>
```

然后，在读取 CSV 值并将它们从不同的 CSV 文件映射到 Pojo 之后，如果需要合并到单个 CSV 文件，我们可以添加`writterListener`。

```java
<bean id="flatFileItemWriter" class="org.springframework.batch.item.file.FlatFileItemWriter">
  <property name="resource" value="file:csv/outputs/product.all.csv" />
  <property name="appendAllowed" value="true" />
  <property name="lineAggregator">
  <bean class="org.springframework.batch.item.file.transform.DelimitedLineAggregator">
    <property name="delimiter" value="," />
    <property name="fieldExtractor">
    <bean class="org.springframework.batch.item.file.transform.BeanWrapperFieldExtractor">
      <property name="names" value="id, name" />
    </bean>
    </property>
  </bean>
  </property>

</bean>
```

运行 `Main` 类时，XML 文件中配置的所有 bean 都会被实例化，以便批处理作业运行。作业在这里的 `Main` 类的配置中执行了块执行，使用了 `ItemReader` 和 `Writer`。

```java
public class Main {
  public static void main(String[] args) {
    Main obj = new Main();
    obj.run();

  }

  private void run() {
    String[] springConfig = { "spring/batch/jobs/job-read-files.xml" };
    ApplicationContext context = new ClassPathXmlApplicationContext(springConfig);
    JobLauncher jobLauncher = (JobLauncher) context.getBean("jobLauncher");
    Job job = (Job) context.getBean("readMultiFileJob");

    try {
      JobExecution execution = jobLauncher.run(job, new JobParameters());
      System.out.println("Exit Status : " + execution.getStatus());
      System.out.println("Exit Status : " + execution.getAllFailureExceptions());
    } catch (Exception e) {
      e.printStackTrace();
    }
    System.out.println("COMPLTED CHECK THE OUTPUT DIRECTORY");
  }
}
```

在本节中，我们学习了有关监听器的知识，并配置了监听器与作业。

在下一节中，我们将看到如何对 Spring Batch 应用程序进行一些单元测试。

# Spring Batch 应用程序的单元测试

让我们演示为 Spring Batch 应用程序编写测试用例：

```java
<dependency>
  <groupId>org.springframework.batch</groupId>
  <artifactId>spring-batch-test</artifactId>
  <version>2.2.0.RELEASE</version>
</dependency>

<!-- Junit -->
<dependency>
  <groupId>junit</groupId>
  <artifactId>junit</artifactId>
  <version>4.11</version>
  <scope>test</scope>
</dependency>
```

让我们创建一个名为 `Test` 类的简单的 `Test` 类，称为 `mport static org.junit.Assert.assertEquals`：

```java
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.batch.core.BatchStatus;
import org.springframework.batch.core.JobExecution;
import org.springframework.batch.test.JobLauncherTestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = {
  "classpath:spring/batch/jobs/job-report.xml",
  "classpath:spring/batch/config/context.xml",
  "classpath:spring/batch/config/database.xml",
  "classpath:spring/batch/config/test-context.xml"})
public class MainTest {
  @Autowired
  private JobLauncherTestUtils jobLauncherTestUtils;

  @Test
  public void launchJob() throws Exception {
    JobExecution jobExecution = jobLauncherTestUtils.launchStep("step1");

    assertEquals(BatchStatus.COMPLETED, jobExecution.getStatus());

  }
}
```

我们必须创建一个名为 `text-context.xml` 的文件，以便在批处理中可用，并配置 `JobLauncher` 以便在 XML 文件和测试包中可用。在 `Test` 类中，使用 `@Test 注释` 方法并调用 `JobLauncher` 执行一个步骤。我们需要使用 `assertEquals` 来检查批处理作业的状态与 `jobExecution` 状态是否一致。

# 总结

在本章中，我们学习了如何创建基于 Spring 的批处理应用程序来读取 CSV 文件。我们还阐明了 Spring Batch 如何用于读取 XML 文件。最高级的主题是将作业分区并将作业运行到单独的线程中。我们还将 Spring Batch 与 Quartz Scheduler 集成。

我们已经演示了使用 Spring Batch 编写简单测试用例。我们还使用监听器拦截了一个定义的作业来执行某些操作，并演示了某些配置。


# 第五章：Spring 与 FTP 的集成

FTP 涉及使用文件传输协议从一台计算机通过互联网发送文件到另一台计算机。Spring 集成还提供了对文件传输协议的支持。可以通过 FTP 或使用 SFTP（安全 FTP）进行文件传输。

以下是 FTP 场景中使用的一些缩写：

+   **FTP**：**文件传输协议**。

+   **FTPS**：**FTP 安全**是 FTP 的扩展，它添加了对**传输层安全**（**TLS**）和**安全套接字层**（**SSL**）加密协议的支持。

+   **SFTP**：**SSH 文件传输协议**，即 FTP 通过安全外壳协议。

在实际场景中，文件服务器将具有 FTP 地址、用户名和密码。客户端连接到服务器以传输文件。我们可以使用 FTP 上传文件到远程位置或从远程位置下载文件。

Spring 的集成包支持从 FTP 或 FTPS 服务器发送和接收文件。它提供了一些端点，以下是 Spring 为 FTP/FTPS 提供的端点/适配器：

+   入站通道适配器

+   出站通道适配器

+   出站网关

通道适配器只是消息端点，实际上将消息连接到消息通道。在处理通道适配器时，我们可以明显看到、发送和接收配置和方法。

在本章中，我们将看到 Spring 如何使我们能够使用 FTP，并开发一个演示 Spring 集成能力支持文件传输的示例应用程序。我们还将看到需要编写的配置以及如何使用入站和出站适配器来使用 Spring 集成包在 FTP 上传输文件。

# Maven 依赖项

为了使用 Spring 集成框架创建 FTP 应用程序，在 Maven 项目的`pom.xml`文件中添加以下依赖项。主要包括 Spring 集成测试和 Spring 集成 FTP。这些库可以从 Maven 仓库下载，也可以添加到项目的`pom.xml`文件中。

以下是需要添加到`pom.xml`文件中的 Maven 依赖项，以开始使用 Spring Integration FTP 包开发应用程序：

```java
<dependency>
  <groupId>org.springframework.integration</groupId>
  <artifactId>spring-integration-ftp</artifactId>
  <version>4.0.0.RELEASE</version>
  <scope>compile</scope>
</dependency>

<dependency>
  <groupId>org.springframework.integration</groupId>
  <artifactId>spring-integration-test</artifactId>
  <version>4.0.0.RELEASE</version>
  <scope>test</scope>
</dependency>

<dependency>
  <groupId>org.apache.ftpserver</groupId>
  <artifactId>ftpserver-core</artifactId>
  <version>1.0.6</version>
  <scope>compile</scope>
</dependency>
```

# Spring 的 FTP 的 XSD

让我们看看 Spring 集成包为 FTP 提供的 XSD。这包含了所有模式定义，并提供了 Spring 支持的所有配置可能性，因此配置 XML 文件变得更容易。

XSD（[`www.springframework.org/schema/integration/ftp/spring-integration-ftp.xsd`](http://www.springframework.org/schema/integration/ftp/spring-integration-ftp.xsd)）提供了关于 Spring 与 FTP 集成的大量信息。它为我们提供了有关在 XML 配置文件中配置通道适配器的信息。

入站和出站通道适配器是 XSD 中的两个主要元素。以下是从我们刚提到的链接中提取的 XSD 的摘录：

```java
<xsd:element name="outbound-channel-adapter">...</xsd:element>
<xsd:element name="inbound-channel-adapter">...</xsd:element>
<xsd:complexType name="base-ftp-adapter-type">...</xsd:complexType>
</xsd:schema>
```

在接下来的章节中，我们将看到如何配置入站和出站通道适配器以及 Spring 集成支持的 FTP 的配置选项。

## 为 FTP 配置出站通道适配器

出站通道适配器配置是针对远程目录的。它旨在执行诸如将文件写入远程服务器（文件上传）、创建新文件或在远程 FTP 服务器上添加后缀等操作。以下是 XSD 中提供的出站通道适配器的一些可用配置：

+   它支持使用正则表达式配置远程目录以写入文件。使用的属性如下：

```java
<xsd:attribute name="remote-directory-expression"type="xsd:string">
```

+   我们还可以配置自动在远程位置创建目录：

```java
<xsd:attribute name="auto-create-directory" type="xsd:string" default="false">
```

+   我们还可以配置 Spring 集成框架以与 FTP 一起工作，临时为文件添加后缀：

```java
<xsd:attribute name="temporary-file-suffix" type="xsd:string">
```

+   另一个重要的配置是在 FTP 服务器的远程位置生成文件名：

```java
<xsd:attribute name="remote-filename-generator" type="xsd:string">
```

+   前面的功能再次升级以支持正则表达式：

```java
<xsd:attribute name="remote-filename-generator-expression" type="xsd:string">
```

## 配置 FTP 的入站通道适配器

入站通道适配器配置是针对本地目录的，即旨在执行从远程服务器写入文件（文件下载）、创建新文件或在本地目录上添加后缀等操作。入站通道适配器确保本地目录与远程 FTP 目录同步。

从 XSD 中可用的入站通道适配器的一些配置如下：

+   它提供了配置选项，以自动创建本地目录（如果不存在）：

```java
<xsd:attribute name="auto-create-local-directory" type="xsd:string">
  <xsd:annotation>
    <xsd:documentation>Tells this adapter if local directory must be auto-created if it doesn't exist. Default is TRUE.</xsd:documentation> 
  </xsd:annotation>
</xsd:attribute>
```

+   它提供了配置远程服务器的选项，并在将其复制到本地目录后删除远程源文件：

```java
<xsd:attribute name="delete-remote-files" type="xsd:string">
  <xsd:annotation>
    <xsd:documentation>Specify whether to delete the remote source file after copying. By default, the remote files will NOT be deleted.</xsd:documentation> 
  </xsd:annotation>
</xsd:attribute>
```

+   使用可用的比较器配置对文件进行排序：

```java
<xsd:attribute name="comparator" type="xsd:string">
<xsd:annotation>
```

指定在排序文件时要使用的比较器。如果没有提供，则顺序将由`java.io`文件实现确定：

```java
</xsd:documentation>
  </xsd:annotation>
  </xsd:attribute>
```

+   使用以下属性配置会话缓存：

```java
<xsd:attribute name="cache-sessions" type="xsd:string" default="true">
  <xsd:annotation>
  <xsd:documentation>
<![CDATA[ 
```

指定会话是否应该被缓存。默认值为`true`。

```java
</xsd:documentation>
</xsd:annotation>
</xsd:attribute>
```

+   可以使用 XSD 引用进行的配置如下：

```java
<int-ftp:inbound-channel-adapter id="ftpInbound"
                 channel="ftpChannel" 
                 session-factory="ftpSessionFactory"
                 charset="UTF-8"
                 auto-create-local-directory="true"
                 delete-remote-files="true"
                 filename-pattern="*.txt"
                 remote-directory="some/remote/path"
                 local-directory=".">
  <int:poller fixed-rate="1000"/>
</int-ftp:inbound-channel-adapter>
```

# FTPSessionFactory 和 FTPSSessionFactory

在本节中，让我们看一下使用 Spring 集成的 FTP 的两个核心类`FTPSessionFactory`和`FTPSSessionFactory`。这些类有很多的 getter、setter 和实例变量，提供有关数据、文件和 FTP 模式的信息。实例变量及其用法如下所述：

类`org.springframework.integration.ftp.session.DefaultFtpSessionFactory`用于在应用程序中配置 FTP 详细信息。该类在配置 XML 文件中配置为一个简单的 bean。该类有以下的 getter 和 setter：

+   `Session`：这接受会话变量。

+   `postProcessClientAfterConnect`：这在执行客户端连接操作后处理额外的初始化。

+   `postProcessClientBeforeConnect`：这在执行客户端连接操作之前处理额外的初始化。

+   `BufferSize`：这定义了通过 FTP 传输的缓冲数据的大小。

+   `ClientMode`：FTP 支持两种模式。它们如下：

+   **主动 FTP 模式**：在 Spring FTP 集成包中指定为`ACTIVE_LOCAL_DATA_CONNECTION_MODE`。在主动 FTP 模式下，服务器必须确保随机端口`1023`<通信通道是打开的。在主动 FTP 模式下，客户端从一个随机的非特权端口（`N > 1023`）连接到 FTP 服务器的命令端口，端口`21`。然后，客户端开始监听端口`N + 1`并向 FTP 服务器发送 FTP 命令`PORT N + 1`。然后服务器将从其本地数据端口（端口`20`）连接回客户端指定的数据端口。

+   **被动 FTP 模式**：在 Spring FTP 集成包中指定为`PASSIVE_LOCAL_DATA_CONNECTION_MODE`。在被动 FTP 模式下，客户端同时启动到服务器的两个连接，解决了防火墙过滤来自服务器的传入数据端口连接到客户端的问题。在打开 FTP 连接时，客户端在本地打开两个随机的非特权端口（`N > 1023`和`N + 1`）。第一个端口在端口`21`上联系服务器，但是不是然后发出`PORT`命令并允许服务器连接回其数据端口，而是客户端将发出`PASV`命令。其结果是服务器随后打开一个随机的非特权端口（`P > 1023`）并在响应`PASV`命令中将`P`发送回客户端。然后客户端从端口`N + 1`到服务器上的端口`P`发起连接以传输数据。包`DefaultFTPClientFactory`具有一个设置器方法，其中有一个开关用于设置模式。

```java
**
  * Sets the mode of the connection. Only local modes are supported.
  */
  private void setClientMode(FTPClient client) {
    switch (clientMode ) {
      case FTPClient.ACTIVE_LOCAL_DATA_CONNECTION_MODE:
      client.enterLocalActiveMode();
      break;
      case FTPClient.PASSIVE_LOCAL_DATA_CONNECTION_MODE:
      client.enterLocalPassiveMode();
      break;
      default:
      break;
    }
  }
```

+   `Config`：这设置 FTP 配置对象`org.apache.commons.net.ftp.FTPClientConfig config`

+   `ConnectTimeout`：这指定了尝试连接到客户端后的连接超时时间。

+   `ControlEncoding`：这设置了编码。

+   `Data Timeout`：这设置了文件传输期间的数据超时时间。

+   `Default Timeout`：这设置了套接字超时时间。

+   `文件类型`：FTP 协议支持多种文件类型。它们列举如下：

+   **ASCII 文件类型（默认）**：文本文件以**网络虚拟终端**（**NVT**）ASCII 格式通过数据连接传输。这要求发送方将本地文本文件转换为 NVT ASCII，接收方将 NVT ASCII 转换为本地文本文件类型。每行的结尾使用 NVT ASCII 表示回车后跟换行。这意味着接收方必须扫描每个字节，寻找 CR，LF 对。（我们在第 15.2 节中看到了 TFTP 的 ASCII 文件传输中的相同情景。）

+   **EBCDIC 文件类型**：在两端都是**扩展二进制编码十进制交换码**（**EBCDIC**）系统时，传输文本文件的另一种方式。

+   **图像文件类型**：也称为二进制文件类型。数据以连续的位流发送，通常用于传输二进制文件。

+   **本地文件类型**：这是在不同字节大小的主机之间传输二进制文件的一种方式。发送方指定每字节的位数。对于使用 8 位的系统，具有 8 字节大小的本地文件类型等同于图像文件类型。我们应该知道 8 位等于 1 字节。

Spring 有抽象类`AbstractFtpSessionFactory<T extends org.apache.commons.net.ftp.FTPClient>`，其中定义了以下参数和静态变量，可以在 FTP 的配置中使用：

```java
public static final int ASCII_FILE_TYPE = 0;
public static final int EBCDIC_FILE_TYPE = 1;
public static final int BINARY_FILE_TYPE = 2;
public static final int LOCAL_FILE_TYPE = 3;
```

+   `Host`：指定 FTP 主机。

+   `Password`：指定 FTP 密码。

+   `Port`：指定 FTP 端口。有两个可用的端口，一个是数据端口，一个是命令端口。数据端口配置为 20，命令端口配置为 21。

+   `Username`：指定 FTP 用户名。

以下配置显示了`DefaultFtpSessionFactory`类作为一个 bean，其 bean ID 为`ftpClientFactory`，并且其属性值根据 FTP 服务器凭据进行设置：

```java
<bean id="ftpClientFactory" class="org.springframework.integration.ftp.session.DefaultFtpSessionFactory">
  <property name="host" value="localhost"/>
  <property name="port" value="22"/>
  <property name="username" value="anjana"/>
  <property name="password" value="raghu"/>
  <property name="clientMode" value="0"/>
  <property name="fileType" value="1"/>
</bean>
```

`org.springframework.integration.ftp.session.DefaultFtpsSessionFactory`类使我们能够使用 FTPS 连接。该类包含以下内容的 getter 和 setter：

+   `BufferSize`

+   `clientMode`

+   `config`

+   `ControlEncoding`

+   `DEFAULT_REMOTE_WORKING_DIRECTORY`

+   `fileType`

+   `host`

+   `password`

+   `port`

+   `username`

上述字段是从名为`AbstarctFtpSessionFactory`的抽象类继承的。

以下是`DefaultFtpsClientFactory`的示例 bean 配置及其可以在 XML 文件中配置的属性：

```java
<bean id="ftpClientFactory" class="org.springframework.integration.ftp.client.DefaultFtpsClientFactory">
  <property name="host" value="localhost"/>
  <property name="port" value="22"/>
  <property name="username" value="anju"/>
  <property name="password" value="raghu"/>
  <property name="clientMode" value="1"/>
  <property name="fileType" value="2"/>
  <property name="useClientMode" value="true"/>
  <property name="cipherSuites" value="a,b.c"/>
  <property name="keyManager" ref="keyManager"/>
  <property name="protocol" value="SSL"/>
  <property name="trustManager" ref="trustManager"/>
  <property name="prot" value="P"/>
  <property name="needClientAuth" value="true"/>
  <property name="authValue" value="anju"/>
  <property name="sessionCreation" value="true"/>
  <property name="protocols" value="SSL, TLS"/>
  <property name="implicit" value="true"/>
</bean>
```

# Spring FTP 使用出站通道示例

在本节中，让我们看一个简单的场景，将文件从 Location1 传输到远程位置 Location2。为了清晰起见，让我们定义它们如下：

+   Location1：`d:\folder1`

+   Location2：`d:\folder2`

让我们在 Spring 中使用 Spring 集成包创建一个简单的应用程序，以完成从 Location1 到 Location2 的文件传输任务。我们需要两个主要文件来完成这个任务；第一个是配置文件`applicationContext.xml`，第二个是一个 Java 类文件，它将通知 Spring 集成框架将文件上传到远程位置。

`applicationContext.xml`文件将包含整个必要的 bean 配置，以及使用 Spring 集成包所需的 XMLNS。需要集成的 XMLNS 如下：

```java

  xmlns:int-ftp="http://www.springframework.org/schema/integration/ftp"
```

我们还需要将`DefaultFtpSessionFactory`配置为一个 bean，其中包括`FtpChannel`和`FtpOutBoundAdpater`。`DefaultFtpSessionFactory`具有所有 FTP 属性的 setter。`FTPOutboundeAdapter`将配置为`remoteFTP`位置和`outboundchannel`。以下是完整的配置文件：

```java
<beans 

  xmlns:int-ftp="http://www.springframework.org/schema/integration/ftp"
  xsi:schemaLocation="http://www.springframework.org/schema/integration/ftp http://www.springframework.org/schema/integration/ftp/spring-integration-ftp.xsd
  http://www.springframework.org/schema/integration http://www.springframework.org/schema/integration/spring-integration.xsd
  http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

  <bean id="ftpClientFactory" class="org.springframework.integration.ftp.session.DefaultFtpSessionFactory">
    <property name="host" value="localhost"/>
    <property name="port" value="21"/>
    <property name="username" value="myftpusername"/>
    <property name="password" value="myftppassword"/>
    <property name="clientMode" value="0"/>
    <property name="fileType" value="2"/>
    <property name="bufferSize" value="100000"/>
  </bean>

  <int:channel id="ftpChannel" />

  <int-ftp:outbound-channel-adapter id="ftpOutbound"
                    channel="ftpChannel"
                    remote-directory="D:/folder2"
                    session-factory="ftpClientFactory"/>

</beans>
```

现在让我们创建一个简单的 Java 类，通知 Spring 将文件上传到 Location2。这个类将加载`applicationContext.xml`文件，并使用在 XML 文件中配置的 bean ID 实例化`FTPChannel`。创建一个文件对象，其中包含需要传输到远程位置的文件名。将这个文件对象发送到 Spring 集成消息，然后将消息发送到通道，以便文件被传送到目的地。以下是示例代码：

```java
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.integration.Message;
import org.springframework.integration.MessageChannel;
import org.springframework.integration.support.MessageBuilder;
import java.io.File;

public class SendFileSpringFTP {
  public static void main(String[] args) throws InterruptedException {
    ConfigurableApplicationContext ctx =
    new ClassPathXmlApplicationContext("/applicationContext.xml");
    MessageChannel ftpChannel = ctx.getBean("ftpChannel", MessageChannel.class);
    File file = new File("D:/folder2/report-Jan.txt");
    final Message<File> messageFile = MessageBuilder.withPayload(file).build();
    ftpChannel.send(messageFile);
    Thread.sleep(2000);
  }

}
```

运行上述类以查看`report-Jan.txt`被传输到远程位置。

## 配置 Spring FTP 以使用网关读取子文件夹中的文件

在这一节中，让我们看看另一个可以用来读取子文件夹报告的配置文件。

我们已经使用了上一节处理 FTP XSD 的表达式属性。我们将进一步看到如何使用表达式属性通知 Spring 集成 FTP 框架触发 FTP 命令。在 FTP 中执行的每个命令都会得到一个回复，通常是三位数，例如：

+   `125`：数据连接已打开；传输开始

+   `200`：命令 OK

+   `214`：帮助消息（供人类用户使用）

+   `331`：用户名正确；需要密码

+   `425`：无法打开数据连接

+   `452`：写文件错误

+   `500`：语法错误（无法识别的命令）

+   `501`：语法错误（无效参数）

+   `502`：未实现的模式类型

回复通道由网关创建。在以下代码中，我们为分割器配置了一个回复通道：

```java
<int-ftp:outbound-gateway id="gatewayLS" cache-sessions="false"
  session-factory="ftpSessionFactory"
  request-channel="inbound"
  command="ls"
  command-options="-1"
  expression="'reports/*/*'"
  reply-channel="toSplitter"/>

<int:channel id="toSplitter" />

<int:splitter id="splitter" input-channel="toSplitter" output-channel="toGet"/>

<int-ftp:outbound-gateway id="gatewayGET" cache-sessions="false"
  local-directory="localdir"
  session-factory="ftpSessionFactory"
  request-channel="toGet"
  reply-channel="toRemoveChannel"
  command="get"
  command-options="-P"
  expression="payload.filename"/>
```

使用 Spring 集成支持 FTP，我们还可以将消息分割成多个部分。这是在 XML 文件中使用`splitter`属性（`AbstractMessageSplitter implements MessageHandler`）进行配置的。

```java
<channel id="inputChannel"/>
<splitter id="splitter" 
  ref="splitterBean" 
  method="split" 
  input-channel="inputChannel" 
  output-channel="outputChannel" />
<channel id="outputChannel"/>
<beans:bean id="splitterBean" class="sample.PojoSplitter"/>
```

从逻辑上讲，`splitter`类必须分割消息并为每个分割消息附加序列号和大小信息，以便不丢失顺序。可以使用聚合器将断开的消息组合在一起，然后发送到通道。

## 在 Java 中配置 Spring FTP

在这一节中，让我们看看如何使用注解在 Java 类中配置 FTP 属性，并创建`DefaultFTPSession`工厂的实例，并使用实例可用的 setter 方法设置属性。

我们可以使用`@Configuration`注解来配置 FTP 属性，如下所示：

```java
import org.springframework.integration.file.remote.session.SessionFactory;
import org.springframework.integration.ftp.session.DefaultFtpSessionFactory;
@Configuration
public class MyApplicationConfiguration {
  @Autowired
  @Qualifier("myFtpSessionFactory")
  private SessionFactory myFtpSessionFactory;
  @Bean
  public SessionFactory myFtpSessionFactory()
  {
    DefaultFtpSessionFactory ftpSessionFactory = new DefaultFtpSessionFactory();
    ftpSessionFactory.setHost("ftp.abc.org");
    ftpSessionFactory.setClientMode(0);
    ftpSessionFactory.setFileType(0);
    ftpSessionFactory.setPort(21);
    ftpSessionFactory.setUsername("anjju");
    ftpSessionFactory.setPassword("raghu");
    return ftpSessionFactory;
  }

}
```

# 使用 Spring 集成发送文件到 FTP

想象一种情景，你正在通过 FTP 通道发送文件。假设有两个文件，比如`Orders.txt`和`vendors.txt`，需要通过 FTP 发送到远程位置。为了实现这一点，我们需要按照以下步骤进行操作：

1.  创建`FTPChannel`。

1.  使用`baseFolder.mkdirs()`在基本文件夹中创建一个目录。

1.  在基本文件夹位置创建两个文件对象。

1.  使用`InputStream`为订单和供应商创建两个单独的流。

1.  使用 Spring 中可用的文件工具，将输入流复制到它们各自的文件中。

1.  使用`MessageBuilder`类，使用`withpayload()`方法将文件转换为消息。

1.  最后，将消息发送到 FTP 通道并关闭上下文。

让我们写一些示例代码来做到这一点：

```java
public void sendFilesOverFTP() throws Exception{

  ConfigurableApplicationContext ctx = new ClassPathXmlApplicationContext("META-INF/spring/integration/FtpOutboundChannelAdapterSample-context.xml");

  MessageChannel ftpChannel = ctx.getBean("ftpChannel", MessageChannel.class);

  baseFolder.mkdirs();
  final File fileToSendOrders = new File(baseFolder, "orders.txt");
  final File fileToSendVendors = new File(baseFolder, "vendore.txt");

  final InputStream inputStreamOrders = FtpOutboundChannelAdapterSample.class.getResourceAsStream("/test-files/orders.txt");
  final InputStream inputStreamVendors = FtpOutboundChannelAdapterSample.class.getResourceAsStream("/test-files/vendors.txt");
  FileUtils.copyInputStreamToFile(inputStreamOrders, fileToSendOrders);
  FileUtils.copyInputStreamToFile(inputStreamVendors, fileToSendVendors);
  assertTrue(fileToSendOrders.exists());
  assertTrue(fileToSendVendors.exists());
  final Message<File> messageOrders = MessageBuilder.withPayload(fileToSendOrders).build();
  final Message<File> messageVendors = MessageBuilder.withPayload(fileToSendVendors).build();
  ftpChannel.send(messageOrders);
  ftpChannel.send(messageVendors);
  Thread.sleep(2000);
  assertTrue(new File(TestSuite.FTP_ROOT_DIR + File.separator + "orders.txt").exists());
  assertTrue(new File(TestSuite.FTP_ROOT_DIR + File.separator + "vendors.txt").exists());
  LOGGER.info("Successfully transfered file 'orders.txt' and 'vendors.txt' to a remote FTP location.");
  ctx.close();
}
```

## 使用 Spring 集成和 Spring 批处理的 FTP 应用程序

在这一节中，我们将学习如何将 FTP 作为批处理作业。我们将在 Java 中创建一个配置文件，而不是 XML。在这里，我们将使用`@Configuration`注解为 Spring 批处理数据库和 tasklet 设置所有属性。然后我们有一个属性文件，它将为`ApplicationConfiguration.java`文件中的实例变量设置值。使用 Spring 框架中可用的属性持有者模式加载属性。

1.  我们首先要更新配置文件。以下是一个示例配置文件：

```java
@Configuration
public class ApplicationConfiguration {
  //Below is the set of instance variables that will be configured.
  //configuring the jdbc driver
  @Value("${batch.jdbc.driver}")
  private String driverClassName;
  //configuring the jdbc url
  @Value("${batch.jdbc.url}")
  private String driverUrl;

  //configuring the jdbc username
  @Value("${batch.jdbc.user}")
  private String driverUsername;

  //configuring the jdbc passowrd
  @Value("${batch.jdbc.password}")
  private String driverPassword;

  //configuring the jobrepository autowiring the bean
  @Autowired
  @Qualifier("jobRepository")
  private JobRepository jobRepository;

  //configuring the  ftpsessionfactory
  @Autowired
  @Qualifier("myFtpSessionFactory")
  private SessionFactory myFtpSessionFactory;

  @Bean
  public DataSource dataSource() {
    BasicDataSource dataSource = new BasicDataSource();
    dataSource.setDriverClassName(driverClassName);
    dataSource.setUrl(driverUrl);
    dataSource.setUsername(driverUsername);
    dataSource.setPassword(driverPassword);
    return dataSource;
  }
  //setting the ftp as a batch job
  @Bean
  @Scope(value="step")
  public FtpGetRemoteFilesTasklet myFtpGetRemoteFilesTasklet(){
    FtpGetRemoteFilesTasklet  ftpTasklet = new FtpGetRemoteFilesTasklet();
    ftpTasklet.setRetryIfNotFound(true);
    ftpTasklet.setDownloadFileAttempts(3);
    ftpTasklet.setRetryIntervalMilliseconds(10000);
    ftpTasklet.setFileNamePattern("README");
    //ftpTasklet.setFileNamePattern("TestFile");
    ftpTasklet.setRemoteDirectory("/");
    ftpTasklet.setLocalDirectory(new File(System.getProperty("java.io.tmpdir")));
    ftpTasklet.setSessionFactory(myFtpSessionFactory);

    return ftpTasklet;
  }
  //setting the  ftp sessionfactory

  @Bean
  public SessionFactory myFtpSessionFactory() {
    DefaultFtpSessionFactory ftpSessionFactory = new DefaultFtpSessionFactory();
    ftpSessionFactory.setHost("ftp.gnu.org");
    ftpSessionFactory.setClientMode(0);
    ftpSessionFactory.setFileType(0);
    ftpSessionFactory.setPort(21);
    ftpSessionFactory.setUsername("anonymous");
    ftpSessionFactory.setPassword("anonymous");

    return ftpSessionFactory;
  }

  //Configuring the simple JobLauncher
  @Bean
  public SimpleJobLauncher jobLauncher() {
    SimpleJobLauncher jobLauncher = new SimpleJobLauncher();
    jobLauncher.setJobRepository(jobRepository);
    return jobLauncher;
  }

  @Bean
  public PlatformTransactionManager transactionManager() {
    return new DataSourceTransactionManager(dataSource());
  }

}
```

1.  让我们使用`property-placeholder`进一步配置批处理作业。

1.  创建一个名为`batch.properties`的文件：

```java
batch.jdbc.driver=org.hsqldb.jdbcDriver
batch.jdbc.url=jdbc:hsqldb:mem:anjudb;sql.enforce_strict_size=true batch.jdbc.url=jdbc:hsqldb:hsql://localhost:9005/anjdb
batch.jdbc.user=anjana
batch.jdbc.password=raghu
```

1.  在`context.xml`文件或一个单独的文件中配置应用程序，以运行 FTP 的 tasklet：

```java
<batch:job id="ftpJob">
  <batch:step id="step1"  >
  <batch:tasklet ref="myApplicationFtpGetRemoteFilesTasklet" />
  </batch:step>
</batch:job>
```

1.  这里是`MyApplicationFtpGetRemoteFilesTasklet`：

```java
public class MyApplicationFtpGetRemoteFilesTasklet implements Tasklet, InitializingBean {
  private File localDirectory;
  private AbstractInboundFileSynchronizer<?> ftpInboundFileSynchronizer;
  private SessionFactory sessionFactory;
  private boolean autoCreateLocalDirectory = true;
  private boolean deleteLocalFiles = true;
  private String fileNamePattern;
  private String remoteDirectory;
  private int downloadFileAttempts = 12;
  private long retryIntervalMilliseconds = 300000;
  private boolean retryIfNotFound = false;
  /**All the above instance variables have setters and getters*/

  /*After properties are set it just checks for certain instance variables for null values and calls the setupFileSynchronizer method.
    It also checks for local directory if it doesn't exits it auto creates the local directory.
  */
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(sessionFactory, "sessionFactory attribute cannot be null");
    Assert.notNull(localDirectory, "localDirectory attribute cannot be null");
    Assert.notNull(remoteDirectory, "remoteDirectory attribute cannot be null");
    Assert.notNull(fileNamePattern, "fileNamePattern attribute cannot be null");

    setupFileSynchronizer();

    if (!this.localDirectory.exists()) {
      if (this.autoCreateLocalDirectory) {
        if (logger.isDebugEnabled()) {
          logger.debug("The '" + this.localDirectory + "' directory doesn't exist; Will create.");
        }
        this.localDirectory.mkdirs();
      }
      else
      {
        throw new FileNotFoundException(this.localDirectory.getName());
      }
    }
  }
/*This method is called in afterpropertiesset() method. This method checks if we need to transfer files using FTP or SFTP.
If it is SFTP then it initializes ftpInbounFileSynchronizer using SFTPinbounfFileSynchronizer which has a constructor which takes sessionFactory as the argument and has setter method to set file Filter details with FileNamesPatterns.The method also sets the remoteDirectory location..
*/
  private void setupFileSynchronizer() {
    if (isSftp()) {
      ftpInboundFileSynchronizer = new SftpInboundFileSynchronizer(sessionFactory);
      ((SftpInboundFileSynchronizer) ftpInboundFileSynchronizer).setFilter(new SftpSimplePatternFileListFilter(fileNamePattern));
    }
    else
    {
      ftpInboundFileSynchronizer = new FtpInboundFileSynchronizer(sessionFactory);
      ((FtpInboundFileSynchronizer) ftpInboundFileSynchronizer).setFilter(new FtpSimplePatternFileListFilter(fileNamePattern));
    }
    ftpInboundFileSynchronizer.setRemoteDirectory(remoteDirectory);
  }
/*This method is called during the file synchronization process this will delete the files in the directory after copying..
*/
  private void deleteLocalFiles() {
    if (deleteLocalFiles) {
      SimplePatternFileListFilter filter = new SimplePatternFileListFilter(fileNamePattern);
      List<File> matchingFiles = filter.filterFiles(localDirectory.listFiles());
      if (CollectionUtils.isNotEmpty(matchingFiles)) {
        for (File file : matchingFiles) {
          FileUtils.deleteQuietly(file);
        }
      }
    }
  }
/*This is a batch execute method which operates with FTP ,it synchronizes the local directory with the remote directory.
*/
  /* (non-Javadoc)
  * @see org.springframework.batch.core.step.tasklet.Tasklet#execute(org.springframework.batch.core.StepContribution, org.springframework.batch.core.scope.context.ChunkContext)
  */
  public RepeatStatus execute(StepContribution contribution, ChunkContext chunkContext) throws Exception {
    deleteLocalFiles();

    ftpInboundFileSynchronizer.synchronizeToLocalDirectory(localDirectory);

    if (retryIfNotFound) {
      SimplePatternFileListFilter filter = new SimplePatternFileListFilter(fileNamePattern);
      int attemptCount = 1;
      while (filter.filterFiles(localDirectory.listFiles()).size() == 0 && attemptCount <= downloadFileAttempts) {
        logger.info("File(s) matching " + fileNamePattern + " not found on remote site.  Attempt " + attemptCount + " out of " + downloadFileAttempts);
        Thread.sleep(retryIntervalMilliseconds);
        ftpInboundFileSynchronizer.synchronizeToLocalDirectory(localDirectory);
        attemptCount++;
      }

      if (attemptCount >= downloadFileAttempts && filter.filterFiles(localDirectory.listFiles()).size() == 0) {
        throw new FileNotFoundException("Could not find remote file(s) matching " + fileNamePattern + " after " + downloadFileAttempts + " attempts.");
      }
    }

    return null;
  }
```

# 摘要

在本章中，我们看到了 FTP 及其缩写的概述。我们已经看到了不同类型的适配器，比如入站和出站适配器，以及出站网关及其配置。我们还展示了`springs-integration-ftp.xsd`，并引用了每个入站和出站适配器可用的各种选项。我们还展示了使用`spring-integration-ftp`包开发 maven 应用程序所需的库。然后我们看了两个重要的类，`FTPSessionFactory`和`FTPsSessionFactory`，以及它们的 getter 和 setter。我们还演示了使用出站通道的`SpringFTP`传输文件的示例。我们还演示了如何使用 Java 通过`@Configuration`注解配置 FTP。最后，我们演示了 FTP 作为一个 tasklet。在下一章中，我们将进一步探讨 Spring 与 HTTP 的集成。
