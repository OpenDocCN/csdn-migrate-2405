# C++ 反应式编程（三）

> 原文：[`annas-archive.org/md5/e4e6a4bd655b0a85e570c3c31e1be9a2`](https://annas-archive.org/md5/e4e6a4bd655b0a85e570c3c31e1be9a2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：RxCpp - 关键元素

在上一章中，我们介绍了 RxCpp 库及其编程模型。我们编写了一些程序来了解库的工作原理，并介绍了 RxCpp 库的最基本元素。在本章中，我们将深入介绍响应式编程的关键元素，包括以下内容：

+   Observables

+   观察者及其变体（订阅者）

+   主题

+   调度程序

+   操作符

实际上，响应式编程的关键方面如下：

+   Observables 是观察者可以订阅以获取通知的流

+   主题是 Observable 和 Observer 的组合

+   调度程序执行与操作符相关的操作，并帮助数据从 Observables 流向 Observers

+   操作符是接受 Observable 并发出另一个 Observable 的函数（嗯，几乎是！）

# Observables

在上一章中，我们从头开始创建了 Observables 并订阅了这些 Observables。在我们的所有示例中，Observables 创建了`Producer`类的实例（数据）。`Producer`类产生一个事件流。换句话说，Observables 是将订阅者（观察者）连接到生产者的函数。

在我们继续之前，让我们剖析一下 Observable 及其相关的核心活动：

+   Observable 是一个以 Observer 作为参数并返回函数的函数

+   Observable 将 Observer 连接到 Producer（Producer 对 Observer 是不透明的）

+   生产者是 Observable 的值来源

+   观察者是一个具有`on_next`、`on_error`和`on_completed`方法的对象

# 生产者是什么？

简而言之，生产者是 Observable 的值来源。生产者可以是 GUI 窗口、定时器、WebSockets、DOM 树、集合/容器上的迭代器等。它们可以是任何可以成为值来源并传递给 Observer 的值的东西（在`RxCpp`中，`observer.on_next(value)`）。当然，值可以传递给操作符，然后传递给操作符的内部观察者。

# 热 Observable 与冷 Observable

在上一章的大多数示例中，我们看到 Producers 是在 Observable 函数中创建的。生产者也可以在 Observable 函数之外创建，并且可以将对生产者的引用放在 Observable 函数内。引用到在其范围之外创建的生产者的 Observable 称为热 Observable。任何我们在 Observable 中创建了生产者实例的 Observable 称为冷 Observable。为了搞清楚问题，让我们编写一个程序来演示冷 Observable：

```cpp
//---------- ColdObservable.cpp 
#include <rxcpp/rx.hpp> 
#include <memory> 
int main(int argc, char *argv[])  
{
 //----------- Get a Coordination 
 auto eventloop = rxcpp::observe_on_event_loop(); 
 //----- Create a Cold Observable 
 auto values = rxcpp::observable<>::interval( 
               std::chrono::seconds(2)).take(2);
```

在上面的代码中，interval 方法创建了一个冷 Observable，因为事件流的生产者是在`interval`函数中实例化的。当订阅者或观察者附加到冷 Observable 时，它将发出数据。即使在两个观察者之间订阅存在延迟，结果也将是一致的。这意味着我们将获得 Observable 发出的所有数据的两个观察者：

```cpp
 //----- Subscribe Twice

values.subscribe_on(eventloop). 
    subscribe([](int v){printf("[1] onNext: %dn", v);}, 
        [](){printf("[1] onCompleted\n");}); 
 values.subscribe_on(eventloop). 
    subscribe([](int v){printf("[2] onNext: %dn", v);}, 
        [](){printf("[2] onCompleted\n");}); 
  //---- make a blocking subscription to see the results 
 values.as_blocking().subscribe(); 
 //----------- Wait for Two Seconds 
 rxcpp::observable<>::timer(std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 
} 
```

程序发出的输出如下。对于每次运行，控制台中内容的顺序可能会改变，因为我们在同一线程中调度执行观察者方法。但是，由于订阅延迟，不会有数据丢失：

```cpp
[1] onNext: 1 
[2] onNext: 1 
[2] onNext: 2 
[1] onNext: 2 
[2] onCompleted 
[1] onCompleted 
```

# 热 Observable

我们可以通过调用 Observable 的`publish`方法将冷 Observable 转换为热 Observable。将冷 Observable 转换为热 Observable 的后果是数据可能会被后续的订阅所错过。热 Observable 会发出数据，无论是否有订阅。以下程序演示了这种行为：

```cpp
//---------- HotObservable.cpp

#include <rxcpp/rx.hpp> 
#include <memory> 
int main(int argc, char *argv[]) { 
 auto eventloop = rxcpp::observe_on_event_loop(); 
 //----- Create a Cold Observable 
 //----- Convert Cold Observable to Hot Observable  
 //----- using .Publish(); 
 auto values = rxcpp::observable<>::interval( 
               std::chrono::seconds(2)).take(2).publish();   
 //----- Subscribe Twice 
 values. 
    subscribe_on(eventloop). 
    subscribe( 
        [](int v){printf("[1] onNext: %dn", v);}, 
        [](){printf("[1] onCompletedn");}); 
  values. 
    subscribe_on(eventloop). 
    subscribe( 
        [](int v){printf("[2] onNext: %dn", v);}, 
        [](){printf("[2] onCompletedn");}); 
 //------ Connect to Start Emitting Values 
 values.connect(); 
 //---- make a blocking subscription to see the results 
 values.as_blocking().subscribe(); 
 //----------- Wait for Two Seconds 
 rxcpp::observable<>::timer( 
       std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 
} 
```

在下一个示例中，我们将看一下`RxCpp 库`支持的`publish_synchronized`机制。从编程接口的角度来看，这只是一个小改变。看一下以下程序：

```cpp
//---------- HotObservable2.cpp 
#include <rxcpp/rx.hpp> 
#include <memory> 

int main(int argc, char *argv[]) { 

 auto eventloop = rxcpp::observe_on_event_loop(); 
 //----- Create a Cold Observable 
 //----- Convert Cold Observable to Hot Observable  
 //----- using .publish_synchronized(); 
 auto values = rxcpp::observable<>::interval( 
               std::chrono::seconds(2)). 
               take(5).publish_synchronized(eventloop);   
 //----- Subscribe Twice 
 values. 
    subscribe( 
        [](int v){printf("[1] onNext: %dn", v);}, 
        [](){printf("[1] onCompletedn");}); 

 values. 
    subscribe( 
        [](int v){printf("[2] onNext: %dn", v);}, 
        [](){printf("[2] onCompletedn");}); 

 //------ Start Emitting Values 
 values.connect(); 
 //---- make a blocking subscription to see the results 
 values.as_blocking().subscribe(); 

 //----------- Wait for Two Seconds 
 rxcpp::observable<>::timer( 
       std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 
} 
```

程序的输出如下。我们可以看到输出很好地同步，即输出按正确的顺序显示：

```cpp
[1] onNext: 1 
[2] onNext: 1 
[1] onNext: 2 
[2] onNext: 2 
[1] onNext: 3 
[2] onNext: 3 
[1] onNext: 4 
[2] onNext: 4 
[1] onNext: 5 
[2] onNext: 5 
[1] onCompleted 
[2] onCompleted
```

# 热可观察对象和重放机制

热可观察对象会发出数据，无论是否有订阅者可用。这在我们期望订阅者持续接收数据的情况下可能会成为问题。在响应式编程中有一种机制可以缓存数据，以便稍后的订阅者可以被通知可观察对象的可用数据。我们可以使用`.replay()`方法来创建这样的可观察对象。让我们编写一个程序来演示重放机制，这在编写涉及热可观察对象的程序时非常有用：

```cpp
//---------- ReplayAll.cpp 
#include <rxcpp/rx.hpp> 
#include <memory> 
int main(int argc, char *argv[]) { 

  auto values = rxcpp::observable<>::interval( 
                std::chrono::milliseconds(50),  
                rxcpp::observe_on_new_thread()). 
                take(5).replay(); 
    // Subscribe from the beginning 
    values.subscribe( 
        [](long v){printf("[1] OnNext: %ldn", v);}, 
        [](){printf("[1] OnCompletedn");}); 
    // Start emitting 
    values.connect(); 
    // Wait before subscribing 
    rxcpp::observable<>::timer( 
         std::chrono::milliseconds(125)).subscribe(&{ 
        values.as_blocking().subscribe( 
            [](long v){printf("[2] OnNext: %ldn", v);}, 
            [](){printf("[2] OnCompletedn");}); 
    }); 
 //----------- Wait for Two Seconds 
 rxcpp::observable<>::timer( 
       std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 

} 
```

在编写响应式程序时，您确实需要了解热和冷可观察对象之间的语义差异。我们只是涉及了这个主题的一些方面。请参考 RxCpp 文档和 ReactiveX 文档以了解更多关于热和冷可观察对象的信息。互联网上有无数关于这个主题的文章。

# 观察者及其变体（订阅者）

观察者订阅可观察对象并等待事件通知。观察者已经在上一章中介绍过了。因此，我们将专注于订阅者，它们是观察者和订阅的组合。订阅者有取消订阅观察者的功能，而“普通”观察者只能订阅。以下程序很好地解释了这些概念：

```cpp
//---- Subscriber.cpp 
#include "rxcpp/rx.hpp" 
int main() { 
     //----- create a subscription object 
     auto subscription = rxcpp::composite_subscription(); 
     //----- Create a Subscription  
     auto subscriber = rxcpp::make_subscriber<int>( 
        subscription, 
        &{ 
            printf("OnNext: --%dn", v); 
            if (v == 3) 
                subscription.unsubscribe(); // Demonstrates Un Subscribes 
        }, 
        [](){ printf("OnCompletedn");}); 

    rxcpp::observable<>::create<int>( 
        [](rxcpp::subscriber<int> s){ 
            for (int i = 0; i < 5; ++i) { 
                if (!s.is_subscribed())  
                    break; 
                s.on_next(i); 
           } 
            s.on_completed();   
    }).subscribe(subscriber); 
    return 0; 
} 
```

对于使用并发和动态性（异步时间变化事件）编写复杂程序，订阅和取消订阅的能力非常方便。通过查阅 RxCpp 文档来更深入地了解这个主题。

# 主题

主题是既是观察者又是可观察对象的实体。它有助于从一个可观察对象（通常）传递通知给一组观察者。我们可以使用主题来实现诸如缓存和数据缓冲之类的复杂技术。我们还可以使用主题将热可观察对象转换为冷可观察对象。在`RxCpp 库`中实现了四种主题的变体。它们如下：

+   `SimpleSubject`

+   行为主题

+   `ReplaySubject`

+   `SynchronizeSubject`

让我们编写一个简单的程序来演示主题的工作。代码清单将演示如何将数据推送到主题并使用主题的观察者端检索它们。

```cpp
//------- SimpleSubject.cpp 
#include <rxcpp/rx.hpp> 
#include <memory> 
int main(int argc, char *argv[]) { 
    //----- Create an instance of Subject 
    rxcpp::subjects::subject<int> subject; 
    //----- Retreive the Observable  
    //----- attached to the Subject 
    auto observable = subject.get_observable(); 
    //------ Subscribe Twice 
    observable.subscribe( [] ( int v ) { printf("1------%dn",v ); }); 
    observable.subscribe( [] ( int v ) { printf("2------%dn",v );}); 
    //--------- Get the Subscriber Interface 
    //--------- Attached to the Subject 
    auto subscriber = subject.get_subscriber(); 
    //----------------- Emit Series of Values 
    subscriber.on_next(1); 
    subscriber.on_next(4); 
    subscriber.on_next(9); 
    subscriber.on_next(16); 
    //----------- Wait for Two Seconds 
    rxcpp::observable<>::timer(std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 
}
```

`BehaviorSubject`是 Subject 的一种变体，它作为其实现的一部分存储最后发出的（当前）值。任何新的订阅者都会立即获得*当前值*。否则，它的行为就像一个普通的 Subject。`BehaviorSubject`在某些领域中也被称为属性或单元。它在我们更新特定单元或内存区域的一系列数据时非常有用，比如在事务上下文中。让我们编写一个程序来演示`BehaviorSubject`的工作原理：

```cpp
//-------- BehaviorSubject.cpp 
#include <rxcpp/rx.hpp> 
#include <memory> 

int main(int argc, char *argv[]) { 

    rxcpp::subjects::behavior<int> behsubject(0); 

    auto observable = behsubject.get_observable(); 
    observable.subscribe( [] ( int v ) { 
        printf("1------%dn",v ); 
     }); 

     observable.subscribe( [] ( int v ) { 
        printf("2------%dn",v ); 
     }); 

    auto subscriber = behsubject.get_subscriber(); 
    subscriber.on_next(1); 
    subscriber.on_next(2); 

    int n = behsubject.get_value(); 

    printf ("Last Value ....%dn",n); 

} 
```

`ReplaySubject`是 Subject 的一种变体，它存储已经发出的数据。我们可以指定参数来指示主题必须保留多少个值。在处理热可观察对象时，这非常方便。各种重放重载的函数原型如下：

```cpp
replay (Coordination cn,[optional] composite_subscription cs) 
replay (std::size_t count, Coordination cn, [optional]composite_subscription cs) 
replay (duration period, Coordination cn, [optional] composite_subscription cs) 
replay (std::size_t count, duration period, Coordination cn,[optional] composite_subscription cs).
```

让我们编写一个程序来理解`ReplaySubject`的语义：

```cpp
//------------- ReplaySubject.cpp 
#include <rxcpp/rx.hpp> 
#include <memory> 
int main(int argc, char *argv[]) { 
    //----------- instantiate a ReplaySubject 
    rxcpp::subjects::replay<int,rxcpp::observe_on_one_worker>       
           replay_subject(10,rxcpp::observe_on_new_thread()); 
    //---------- get the observable interface 
    auto observable = replay_subject.get_observable(); 
    //---------- Subscribe! 
    observable.subscribe( [] ( int v ) {printf("1------%dn",v );}); 
    //--------- get the subscriber interface 
    auto subscriber = replay_subject.get_subscriber(); 
    //---------- Emit data  
    subscriber.on_next(1); 
    subscriber.on_next(2); 
    //-------- Add a new subscriber 
    //-------- A normal subject will drop data 
    //-------- Replay subject will not 
    observable.subscribe( [] ( int v ) {  printf("2------%dn",v );}); 
     //----------- Wait for Two Seconds 
    rxcpp::observable<>::timer( 
       std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 
} 
```

在本节中，我们介绍了主题的三种变体。主要用例是通过使用可观察接口从不同来源获取事件和数据，并允许一组订阅者消耗获取的数据。`SimpleSubject`可以作为可观察对象和观察者来处理一系列值。`BehaviorSubject`用于监视一段时间内属性或变量的变化，而`ReplaySubject`将帮助您避免由于订阅延迟而导致的数据丢失。最后，`SynchronizeSubject`是一个具有同步逻辑的主题。

# 调度器

`RxCpp`库拥有一个声明性的线程机制，这要归功于其内置的强大调度子系统。从一个 Observable 中，数据可以通过不同的路径流经变化传播图。通过给流处理管道提供提示，我们可以在相同线程、不同线程或后台线程中安排操作符和观察者方法的执行。这有助于更好地捕捉程序员的意图。

`RxCpp`中的声明性调度模型是可能的，因为操作符实现中的流是不可变的。流操作符将一个 Observable 作为参数，并返回一个新的 Observable 作为结果。输入参数根本没有被改变（这种行为从操作符的实现中隐含地期望）。这有助于无序执行。`RxCpp`的调度子系统包含以下构造（特定于 Rxcpp v2）：

+   调度程序

+   Worker

+   协调

+   协调员

+   可调度的

+   时间线

`RxCpp`的第 2 版从`RxJava`系统中借用了其调度架构。它依赖于`RxJava`使用的调度程序和 Worker 习语。以下是关于调度程序的一些重要事实：

+   调度程序有一个时间线。

+   调度程序可以在时间线上创建许多 Worker。

+   Worker 拥有时间线上的可调度队列。

+   `schedulable`拥有一个函数（通常称为`Action`）并拥有生命周期。

+   `Coordination`函数作为协调员的工厂，并拥有一个调度程序。

+   每个协调员都有一个 Worker，并且是以下内容的工厂：

+   协调的`schedulable`

+   协调的 Observables 和订阅者

我们一直在程序中使用 Rx 调度程序，而不用担心它们在幕后是如何工作的。让我们编写一个玩具程序，来帮助我们理解调度程序在幕后是如何工作的：

```cpp
//------------- SchedulerOne.cpp 
#include "rxcpp/rx.hpp" 
int main(){ 
    //---------- Get a Coordination  
    auto Coordination function= rxcpp::serialize_new_thread(); 
    //------- Create a Worker instance  through a factory method  
    auto worker = coordination.create_coordinator().get_worker(); 
    //--------- Create a action object 
    auto sub_action = rxcpp::schedulers::make_action( 
         [] (const rxcpp::schedulers::schedulable&) {   
          printf("Action Executed in Thread # : %dn",  
          std::this_thread::get_id());   
          } );  
    //------------- Create a schedulable and schedule the action 
    auto scheduled = rxcpp::schedulers::make_schedulable(worker,sub_action); 
    scheduled.schedule(); 
    return 0; 
} 
```

在`RxCpp`中，所有接受多个流作为输入或涉及对时间有影响的任务的操作符都将`Coordination`函数作为参数。一些使用特定调度程序的`Coordination`函数如下：

+   `identity_immediate()`

+   `identity_current_thread()`

+   `identity_same_worker(worker w)`

+   `serialize_event_loop()`

+   `serialize_new_thread()`

+   `serialize_same_worker(worker w)`

+   `observe_on_event_loop()`

+   `observe_on_new_thread()`

在前面的程序中，我们手动安排了一个操作（实际上只是一个 lambda）。让我们继续调度程序的声明方面。我们将编写一个使用`Coordination`函数安排任务的程序：

```cpp
//----------- SchedulerTwo.cpp 
#include "rxcpp/rx.hpp" 
int main(){ 
    //-------- Create a Coordination function 
    auto Coordination function= rxcpp::identity_current_thread(); 
    //-------- Instantiate a coordinator and create a worker     
    auto worker = coordination.create_coordinator().get_worker(); 
    //--------- start and the period 
    auto start = coordination.now() + std::chrono::milliseconds(1); 
    auto period = std::chrono::milliseconds(1);      
    //----------- Create an Observable (Replay ) 
    auto values = rxcpp::observable<>::interval(start,period). 
    take(5).replay(2, coordination); 
    //--------------- Subscribe first time using a Worker 
    worker.schedule(&{ 
       values.subscribe( [](long v){ printf("#1 -- %d : %ldn",  
                   std::this_thread::get_id(),v);  }, 
                        [](){ printf("#1 --- OnCompletedn");}); 
    }); 
    worker.schedule(&{ 
      values.subscribe( [](long v){printf("#2 -- %d : %ldn",  
                   std::this_thread::get_id(),v); }, 
                     [](){printf("#2 --- OnCompletedn");});  
    }); 
    //----- Start the emission of values  
   worker.schedule(& 
   { values.connect();}); 
   //------- Add blocking subscription to see results 
   values.as_blocking().subscribe(); return 0; 
}
```

我们使用重放机制创建了一个热 Observable 来处理一些观察者的延迟订阅。我们还创建了一个 Worker 来进行订阅的调度，并将观察者与 Observable 连接起来。前面的程序演示了`RxCpp`中调度程序的工作原理。

# ObserveOn 与 SubscribeOn

`ObserveOn`和`SubscribeOn`操作符的行为方式不同，这一直是反应式编程新手困惑的来源。`ObserveOn`操作符改变了其下方的操作符和观察者的线程。而`SubscribeOn`则影响其上方和下方的操作符和方法。以下程序演示了`SubscribeOn`和`ObserveOn`操作符的行为方式对程序运行时行为的微妙变化。让我们编写一个使用`ObserveOn`操作符的程序：

```cpp
//-------- ObservableOnScheduler.cpp 
#include "rxcpp/rx.hpp" 
int main(){ 
    //------- Print the main thread id 
    printf("Main Thread Id is %dn",  
             std::this_thread::get_id()); 
    //-------- We are using observe_on here 
    //-------- The Map will use the main thread 
    //-------- Subscribed Lambda will use a new thread 
    rxcpp::observable<>::range(0,15). 
        map([](int i){ 
            printf("Map %d : %dn", std::this_thread::get_id(),i);  
            return i; }). 
        take(5).observe_on(rxcpp::synchronize_new_thread()). 
        subscribe(&{ 
           printf("Subs %d : %dn", std::this_thread::get_id(),i);  
        }); 
    //----------- Wait for Two Seconds 
    rxcpp::observable<>::timer( 
       std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 

    return 0; 
}
```

前述程序的输出如下：

```cpp
Main Thread Id is 1 
Map 1 : 0 
Map 1 : 1 
Subs 2 : 0 
Map 1 : 2 
Subs 2 : 1 
Map 1 : 3 
Subs 2 : 2 
Map 1 : 4 
Subs 2 : 3 
Subs 2 : 4 
```

前述程序的输出清楚地显示了`map`在主线程中工作，而`subscribe`方法在次要线程中被调度。这清楚地表明`ObserveOn`只对其下方的操作符和订阅者起作用。让我们编写一个几乎相同的程序，使用`SubscribeOn`操作符而不是`ObserveOn`操作符。看一下这个：

```cpp
//-------- SubscribeOnScheduler.cpp 
#include "rxcpp/rx.hpp" 
int main(){ 
    //------- Print the main thread id 
    printf("Main Thread Id is %dn",  
             std::this_thread::get_id()); 
    //-------- We are using subscribe_on here 
    //-------- The Map and subscribed Lambda will  
    //--------- use the secondary thread 
    rxcpp::observable<>::range(0,15). 
        map([](int i){ 
            printf("Map %d : %dn", std::this_thread::get_id(),i);  
            return i; 
        }). 
        take(5).subscribe_on(rxcpp::synchronize_new_thread()). 
        subscribe(&{ 
           printf("Subs %d : %dn", std::this_thread::get_id(),i);  
        }); 
    //----------- Wait for Two Seconds 
    rxcpp::observable<>::timer( 
       std::chrono::milliseconds(2000)). 
       subscribe(&{ }); 

    return 0; 
}
```

前述程序的输出如下：

```cpp
Main Thread Id is 1 
Map 2 : 0 
Subs 2 : 0 
Map 2 : 1 
Subs 2 : 1 
Map 2 : 2 
Subs 2 : 2 
Map 2 : 3 
Subs 2 : 3 
Map 2 : 4 
Subs 2 : 4 
```

前述程序的输出显示 map 和订阅方法都在次要线程中工作。这清楚地显示了`SubscribeOn`改变了它之前和之后的项目的线程行为。

# RunLoop 调度程序

RxCpp 库没有内置的主线程调度程序的概念。你能做的最接近的是利用`run_loop`类来模拟在主线程中进行调度。在下面的程序中，Observable 在后台线程执行，订阅方法在主线程运行。我们使用`subscribe_on`和`observe_on`来实现这个目标：

```cpp
//------------- RunLoop.cpp 
#include "rxcpp/rx.hpp" 
int main(){ 
    //------------ Print the Main Thread Id 
    printf("Main Thread Id is %dn",  
                std::this_thread::get_id()); 
    //------- Instantiate a run_loop object 
    //------- which will loop in the main thread 
    rxcpp::schedulers::run_loop rlp; 
    //------ Create a Coordination functionfor run loop 
    auto main_thread = rxcpp::observe_on_run_loop(rlp); 
    auto worker_thread = rxcpp::synchronize_new_thread(); 
    rxcpp::composite_subscription scr; 
    rxcpp::observable<>::range(0,15). 
        map([](int i){ 
            //----- This will get executed in worker 
            printf("Map %d : %dn", std::this_thread::get_id(),i);  
            return i; 
        }).take(5).subscribe_on(worker_thread). 
        observe_on(main_thread). 
        subscribe(scr, &{ 
            //--- This will get executed in main thread 
            printf("Sub %d : %dn", std::this_thread::get_id(),i); }); 
    //------------ Execute the Run Loop 
    while (scr.is_subscribed() || !rlp.empty()) { 
        while (!rlp.empty() && rlp.peek().when < rlp.now()) 
        { rlp.dispatch();} 
    }  
    return 0; 
} 
```

前述程序的输出如下：

```cpp
Main Thread Id is 1 
Map 2 : 0 
Map 2 : 1 
Sub 1 : 0 
Sub 1 : 1 
Map 2 : 2 
Map 2 : 3 
Sub 1 : 2 
Map 2 : 4 
Sub 1 : 3 
Sub 1 : 4 
```

我们可以看到 map 被调度在工作线程中，订阅方法在主线程中执行。这是因为我们巧妙地放置了 subscribe_on 和 observe_on 运算符，这是我们在前一节中介绍的。

# 运算符

运算符是应用于 Observable 以产生新的 Observable 的函数。在这个过程中，原始 Observable 没有被改变，并且可以被认为是一个纯函数。我们已经在我们编写的示例程序中涵盖了许多运算符。在[第十章](https://cdp.packtpub.com/c___reactive_programming/wp-admin/post.php?post=79&action=edit#post_86)中，*在 Rxcpp 中创建自定义运算符*，我们将学习如何创建在 Observables 上工作的自定义运算符。运算符不改变（输入）Observable 的事实是声明式调度在 Rx 编程模型中起作用的原因。Rx 运算符可以被分类如下：

+   创建运算符

+   变换运算符

+   过滤运算符

+   组合运算符

+   错误处理运算符

+   实用运算符

+   布尔运算符

+   数学运算符

还有一些更多的运算符不属于这些类别。我们将提供一个来自前述类别的关键运算符列表，作为一个快速参考的表格。作为开发人员，可以根据上面给出的表格来选择运算符，根据上下文来选择运算符。

# 创建运算符

这些运算符将帮助开发人员从输入数据中创建各种类型的 Observables。我们已经在我们的示例代码中演示了 create、from、interval 和 range 运算符的使用。请参考这些示例和 RxCpp 文档以了解更多信息。下面给出了一张包含一些运算符的表格：

| **Observables** | **描述** |
| --- | --- |
| `create` | 通过以编程方式调用 Observer 方法创建一个 Observable |
| `defer` | 为每个 Observer/Subscriber 创建一个新的 Observable |
| `empty` | 创建一个不发出任何内容的 Observable（只在完成时发出） |
| `from` | 根据参数创建一个 Observable（多态） |
| `interval` | 创建一个在时间间隔内发出一系列值的 Observable |
| `just` | 创建一个发出单个值的 Observable |
| `range` | 创建一个发出一系列值的 Observable |
| `never` | 创建一个永远不发出任何内容的 Observable |
| `repeat` | 创建一个重复发出值的 Observable |
| `timer` | 创建一个在延迟因子之后发出值的 Observable，可以将其指定为参数 |
| `throw` | 创建一个发出错误的 Observable |

# 变换运算符

这些运算符帮助开发人员创建一个新的 Observable，而不修改源 Observable。它们通过在源 Observable 上应用 lambda 或函数对象来作用于源 Observable 中的单个项目。下面给出了一张包含一些最有用的变换运算符的表格。

| **Observables** | **描述** |
| --- | --- |
| `buffer` | 收集过去的值并在收到信号时发出的 Observable |
| `flat_map` | 发出应用于源 Observable 和集合 Observable 发出的一对值的函数的结果的 Observable |
| `group_by` | 帮助从 Observable 中分组值的 Observable |
| `map` | 通过指定的函数转换源 Observable 发出的项目的 Observable |
| `scan` | 发出累加器函数的每次调用的结果的 Observable |
| `window` | 发出连接的、不重叠的项目窗口的 Observable。 每个窗口将包含特定数量的项目，该数量作为参数给出。 参数名为 count。 |

# 过滤运算符

过滤流的能力是流处理中的常见活动。 Rx 编程模型定义了许多过滤类别的运算符并不罕见。 过滤运算符主要是谓词函数或 lambda。 以下表格包含过滤运算符的列表：

| **Observables** | **Description** |
| --- | --- |
| `debounce` | 如果经过一段特定的时间间隔而没有从源 Observable 发出另一个项目，则发出一个项目的 Observable |
| `distinct` | 发出源 Observable 中不同的项目的 Observable |
| `element_at` | 发出位于指定索引位置的项目的 Observable |
| `filter` | 只发出由过滤器评估为 true 的源 Observable 发出的项目的 Observable |
| `first` | 只发出源 Observable 发出的第一个项目的 Observable |
| `ignore_eleements` | 从源 Observable 发出终止通知的 Observable |
| `last` | 只发出源 Observable 发出的最后一个项目的 Observable |
| `sample` | 在周期时间间隔内发出源 Observable 发出的最近的项目的 Observable |
| `skip` | 与源 Observable 相同的 Observable，只是它不会发出源 Observable 发出的前 t 个项目 |
| `skip_last` | 与源 Observable 相同的 Observable，只是它不会发出源 Observable 发出的最后 t 个项目 |
| `take` | 只发出源 Observable 发出的前 t 个项目，或者如果该 Observable 发出的项目少于 t 个，则发出源 Observable 的所有项目 |
| `take_last` | 只发出源 Observable 发出的最后 t 个项目的 Observable |

# 组合运算符

Rx 编程模型的主要目标之一是将事件源与事件接收器解耦。 显然，需要能够组合来自各种来源的流的运算符。 RxCpp 库实现了一组此类运算符。 以下表格概述了一组常用的组合运算符：

| **Observables** | **Description** |
| --- | --- |
| `combine_latest` | 当两个 Observables 中的任一 Observable 发出项目时，通过指定的函数组合每个 Observable 发出的最新项目，并根据该函数的结果发出项目 |
| `merge` | 通过合并它们的发射将多个 Observables 合并为一个 |
| `start_with` | 在开始发出源 Observable 的项目之前，发出指定的项目序列 |
| `switch_on_next` | 将发出 Observables 的 Observable 转换为发出最近发出的 Observable 发出的项目的单个 Observable |
| `zip` | 通过指定的函数将多个 Observables 的发射组合在一起，并根据该函数的结果发出每个组合的单个项目 |

# 错误处理运算符

这些是在管道执行过程中发生异常时帮助我们进行错误恢复的运算符。

| **Observables** | **Description** |
| --- | --- |
| `Catch` | `RxCpp`不支持 |
| `retry` | 如果调用`on_error`，则会重新订阅源 Observable 的 Observable，最多重试指定次数 |

# Observable 实用程序运算符

以下是用于处理 Observables 的有用实用程序运算符工具箱： observe_on 和 subscribe_on 运算符帮助我们进行声明式调度。 我们已经在上一章中介绍过它们。

| **Observables** | **Description** |
| --- | --- |
| `finally` | Observable 发出与源 Observable 相同的项目，然后调用给定的操作 |
| `observe_on` | 指定观察者将观察此 Observable 的调度程序 |
| `subscribe` | 对 Observable 的发射和通知进行操作 |
| `subscribe_on` | 指定 Observable 订阅时应使用的调度程序 |
| `scope` | 创建与 Observable 寿命相同的一次性资源 |

# 条件和布尔运算符

条件和布尔运算符是评估一个或多个 Observable 或 Observable 发出的项目的运算符：

| **Observables** | **Description** |
| --- | --- |
| `all` | 如果源 Observable 发出的每个项目都满足指定条件，则发出 true 的 Observable；否则，它发出 false |
| `amb` | Observable 发出与源 Observables 中首先发出项目或发送终止通知的相同序列 |
| `contains` | 如果源 Observable 发出了指定的项目，则发出 true 的 Observable；否则发出 false |
| `default_if_empty` | 如果源 Observable 发出了指定的项目，则发出 true 的 Observable；否则发出 false |
| `sequence_equal` | 只有在发出相同顺序的相同项目序列后正常终止时，Observable 才会发出 true；否则，它将发出 false |
| `skip_until` | 直到第二个 Observable 发出项目之前，丢弃由 Observable 发出的项目 |
| `skip_while` | 直到指定条件变为 false 后，丢弃由 Observable 发出的项目 |
| `take_until` | 在第二个 Observable 发出项目或终止后，丢弃由 Observable 发出的项目 |
| `take_while` | 在指定条件变为 false 后，丢弃由 Observable 发出的项目 |

# 数学和聚合运算符

这些数学和聚合运算符是一类操作符，它们对 Observable 发出的整个项目序列进行操作：它们基本上将 Observable<T>减少为类型 T 的某个值。它们不会返回 Observable。

| **Observables** | **Description** |
| --- | --- |
| `average` | 计算 Observable 发出的数字的平均值并发出此平均值 |
| `concat` | 发出两个或多个 Observable 的发射，而不对它们进行交错 |
| `count` | 计算源 Observable 发出的项目数量并仅发出此值 |
| `max` | 确定并发出 Observable 发出的最大值项目 |
| `min` | 确定并发出 Observable 发出的最小值项目 |
| `reduce` | 对 Observable 发出的每个项目依次应用函数，并发出最终值 |
| `sum` | 计算 Observable 发出的数字的总和并发出此总和 |

# 可连接的 Observable 运算符

可连接的 Observable 是具有更精确控制的订阅动态的特殊 Observable。以下表格列出了一些具有高级订阅语义的关键运算符

| **Observables** | **Description** |
| --- | --- |
| `connect` | 指示可连接的 Observable 开始向其订阅者发出项目 |
| `publish` | 将普通 Observable 转换为可连接的 Observable |
| `ref_count` | 使可连接的 Observable 表现得像普通的 Observable |
| `replay` | 确保所有观察者看到相同的发出项目序列，即使它们在 Observable 开始发出项目后订阅。此运算符与热 Observable 一起使用 |

# 摘要

在本章中，我们了解了 Rx 编程模型的各个部分是如何配合的。我们从 Observables 开始，迅速转移到热和冷 Observables 的主题。然后，我们讨论了订阅机制及其使用。接着，我们转向了 Subjects 这一重要主题，并了解了多种 Scheduler 实现的工作方式。最后，我们对 RxCpp 系统中提供的各种操作符进行了分类。在下一章中，我们将学习如何利用迄今为止所学的知识，以一种反应式的方式使用 Qt 框架编写 GUI 程序。


# 第九章：使用 Qt/C++进行响应式 GUI 编程

Qt（发音为可爱）生态系统是一个全面的基于 C++的框架，用于编写跨平台和多平台 GUI 应用程序。如果您使用库的可移植核心编写程序，可以利用该框架支持的“一次编写，到处编译”范式。在某些情况下，人们使用特定于平台的功能，例如支持 ActiveX 编程模型以编写基于 Windows 的应用程序。

我们遇到了一些情况，Qt 在 Windows 上编写应用程序时优于 MFC。这可能是因为编程简单，因为 Qt 仅使用 C++语言特性的一个非常小的子集来构建其库。该框架的最初目标当然是跨平台开发。Qt 在各个平台上的单一源可移植性、功能丰富性、源代码的可用性以及完善的文档使其成为一个非常友好的框架。这些特点使其在 1995 年首次发布以来，已经繁荣了二十多年。

Qt 提供了一个完整的接口环境，支持开发多平台 GUI 应用程序、Webkit API、媒体流、文件系统浏览器、OpenGL API 等。涵盖这个精彩库的全部功能需要一本专门的书。本章的目的是介绍如何通过利用 Qt 和 RxCpp 库来编写响应式 GUI 应用程序。我们已经在第七章“数据流计算和 RxCpp 库介绍”和第八章“RxCpp - 关键元素”中介绍了响应式编程模型的核心。现在是时候将我们在前几章中学到的知识付诸实践了！Qt 框架本身具有强大的事件处理系统，人们需要学习这些库特性，然后才能将 RxCpp 构造整合到其中。

在本章中，我们将探讨：

+   Qt GUI 编程的快速介绍

+   Hello World - Qt 程序

+   Qt 事件模型，使用信号/槽/MOC - 一个例子

+   将 RxCpp 库与 Qt 事件模型集成

+   在 Rxcpp 中创建自定义操作符

# Qt GUI 编程的快速介绍

Qt 是一个跨平台应用程序开发框架，用于编写可以在多个平台上作为本机应用程序运行的软件，而无需更改太多代码，具有本机平台功能和速度。除了 GUI 应用程序，我们还可以使用该框架编写控制台或命令行应用程序，但主要用例是图形用户界面。

尽管使用 Qt 编写的应用程序通常是用 C++编写的，但也存在 QML 绑定到其他语言的情况。Qt 简化了 C++开发的许多方面，使用了全面而强大的 API 和工具。Qt 支持许多编译器工具链，如 GCC C++编译器和 Visual C++编译器。Qt 还提供了 Qt Quick（包括 QML，一种基于 ECMAScript 的声明性脚本语言）来编写逻辑。这有助于快速开发移动平台应用程序，尽管逻辑可以使用本机代码编写以获得最佳性能。ECMAScript/C++组合提供了声明式开发和本机代码速度的最佳结合。

Qt 目前由 The Qt Company 开发和维护，并且该框架可用于开源和专有许可证。刚开始时，Qt 使用自己的绘图引擎和控件来模拟不同平台的外观和感觉（由于自定义绘图引擎，可以在 GNU Linux 下创建 Windows 的外观和感觉）。这有助于开发人员轻松地跨平台移植，因为目标平台依赖性很小。由于模拟不完美，Qt 开始使用平台的本机样式 API，以及自己的本机小部件集。这解决了 Qt 自己的绘图引擎模拟的问题，但代价是在各个平台上不再具有统一的外观和感觉。Qt 库与 Python 编程语言有很好的绑定，被称为 PyQt。

在程序员利用库之前，有一些基本的东西程序员必须了解。在接下来的几节中，我们将快速介绍 Qt 对象模型、信号和槽、事件系统和元对象系统的方面。

# Qt 对象模型

在 GUI 框架中，运行时效率和高级灵活性是关键因素。标准 C++对象模型提供了非常高效的运行时支持，但其静态性在某些问题领域是不灵活的。Qt 框架将 C++的速度与 Qt 对象模型的灵活性结合起来。

Qt 对象模型支持以下功能：

+   **信号和槽**，用于无缝对象通信

+   可查询和可设计的**对象属性**

+   强大的事件和事件过滤器

+   强大的内部驱动定时器，实现在事件驱动的 GUI 中许多任务的平滑、非阻塞工作

+   **国际化**与上下文字符串翻译

+   受保护的指针（**QPointers**），当引用的对象被销毁时自动设置为 0

+   跨库边界工作的**动态转换**

其中许多功能是作为标准 C++类实现的，基于从`QObject`继承。其他功能，如信号和槽以及对象属性系统，需要 Qt 自己的**元对象编译器**（**MOC**）提供的元对象系统。元对象系统是 C++语言的扩展，使其更适合 GUI 编程。MOC 充当预编译器，根据源代码中嵌入的提示生成代码，并删除这些提示，以便 ANSI C++编译器执行其正常的编译任务。

让我们来看看 Qt 对象模型中的一些类：

| **类名** | **描述** |
| --- | --- |
| `QObject` | 所有 Qt 对象的基类（[`doc.qt.io/archives/qt-4.8/qobject.html`](http://doc.qt.io/archives/qt-4.8/qobject.html)） |
| `QPointer` | 为`QObject`提供受保护指针的模板类（[`doc.qt.io/archives/qt-4.8/qpointer.html`](http://doc.qt.io/archives/qt-4.8/qpointer.html)） |
| `QSignalMapper` | 将可识别发送者的信号捆绑在一起（[`doc.qt.io/archives/qt-4.8/qsignalmapper.html`](http://doc.qt.io/archives/qt-4.8/qsignalmapper.html)） |
| `QVariant` | 作为最常见的 Qt 数据类型的联合体（[`doc.qt.io/archives/qt-4.8/qvariant.html`](http://doc.qt.io/archives/qt-4.8/qvariant.html)） |
| `QMetaClassInfo` | 类的附加信息（[`doc.qt.io/archives/qt-4.8/qmetaclassinfo.html`](http://doc.qt.io/archives/qt-4.8/qmetaclassinfo.html)） |
| `QMetaEnum` | 枚举类型的元数据（[`doc.qt.io/archives/qt-4.8/qmetaenum.html`](http://doc.qt.io/archives/qt-4.8/qmetaenum.html)） |
| `QMetaMethod` | 成员函数的元数据（[`doc.qt.io/archives/qt-4.8/qmetamethod.html`](http://doc.qt.io/archives/qt-4.8/qmetamethod.html)） |
| `QMetaObject` | 包含有关 Qt 对象的元信息（[`doc.qt.io/archives/qt-4.8/qmetaobject.html`](http://doc.qt.io/archives/qt-4.8/qmetaobject.html)） |
| `QMetaProperty` | 关于属性的元数据（[`doc.qt.io/archives/qt-4.8/qmetaproperty.html`](http://doc.qt.io/archives/qt-4.8/qmetaproperty.html)） |
| `QMetaType` | 管理元对象系统中的命名类型（[`doc.qt.io/archives/qt-4.8/qmetatype.html`](http://doc.qt.io/archives/qt-4.8/qmetatype.html)） |
| `QObjectCleanupHandler` | 监视多个`QObject`的生命周期（[`doc.qt.io/archives/qt-4.8/qobjectcleanuphandler.html`](http://doc.qt.io/archives/qt-4.8/qobjectcleanuphandler.html)） |

Qt 对象通常被视为标识，而不是值。标识被克隆，而不是复制或分配；克隆标识是比复制或分配值更复杂的操作。因此，`QObject`和所有`QObject`的子类（直接或间接）都禁用了它们的复制构造函数和赋值运算符。

# 信号和槽

信号和槽是 Qt 中用于实现对象间通信的机制。信号和槽机制是 Qt 的一个核心特性，作为 GUI 框架。在 Qt 中，小部件通过这种机制得知其他小部件的变化。一般来说，任何类型的对象都使用这种机制相互通信。例如，当用户点击关闭按钮时，我们可能希望调用窗口的`close()`函数。

信号和槽是 C/C++中回调技术的替代品。当特定事件发生时，会发出信号。Qt 框架中的所有小部件都有预定义的信号，但我们总是可以对小部件进行子类化，以添加我们自己的信号。槽是响应信号调用的函数。与预定义信号类似，Qt 小部件有许多预定义的槽，但我们可以添加自定义槽来处理我们感兴趣的信号。

来自 Qt 官方文档（[`doc.qt.io/archives/qt-4.8/signalsandslots.html`](http://doc.qt.io/archives/qt-4.8/signalsandslots.html)）的以下图表演示了通过信号和槽进行对象间通信的过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/08250b9c-326e-4c29-905e-2296d3d94f91.jpg)

信号和槽是松散耦合的通信机制；发出信号的类不关心接收信号的槽。信号是忘记即发的完美例子。信号和槽系统确保如果信号连接到槽，槽将在适当的时间以信号的参数被调用。信号和槽都可以接受任意数量和任意类型的参数，并且它们是完全类型安全的。因此，信号和接收槽的签名必须匹配；因此，编译器可以帮助我们检测类型不匹配，作为一个奖励。

所有从`QObject`或其任何子类（如`QWidget`）继承的对象都可以包含信号和槽。当对象改变其状态时，会发出信号，这可能对其他对象很有趣。对象不知道（或不关心）接收端是否有任何对象。一个信号可以连接到尽可能多的槽。同样，我们可以将尽可能多的信号连接到单个槽。甚至可以将一个信号连接到另一个信号；因此，信号链是可能的。

因此，信号和系统一起构成了一个非常灵活和可插拔的组件编程机制。

# 事件系统

在 Qt 中，事件代表应用程序中发生的事情或应用程序需要知道的用户活动。在 Qt 中，事件是从抽象的`QEvent`类派生的对象。任何`QObject`子类的实例都可以接收和处理事件，但它们对小部件特别相关。

每当事件发生时，适当的`QEvent`子类实例被构造，并通过调用其`event()`函数将其所有权交给特定的`QObject`实例（或任何相关的子类）。这个函数本身不处理事件；根据传递的事件类型，它调用特定类型事件的事件处理程序，并根据事件是否被接受或被忽略发送响应。

一些事件，比如`QCloseEvent`和`QMoveEvent`，来自应用程序本身；一些，比如`QMouseEvent`和`QKeyEvent`，来自窗口系统；还有一些，比如`QTimerEvent`，来自其他来源。大多数事件都有从`QEvent`派生的特定子类，并且有时还有特定于事件的函数来满足扩展事件的特定行为。举例来说，`QMouseEvent`类添加了`x()`和`y()`函数，以便小部件发现鼠标光标的位置。

每个事件都有与之关联的类型，在`QEvent::Type`下定义，这是一种方便的运行时类型信息的来源，用于快速识别事件从哪个子类构造而来。

# 事件处理程序

通常，通过调用相关的虚函数来渲染事件。虚函数负责按预期响应。如果自定义虚函数实现不执行所有必要的操作，我们可能需要调用基类的实现。

例如，以下示例处理自定义标签小部件上的鼠标左键单击，同时将所有其他按钮单击传递给基类`QLabel`类：

```cpp
void my_QLabel::mouseMoveEvent(QMouseEvent *evt)
{
    if (event->button() == Qt::LeftButton) {
        // handle left mouse button here
        qDebug() <<" X: " << evt->x() << "t Y: " << evt->y() << "n";
    }
    else {
        // pass on other buttons to base class
        QLabel::mouseMoveEvent(event);
    }
}
```

如果我们想要替换基类功能，我们必须在虚函数覆盖中实现所有内容。如果要求只是简单地扩展基类功能，我们可以实现我们想要的内容，并调用基类函数处理我们不想处理的其他情况。

# 发送事件

许多使用 Qt 框架的应用程序希望发送自己的事件，就像框架提供的事件一样。可以通过使用事件对象构造适当的自定义事件，并使用`QCoreApplication::sendEvent()`和`QCoreApplication::postEvent()`发送它们。

`sendEvent()`是同步执行的；因此，它会立即处理事件。对于许多事件类，有一个名为`isAccepted()`的函数，告诉我们上一个被调用的处理程序是否接受或拒绝了事件。

`postEvent()`是异步执行的；因此，它将事件发布到队列中以供以后调度。下次 Qt 的主事件循环运行时，它会调度所有发布的事件，进行一些优化。例如，如果有多个调整大小事件，它们会被压缩成一个，作为所有调整大小事件的并集，从而避免用户界面的闪烁。

# 元对象系统

Qt 元对象系统实现了信号和槽机制用于对象间通信，动态属性系统和运行时类型信息。

Qt 元对象系统基于三个关键方面：

+   `QObject`类：为 Qt 对象提供元对象系统的优势的基类

+   `Q_OBJECT`宏：在类声明的私有部分提供的宏，用于启用元对象特性，如动态属性、信号和槽

+   MOC：为每个`QObject`子类提供实现元对象特性所需的代码

MOC 在 Qt 源文件的实际编译之前执行。当 MOC 发现包含`Q_OBJECT`宏的类声明时，它会为这些类中的每一个生成另一个带有元对象代码的 C++源文件。生成的源文件要么通过`#include`包含在类的源文件中，要么更常见的是与类的实现一起编译和链接。

# Hello World - Qt 程序

现在，让我们开始使用 Qt/C++进行 GUI 应用程序开发。在进入下面的章节之前，从 Qt 的官方网站([`www.qt.io/download`](https://www.qt.io/download))下载 Qt SDK 和 Qt Creator。我们将在本章讨论的代码完全符合 LGPL，并且将通过编写纯 C++代码手工编码。Qt 框架旨在使编码愉快和直观，以便您可以手工编写整个应用程序，而不使用 Qt Creator IDE。

Qt Creator 是一个跨平台的 C++、JavaScript 和 QML 集成开发环境，是 Qt GUI 应用程序开发框架的一部分。它包括一个可视化调试器和集成的 GUI 布局和表单设计器。编辑器的功能包括语法高亮和自动补全。Qt Creator 在 Linux 和 FreeBSD 上使用 GNU 编译器集合的 C++编译器。在 Windows 上，它可以使用 MinGW 或 MSVC，默认安装时还可以使用 Microsoft 控制台调试器，当从源代码编译时。也支持 Clang。- *维基百科* ([`en.wikipedia.org/wiki/Qt_Creator`](https://en.wikipedia.org/wiki/Qt_Creator))

让我们从一个简单的*Hello World*程序开始，使用一个标签小部件。在这个例子中，我们将创建并显示一个带有文本`Hello World, QT!`的标签小部件：

```cpp
#include <QApplication> 
#include <QLabel> 

int main (int argc, char* argv[]) 
{ 
    QApplication app(argc, argv); 
    QLabel label("Hello World, QT!"); 
    Label.show(); 
    return app.execute(); 
}
```

在这段代码中，我们包含了两个库：`<QApplication>`和`<QLabel>`。`QApplication`对象定义在`QApplication`库中，它管理应用程序中的资源，并且是运行任何 Qt 基于 GUI 的应用程序所必需的。这个对象接受程序的命令行参数，当调用`app.execute()`时，Qt 事件循环就会启动。

**事件循环**是一种程序结构，允许事件被优先级排序、排队和分派给对象。在基于事件的应用程序中，某些函数被实现为被动接口，以响应某些事件的调用。事件循环通常会持续运行，直到发生终止事件（例如用户点击退出按钮）。

`QLabel`是所有 Qt 小部件中最简单的小部件，定义在`<QLabel>`中。在这段代码中，标签被实例化为文本`Hello World, QT`。当调用`label.show()`时，一个带有实例化文本的标签将出现在屏幕上，显示在自己的窗口框架中。

现在，要构建和运行应用程序，我们需要的第一件事是一个项目文件。要创建一个项目文件并编译应用程序，我们需要按照以下步骤进行：

1.  创建一个目录，并将源代码保存在该目录中的 CPP 文件中。

1.  打开一个 shell，并使用`qmake -v`命令验证安装的`qmake`版本。如果找不到`qmake`，则需要将安装路径添加到环境变量中。

1.  现在，在 shell 中切换到 Qt 文件路径，并执行`qmake -project`命令。这将为应用程序创建一个项目文件。

1.  打开项目文件，并在`INCLUDEPATH`之后的`.pro`文件中添加以下行：

```cpp
... 
INCLUDEPATH += . 
QT += widgets 
... 
```

1.  然后，运行`qmake`而不带参数，以创建包含构建应用程序规则的`make`文件。

1.  运行`make`（根据平台的不同可能是`nmake`或`gmake`），它将根据`Makefile`中指定的规则构建应用程序。

1.  如果你运行应用程序，一个带有标签的小窗口将出现，上面写着 Hello World, QT!。

构建任何 Qt GUI 应用程序的步骤都是相同的，只是可能需要在项目文件中进行一些更改。对于我们将在本章讨论的所有未来示例，*构建和运行*意味着遵循这些步骤。

在我们继续下一个示例之前，让我们玩一些。用以下代码替换`QLabel`的实例化：

```cpp
QLabel label("<h2><i>Hello World</i>, <font color=green>QT!</font></h2>"); 
```

现在，重新构建并运行应用程序。正如这段代码所说明的，通过使用一些简单的 HTML 样式格式化，定制 Qt 的用户界面是很容易的。

在下一节中，我们将学习如何处理 Qt 事件以及使用信号和槽来进行对象通信。

# Qt 事件模型与信号/槽/MOC - 一个例子

在这一节中，我们将创建一个应用程序来处理`QLabel`中的鼠标事件。我们将在自定义的`QLabel`中重写鼠标事件，并在放置自定义标签的对话框中处理它们。这个应用程序的方法如下：

1.  创建一个自定义的`my_QLabel`类，继承自框架`QLabel`类，并重写鼠标事件，如鼠标移动、鼠标按下和鼠标离开。

1.  在`my_QLabel`中定义与这些事件对应的信号，并从相应的事件处理程序中发出它们。

1.  创建一个从`QDialog`类继承的对话框类，并手动编写所有小部件的位置和布局，包括用于处理鼠标事件的自定义小部件。

1.  在对话框类中，定义槽来处理从`my_QLabel`对象发出的信号，并在对话框中显示适当的结果。

1.  在`QApplication`对象下实例化这个对话框，并执行。

1.  创建项目文件以构建小部件应用程序并使其运行起来。

# 创建一个自定义小部件

让我们编写头文件`my_qlabel.h`来声明类`my_QLabel`：

```cpp
#include <QLabel> 
#include <QMouseEvent> 

class my_QLabel : public QLabel 
{ 
    Q_OBJECT 
public: 
    explicit my_QLabel(QWidget *parent = nullptr); 

    void mouseMoveEvent(QMouseEvent *evt); 
    void mousePressEvent(QMouseEvent* evt); 
    void leaveEvent(QEvent* evt); 

    int x, y; 

signals: 
    void Mouse_Pressed(); 
    void Mouse_Position(); 
    void Mouse_Left(); 
}; 
```

`QLabel`和`QMouseEvent`在包含的库`<QLabel>`和`<QMouseEvent>`中被定义。该类从`QLabel`派生，以继承其默认行为，并且`QObject`被赋予处理信号机制的属性。

在头文件的私有部分，我们添加了一个`Q_OBJECT`宏，通知 MOC 它必须为这个类生成元对象代码。元对象代码是信号和槽机制、运行时类型信息和动态属性系统所必需的。

在类头部，除了构造函数声明之外，还重写了鼠标事件，如鼠标移动事件、鼠标按下事件和鼠标离开事件。此外，公共整数变量保存了鼠标指针的当前*X*和*Y*坐标。最后，在信号部分声明了从每个鼠标事件发出的信号。

现在，让我们在一个 CPP 文件`my_qlabel.cpp`中定义这些项目：

```cpp
#include "my_qlabel.h" 

my_QLabel::my_QLabel(QWidget *parent) : QLabel(parent), x(0), y(0)  {} 

void my_QLabel::mouseMoveEvent(QMouseEvent *evt) 
{ 
    this->x = evt->x(); 
    this->y = evt->y(); 
    emit Mouse_Position(); 
} 
```

在构造函数中，将父类传递给`QLabel`基类，以继承重写类中未处理的情况，并将坐标变量初始化为零。在`mouse-move`事件处理程序中，更新保存鼠标坐标的成员变量，并发出信号`Mouse_Position()`。使用`my_QLabel`的对话框可以将这个信号连接到父对话框类中相应的`mouse-move`槽，并更新 GUI：

```cpp
void my_QLabel::mousePressEvent(QMouseEvent *evt) 
{ 
    emit Mouse_Pressed(); 
} 

void my_QLabel::leaveEvent(QEvent *evt) 
{ 
   emit Mouse_Left(); 
} 
```

从`mouse-press`事件处理程序中发出信号`Mouse_Pressed()`，从`mouse-leave`事件中发出`Mouse_Left()`信号。这些信号被连接到父窗口（`Dialog`类）中相应的槽，并更新 GUI。因此，我们编写了一个自定义标签类来处理鼠标事件。

# 创建应用程序对话框

由于标签类已经被实现，我们需要实现对话框类来放置所有的小部件，并处理从`my_QLabel`对象发出的所有信号。让我们从`dialog.h`头文件开始：

```cpp
#include <QDialog> 

class my_QLabel; 
class QLabel; 

class Dialog : public QDialog 
{ 
    Q_OBJECT 
public: 
    explicit Dialog(QWidget *parent = 0); 
    ~Dialog(); 

private slots: 
    void Mouse_CurrentPosition(); 
    void Mouse_Pressed(); 
    void Mouse_Left(); 

private: 
    void initializeWidgets(); 
    my_QLabel *label_MouseArea; 
    QLabel *label_Mouse_CurPos; 
    QLabel *label_MouseEvents; 
}; 
```

在这里，我们创建了一个从`QDialog`继承的`Dialog`类，在`<QDialog>`库下定义。在这个类头文件中，`QLabel`和`my_QLabel`类被提前声明，因为实际的库将被包含在类定义文件中。正如我们已经讨论过的，必须包含`Q_OBJECT`宏来生成元对象代码，以启用信号和槽机制、运行时类型信息和动态属性系统。

除了构造函数和析构函数声明之外，还声明了私有槽，用于连接到`my_QLabel`对象发出的信号。这些槽是普通函数，可以正常调用；它们唯一的特殊功能是可以连接到信号。`Mouse_CurrentPosition()`槽将连接到`my_QLabel`对象的`mouseMoveEvent()`发出的信号。类似地，`Mouse_Pressed()`将连接到`mousePressEvent()`，`MouseLeft()`将连接到`my_QLabel`对象的`leaveEvent()`。

最后，声明了所有部件指针和一个名为`initializeWidgets()`的私有函数，用于在对话框中实例化和布局部件。

`Dialog`类的实现属于`dialog.cpp`：

```cpp
#include "dialog.h" 
#include "my_qlabel.h" 
#include <QVBoxLayout> 
#include <QGroupBox> 

Dialog::Dialog(QWidget *parent) : QDialog(parent) 
{ 
    this->setWindowTitle("My Mouse-Event Handling App"); 
    initializeWidgets(); 

    connect(label_MouseArea, SIGNAL(Mouse_Position()), this, SLOT(Mouse_CurrentPosition())); 
    connect(label_MouseArea, SIGNAL(Mouse_Pressed()), this, SLOT(Mouse_Pressed())); 
    connect(label_MouseArea, SIGNAL(Mouse_Left()), this, SLOT(Mouse_Left())); 
} 
```

在构造函数中，应用程序对话框的标题设置为`My Mouse-Event Handling App`。然后调用`initializeWidgets()`函数—该函数将在稍后解释。在创建和设置布局后调用`initializeWidgets()`，从`my_QLabel`对象发出的信号将连接到`Dialog`类中声明的相应槽：

```cpp
void Dialog::Mouse_CurrentPosition() 
{ 
    label_Mouse_CurPos->setText(QString("X = %1, Y = %2") 
                                    .arg(label_MouseArea->x) 
                                    .arg(label_MouseArea->y)); 
    label_MouseEvents->setText("Mouse Moving!"); 
} 
```

`Mouse_CurrentPosition()`函数是与`my_QLabel`对象的鼠标移动事件发出的信号相连接的槽。在这个函数中，标签部件`label_Mouse_CurPos`会被当前鼠标坐标更新，而`label_MouseEvents`会将其文本更新为`Mouse Moving!`：

```cpp
void Dialog::Mouse_Pressed() 
{ 
    label_MouseEvents->setText("Mouse Pressed!"); 
} 
```

`Mouse_Pressed()`函数是与鼠标按下事件发出的信号相连接的槽，每次用户在鼠标区域（`my_QLabel`对象）内单击时都会调用该函数。该函数会将`label_MouseEvents`标签中的文本更新为`"Mouse Pressed!"`：

```cpp
void Dialog::Mouse_Left() 
{ 
    label_MouseEvents->setText("Mouse Left!"); 
} 
```

最后，每当鼠标离开鼠标区域时，`my_QLabel`对象的鼠标离开事件会发出一个信号，连接到`Mouse_Left()`槽函数。然后，它会将`label_MouseEvents`标签中的文本更新为`"Mouse Left!"`。

使用`initializeWidgets()`函数在对话框中实例化和设置布局，如下所示：

```cpp
void Dialog::initializeWidgets() 
{ 
    label_MouseArea = new my_QLabel(this); 
    label_MouseArea->setText("Mouse Area"); 
    label_MouseArea->setMouseTracking(true); 
    label_MouseArea->setAlignment(Qt::AlignCenter|Qt::AlignHCenter); 
    label_MouseArea->setFrameStyle(2); 
```

在这段代码中，使用自定义标签类`my_QLabel`实例化了`label_MouseArea`对象。然后修改了标签属性（例如将标签文本修改为`"Mouse Area"`），在`label_MouseArea`对象内启用了鼠标跟踪，将对齐设置为居中，并将框架样式设置为粗线。

```cpp
label_Mouse_CurPos = new QLabel(this);
label_Mouse_CurPos->setText("X = 0, Y = 0");
label_Mouse_CurPos->setAlignment(Qt::AlignCenter|Qt::AlignHCenter);
label_Mouse_CurPos->setFrameStyle(2);
label_MouseEvents = new QLabel(this);
label_MouseEvents->setText("Mouse current events!");
label_MouseEvents->setAlignment(Qt::AlignCenter|Qt::AlignHCenter);
label_MouseEvents->setFrameStyle(2);
```

`label_Mouse_CurPos`和`label_MouseEvents`标签对象正在更新其属性，例如文本对齐和框架样式，与`label_MouseArea`对象类似。但是，`label_Mouse_CurPos`中的文本最初设置为`"X = 0, Y = 0"`，而`label_MouseEvents`标签设置为`"Mouse current events!"`：

```cpp
    QGroupBox *groupBox = new QGroupBox(tr("Mouse Events"), this); 
    QVBoxLayout *vbox = new QVBoxLayout; 
    vbox->addWidget(label_Mouse_CurPos); 
    vbox->addWidget(label_MouseEvents); 
    vbox->addStretch(0); 
    groupBox->setLayout(vbox); 

    label_MouseArea->move(40, 40); 
    label_MouseArea->resize(280,260); 
    groupBox->move(330,40); 
    groupBox->resize(200,150); 
}
```

最后，创建了一个垂直框布局（`QVBoxLayout`），并将`label_Mouse_CurPos`和`label_MouseEvents`标签部件添加到其中。还创建了一个带有标签`Mouse Events`的分组框，并将分组框的布局设置为垂直框布局，用部件创建。最后，将鼠标区域标签和鼠标事件分组框的位置和大小设置为预定义值。因此，部件的创建和布局设置已完成。

# 执行应用程序

现在我们可以编写`main.cpp`来创建`Dialog`类并显示它：

```cpp
#include "dialog.h" 
#include <QApplication> 

int main(int argc, char *argv[]) 
{ 
    QApplication app(argc, argv); 
    Dialog dialog; 
    dialog.resize(545, 337); 
    dialog.show(); 
    return app.exec(); 
} 
```

这段代码与我们讨论过的 Hello World Qt 应用程序完全相同。我们实例化了我们创建的`Dialog`类，将对话框窗口框架的大小调整为预定义值，然后应用程序准备构建和运行。但是，在构建应用程序之前，让我们手动编写项目文件：

```cpp
QT += widgets 

SOURCES +=  
        main.cpp  
        dialog.cpp  
    my_qlabel.cpp 

HEADERS +=  
        dialog.h  
    my_qlabel.h 
```

现在，构建应用程序并运行。对话框将如下弹出（Windows 平台）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-rct-prog/img/364c4bdf-cdad-490f-8f1f-5d5c30eee32b.jpg)

当我们将鼠标指针悬停在左侧标签（鼠标区域）上时，鼠标的坐标将在右侧的第一个标签中更新，右侧的第二个标签将显示文本“鼠标移动！”。在鼠标区域按下任意鼠标按钮时，第二个标签中的文本将更改为“鼠标按下！”当鼠标指针离开鼠标区域时，文本将更新为“鼠标离开！”

在这一部分，我们学习了如何创建对话框窗口、对话框下的小部件、小部件中的布局等。我们还学习了如何启用自定义小部件（标签小部件），以及如何处理系统事件。然后，我们学习了使用用户定义的信号和槽创建和连接对象。最后，我们使用了所有这些小部件，包括自定义小部件，并创建了一个应用程序来处理窗口中的 Qt 鼠标事件。

现在，让我们实现一个类似的应用程序来处理`QLabel`中的鼠标事件，并在另一个标签中显示鼠标坐标。在这里，事件处理是通过使用`RxCpp`可观察对象和 Qt 事件过滤器进行事件订阅和事件过滤的。

# 将 RxCpp 库与 Qt 事件模型集成

在之前的部分中，我们已经从鸟瞰视角看到了 Qt 框架。我们学习了如何处理 Qt 事件，特别是鼠标事件和信号/槽机制。我们还在前两章中学习了`RxCpp`库及其编程模型。在这个过程中，我们遇到了许多重要的响应式操作符，这些操作符在编写利用响应式方法的程序时很重要。

在这一部分，我们将编写一个应用程序来处理标签小部件中的鼠标事件，这与之前的示例类似。在这个例子中，我们不是像在上一个例子中那样处理鼠标事件来发出信号，而是使用`RxCpp`订阅者订阅 Qt 鼠标事件，并将不同的鼠标事件从结果鼠标事件流中过滤出来。事件（未被过滤掉的）将与订阅者相关联。

# Qt 事件过滤器-一种响应式方法

如前所述，Qt 框架具有强大的事件机制。我们需要在 Qt 和 RxCpp 的事务之间建立桥梁。为了开始使用这个应用程序，我们将编写一个头文件`rx_eventfilter.h`，其中包含所需的 RxCpp 头文件和 Qt 事件过滤器。

```cpp
#include <rxcpp/rx.hpp> 
#include <QEvent> 
namespace rxevt { 
    // Event filter object class 
    class EventEater: public QObject  { 
    Public: 
        EventEater(QObject* parent, QEvent::Type type, rxcpp::subscriber<QEvent*> s): 
        QObject(parent), eventType(type), eventSubscriber(s) {} 
       ~EventEater(){ eventSubscriber.on_completed();}
```

包含`<rxcpp/rx.hpp>`库以获取`RxxCppsubscriber`和`observable`的定义，我们在这个类中使用这些定义，以及`<QEvent>`库以获取`QEvent`的定义。整个头文件都在`rxevt`命名空间下定义。现在，`EventEater`类是一个 Qt 事件过滤器类，用于`filter-in`只有成员`eventType`初始化的 Qt 事件。为了实现这一点，该类有两个成员变量。第一个是`eventSubscriber`，它是`QEvent`类型的`rxcpp::subscriber`，下一个是`eventType`，用于保存`QEvent::Type`。

在构造函数中，将父`QObject`（需要过滤事件的小部件）传递给基类`QObject`。成员变量`eventType`和`eventSubscriber`使用需要过滤的`QEvent::Type`和相应事件类型的`rxcpp::subscriber`进行初始化：

```cpp
        bool eventFilter(QObject* obj, QEvent* event) { 
            if(event->type() == eventType) 
            { eventSubscriber.on_next(event);} 
            return QObject::eventFilter(obj, event); 
        } 
```

我们重写了`eventFilter()`函数，只有在事件类型与初始化的类型相同时才调用`on_next()`。`EventEater`是一个事件过滤器对象，它接收发送到该对象的所有事件。过滤器可以停止事件，也可以将其转发到该对象。`EventEater`对象通过其`eventFilter()`函数接收事件。`eventFilter()`函数（[`doc.qt.io/qt-5/qobject.html#eventFilter`](http://doc.qt.io/qt-5/qobject.html#eventFilter)）必须在事件应该被过滤（换句话说，停止）时返回 true；否则，必须返回`false`：

```cpp
    private: 
        QEvent::Type eventType; 
        rxcpp::subscriber<QEvent*> eventSubscriber; 
    }; 
```

因此，让我们在同一个头文件下编写一个实用函数，使用`EventEater`对象从事件流创建并返回一个`rxcpp::observable`：

```cpp
    // Utility function to retrieve the rxcpp::observable of filtered events 
    rxcpp::observable<QEvent*> from(QObject* qobject, QEvent::Type type) 
    { 
        if(!qobject) return rxcpp::sources::never<QEvent*>(); 
         return rxcpp::observable<>::create<QEvent*>( 
            qobject, type { 
                qobject->installEventFilter(new EventEater(qobject, type, s)); 
            } 
        ); 
    } 
} // rxevt 
```

在这个函数中，我们从事件流中返回`QEvent`的 observable，我们将使用`EventEater`对象进行过滤。在后者对象看到它们之前，可以设置`QObject`实例来监视另一个`QObject`实例的事件。这是 Qt 事件模型的一个非常强大的特性。`installEventFilter()`函数的调用使其成为可能，`EventEater`类具有执行过滤的条件。

# 创建窗口-设置布局和对齐

现在，让我们编写应用程序代码来创建包含两个标签小部件的窗口小部件。一个标签将用作鼠标区域，类似于上一个示例，另一个将用于显示过滤后的鼠标事件和鼠标坐标。

让我们将`main.cpp`中的代码分为两个部分。首先，我们将讨论创建和设置小部件布局的代码：

```cpp
#include "rx_eventfilter.h" 
int main(int argc, char *argv[]) 
{ 
    QApplication app(argc, argv); 
    // Create the application window 
    auto widget = std::unique_ptr<QWidget>(new QWidget()); 
    widget->resize(280,200); 
        // Create and set properties of mouse area label 
    auto label_mouseArea   = new QLabel("Mouse Area"); 
    label_mouseArea->setMouseTracking(true); 
    label_mouseArea->setAlignment(Qt::AlignCenter|Qt::AlignHCenter); 
    label_mouseArea->setFrameStyle(2); 
    // Create and set properties of message display label 
    auto label_coordinates = new QLabel("X = 0, Y = 0"); 
    label_coordinates->setAlignment(Qt::AlignCenter|Qt::AlignHCenter); 
    label_coordinates->setFrameStyle(2);
```

我们已经包含了`rx_eventfilter.h`头文件，以使用`RxCpp`库实现的事件过滤机制。在这个应用程序中，不是在对话框内创建这些小部件，而是创建了一个`QWidget`对象，并将两个`QLabel`小部件添加到`QVBoxLayout`布局中；这被设置为应用程序窗口的布局。应用程序窗口的大小是预定义的，宽度为`200 像素`，高度为`280 像素`。与之前的应用程序类似，为第一个标签启用了鼠标跟踪：

```cpp
    // Adjusting the size policy of widgets to allow stretching 
    // inside the vertical layout 
    label_mouseArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding); 
    label_coordinates->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding); 
    auto layout = new QVBoxLayout; 
    layout->addWidget(label_mouseArea); 
    layout->addWidget(label_coordinates); 
    layout->setStretch(0, 4); 
    layout->setStretch(1, 1); 
    widget->setLayout(layout); 
```

两个小部件的大小策略都设置为`QSizePolicy::Expanding`，以允许垂直布局框内的小部件拉伸。这使我们可以使鼠标区域标签比状态显示标签更大。`setStretch()`函数设置位置索引处的拉伸系数。

# 特定事件类型的 observables

订阅`rxcpp::observable`的鼠标事件的代码如下：

+   鼠标移动

+   鼠标按钮按下

+   鼠标按钮双击

程序如下：

```cpp
    // Display the mouse move message and the mouse coordinates 
    rxevt::from(label_mouseArea, QEvent::MouseMove) 
            .subscribe(&label_coordinates{ 
        auto me = static_cast<const QMouseEvent*>(e); 
        label_coordinates->setText(QString("Mouse Moving : X = %1, Y = %2") 
                                   .arg(me->x()) 
                                   .arg(me->y())); 
    });
```

`rxevt::from()`函数返回基于我们传递的`QEvent::Type`参数的`label_mouseArea`事件的`rxcpp::observable`。在这段代码中，我们正在订阅`label_mouseArea`中的事件的 Observable，这些事件的类型是`QEvent::MouseMove`。在这里，我们正在使用鼠标指针的当前*X*和*Y*位置更新`label_coordinates`文本：

```cpp
    // Display the mouse signle click message and the mouse coordinates 
    rxevt::from(label_mouseArea, QEvent::MouseButtonPress) 
            .subscribe(&label_coordinates{ 
        auto me = static_cast<const QMouseEvent*>(e); 
        label_coordinates->setText(QString("Mouse Single click at X = %1, Y = %2") 
                                   .arg(me->x()) 
                                   .arg(me->y())); 
    }); 
```

与鼠标移动过滤类似，`rxevt::from()`函数返回`QEvent`的 observable，仅包括类型为`QEvent::MouseButtonPress`的事件。然后，在`label_coordinates`中更新鼠标点击的位置：

```cpp
    // Display the mouse double click message and the mouse coordinates 
    rxevt::from(label_mouseArea, QEvent::MouseButtonDblClick) 
            .subscribe(&label_coordinates{ 
        auto me = static_cast<const QMouseEvent*>(e); 
        label_coordinates->setText(QString("Mouse Double click at X = %1, Y = %2") 
                                   .arg(me->x()) 
                                   .arg(me->y())); 
    }); 
    widget->show(); 
    return app.exec(); 
} // End of main 
```

最后，事件类型`QEvent::MouseButtonDblClick`也类似于单击鼠标，更新了`label_coordinates`中的文本，并显示了双击位置。然后，调用应用程序窗口小部件的`show()`函数，并调用`exec()`函数启动事件循环。

项目文件`Mouse_EventFilter.pro`如下：

```cpp
QT += core widgets 
CONFIG += c++14 

TARGET = Mouse_EventFilter 
INCLUDEPATH += include 

SOURCES +=  
    main.cpp 
HEADERS +=  
    rx_eventfilter.h  
```

由于 RxCpp 库是一个仅包含头文件的库，在项目目录内创建了一个名为`include`的文件夹，并将 RxCpp 库文件夹复制到其中。更新`INCLUDEPATH`将帮助应用程序获取指定目录中存在的任何包含文件。现在，让我们构建并运行应用程序。

# RxQt 简介

`RxQt`库是一个基于`RxCpp`库编写的公共领域库，它使得以一种响应式的方式使用 Qt 事件和信号变得容易。为了理解该库，让我们跳转到一个示例中，这样我们就可以跟踪鼠标事件并使用该库提供的 observable 进行过滤。该库可以从 GitHub 存储库[`github.com/tetsurom/rxqt`](https://github.com/tetsurom/rxqt)下载：

```cpp
#include <QApplication> 
#include <QLabel> 
#include <QMouseEvent> 
#include "rxqt.hpp" 

int main(int argc, char *argv[]) 
{ 
    QApplication app(argc, argv); 

    auto widget = new QWidget(); 
    widget->resize(350,300); 
    widget->setCursor(Qt::OpenHandCursor); 

    auto xDock = new QLabel((QWidget*)widget); 
    xDock->setStyleSheet("QLabel { background-color : red}"); 
    xDock->resize(9,9); 
    xDock->setGeometry(0, 0, 9, 9); 

    auto yDock = new QLabel((QWidget*)widget); 
    yDock->setStyleSheet("QLabel { background-color : blue}"); 
    yDock->resize(9,9); 
    yDock->setGeometry(0, 0, 9, 9); 
```

上述代码创建了一个`QWidget`，它充当另外两个`QLabel`的父类。创建了两个标签小部件，以在父小部件内移动，沿着窗口的顶部和左边缘。沿*X*轴的可停靠标签为红色，*Y*轴的标签为蓝色。

```cpp
    rxqt::from_event(widget, QEvent::MouseButtonPress) 
            .filter([](const QEvent* e) { 
        auto me = static_cast<const QMouseEvent*>(e); 
        return (Qt::LeftButton == me->buttons()); 
    }) 
            .subscribe(& { 
        auto me = static_cast<const QMouseEvent*>(e); 
        widget->setCursor(Qt::ClosedHandCursor); 
        xDock->move(me->x(), 0); 
        yDock->move(0, me->y()); 
    }); 
```

在上述代码中，`rxqt::from_event()`函数过滤了除`QEvent::MouseButtonPress`事件之外的所有小部件类事件，并返回了一个`rxcpp::observable<QEvent*>`实例。这里的`rxcpp::observable`已经根据鼠标事件进行了过滤，如果按钮是左鼠标按钮。然后，在`subscribe()`方法的 Lambda 函数内，我们将光标更改为`Qt::ClosedHandCursor`。我们还将`xDock`的位置设置为鼠标*x*位置值，以及窗口的顶部边缘，将`yDock`的位置设置为鼠标*y*位置值，以及窗口的左边缘：

```cpp
    rxqt::from_event(widget, QEvent::MouseMove) 
            .filter([](const QEvent* e) { 
        auto me = static_cast<const QMouseEvent*>(e); 
        return (Qt::LeftButton == me->buttons()); 
    }) 
            .subscribe(& { 
        auto me = static_cast<const QMouseEvent*>(e); 
        xDock->move(me->x(), 0); 
        yDock->move(0, me->y()); 
    });
```

在这段代码中，我们使用`RxQt`库过滤了窗口小部件的所有鼠标移动事件。这里的 observable 是一个包含鼠标移动和左鼦按键事件的鼠标事件流。在 subscribe 方法内，代码更新了`xDock`和`yDock`的位置，沿着窗口的顶部和左边缘：

```cpp
    rxqt::from_event(widget, QEvent::MouseButtonRelease) 
            .subscribe(&widget { 
        widget->setCursor(Qt::OpenHandCursor); 
    }); 

    widget->show(); 
    return app.exec(); 
} 
```

最后，过滤了鼠标释放事件，并将鼠标光标设置回`Qt::OpenHandCursor`。为了给这个应用程序增添一些乐趣，让我们创建一个与`xDock`和`yDock`类似的小部件；这将是一个重力对象。当按下鼠标时，重力对象将跟随鼠标光标移动：

```cpp
#ifndef GRAVITY_QLABEL_H 
#define GRAVITY_QLABEL_H 

#include <QLabel> 

class Gravity_QLabel : public QLabel 
{ 
   public: 
    explicit Gravity_QLabel(QWidget *parent = nullptr): 
         QLabel(parent), prev_x(0), prev_y(0){} 

    int prev_x, prev_y; 
}; 

#endif // GRAVITY_QLABEL_H 
```

现在，我们必须在应用程序窗口下创建一个`gravity`小部件的实例（从新创建的`Gravity_QLabel`类）：

```cpp
    auto gravityDock = new Gravity_QLabel((QWidget*)widget); 
    gravityDock->setStyleSheet("QLabel { background-color : green}"); 
    gravityDock->resize(9,9); 
    gravityDock->setGeometry(0, 0, 9, 9);
```

与`xDock`和`yDock`的创建和大小设置类似，新的`gravityDock`对象已经创建。此外，每当抛出`press`事件时，必须将此对象的位置设置为鼠标坐标值。因此，在`QEvent::MouseButtonPress`的`subscribe`方法的 Lambda 函数内，我们需要添加以下代码行：

```cpp
    gravityDock->move(me->x(),me->y()); 
```

最后，需要根据鼠标移动更新`gravityDock`的位置。为了实现这一点，在`QEvent::MouseMove`的`subscribe`方法的 Lambda 函数内，我们需要添加以下代码：

```cpp
    gravityDock->prev_x = gravityDock->prev_x * .96 + me->x() * .04; 
    gravityDock->prev_y = gravityDock->prev_y * .96 + me->y() * .04; 
    gravityDock->move(gravityDock->prev_x, gravityDock->prev_y); 
```

在这里，`gravityDock`的位置更新为一个新值，该值是先前值的 96%和新位置的 4%之和。因此，我们使用`RxQt`和 RxCpp 库来过滤 Qt 事件，以创建*X*-*Y*鼠标位置指示器和重力对象。现在，让我们构建并运行应用程序。

# 总结

在本章中，我们讨论了使用 Qt 进行响应式 GUI 编程的主题。我们从快速概述使用 Qt 进行 GUI 应用程序开发开始。我们了解了 Qt 框架中的概念，如 Qt 对象层次结构，元对象系统以及信号和槽。我们使用简单的标签小部件编写了一个基本的“Hello World”应用程序。然后，我们使用自定义标签小部件编写了一个鼠标事件处理应用程序。在该应用程序中，我们更多地了解了 Qt 事件系统的工作原理，以及如何使用信号和槽机制进行对象通信。最后，我们编写了一个应用程序，使用`RxCpp`订阅模型和 Qt 事件过滤器来处理鼠标事件并对其进行过滤。我们介绍了如何在 GUI 框架（如 Qt）中使用 RxCpp 来遵循响应式编程模型。我们还介绍了`RxQt`库，这是一个集成了 RxCpp 和 Qt 库的公共领域。

在进入下一章之前，您需要了解如何为 RxCpp observables 编写*自定义操作符*。这个主题在在线部分有介绍。您可以参考以下链接：[`www.packtpub.com/sites/default/files/downloads/Creating_Custom_Operators_in_RxCpp.pdf`](https://www.packtpub.com/sites/default/files/downloads/Creating_Custom_Operators_in_RxCpp.pdf)。

在您完成阅读上述提到的主题之后，我们可以继续下一章，我们将看一下 C++响应式编程的设计模式和习语。


# 第十章：在 RxCpp 中创建自定义操作符

在过去的三章中，我们学习了 RxCpp 库及其编程模型。我们还将所学内容应用到了 GUI 编程的上下文中。从心智模型的角度来看，任何想以响应式方式编写程序的开发人员都必须理解可观察对象、观察者以及它们之间的操作符。当然，调度器和主题也很重要。响应式程序的大部分逻辑都驻留在操作符中。RxCpp 库作为其实现的一部分提供了许多内置（库存）操作符。我们已经在我们的程序中使用了其中一些。在本章中，我们将学习如何实现自定义操作符。要编写自定义操作符，我们需要深入了解与 RxCpp 库相关的一些高级主题。本章涵盖的主题如下：

+   Rx 操作符的哲学

+   链接库存操作符

+   编写基本的 RxCpp 操作符

+   编写不同类型的自定义操作符

+   使用`lift<T>`元操作符编写自定义操作符

+   向 RxCpp 库源代码中添加操作符

# Rx 操作符的哲学

如果你看任何响应式程序，我们会看到一系列操作符堆叠在可观察对象和观察者之间。开发人员使用流畅接口来链接操作符。在 RxCpp 中，可以使用点（`.`）或管道（`|`）来执行操作符链式调用。从软件接口的角度来看，每个操作符都接受一个可观察对象，并返回一个相同类型或不同类型的可观察对象。

RxCpp 可观察对象/观察者交互的一般用法（伪代码）如下：

```cpp
   Observable().     // Source Observable 
          Op1().     // First operator 
          Op2().     // Second operator 
                     ..                         
                     .. 
          Opn().subscribe( on_datahandler, 
                            on_errorhandler, 
                            on_completehandler); 
```

尽管在操作符链式调用时我们使用流畅接口，但实际上我们是在将函数组合在一起。为了将函数组合在一起，函数的返回值应该与组合链中的函数的参数类型兼容。

操作符以可观察对象作为参数，并返回另一个可观察对象。有一些情况下，它返回的是除可观察对象之外的值。只有那些返回可观察对象的操作符才能成为操作符链式调用的一部分。

要编写一个新的操作符，使其成为操作符链式调用方法的一部分，最好的方法是将它们作为`observable<T>`类型的方法添加。然而，编写一个可以在不同上下文中运行的生产质量操作符最好留给 RxCpp 内部的专家。另一个选择是使用 RxCpp 库中提供的`lift<t>`（`...`）操作符。我们将在本章中涵盖这两种策略。

每个操作符实现都应该具有的另一个非常重要的属性是它们应该是无副作用的。至少，它们不应该改变输入可观察对象的内容。换句话说，充当操作符的函数或函数对象应该是一个纯函数。

# 链接库存操作符

我们已经学到了 RxCpp 操作符是在可观察对象上操作的（作为输入接收），并返回可观察对象。这使得这些操作符可以通过操作符链式调用一一调用。链中的每个操作符都会转换从前一个操作符接收到的流中的元素。源流在这个过程中不会被改变。在链式调用操作符时，我们使用流畅接口语法。

开发人员通常在实现 GOF 构建器模式的类的消费上使用流畅接口。构建器模式的实现是以无序的方式实现的。尽管操作符链式调用的语法类似，但在响应式世界中操作符被调用的顺序确实很重要。

让我们编写一个简单的程序，帮助我们理解可观察对象操作符链式执行顺序的重要性。在这个特定的例子中，我们有一个可观察流，在这个流中我们应用 map 操作符两次：一次是为了找出平方，然后是为了找出值的两个实例。我们先应用平方函数，然后是两次函数：

```cpp
//----- operatorChaining1.cpp 
//----- Square and multiplication by 2 in order 
#include "rxcpp/rx.hpp" 
int main() 
{ 
    auto values = rxcpp::observable<>::range(1, 3). 
        map([](int x) { return x * x; }). 
        map([](int x) { return x * 2; }); 
    values.subscribe( 
        [](int v) {printf("OnNext: %dn", v); }, 
        []() {printf("OnCompletedn"); }); 
    return 0; 
} 
```

前面的程序将产生以下输出：

```cpp
OnNext: 2 
OnNext: 8 
OnNext: 18 
OnCompleted
```

现在，让我们颠倒应用顺序（先缩放 2 倍，两次，然后是参数的平方），然后查看输出，看看我们会得到不同的输出（在第一种情况下，先应用了平方，然后是缩放 2 倍）。以下程序将解释执行顺序，如果我们将程序生成的输出与之前的程序进行比较：

```cpp
//----- operatorChaining2.cpp 
//----- Multiplication by 2 and Square in order 
#include "rxcpp/rx.hpp" 
int main() 
{ 
    auto values = rxcpp::observable<>::range(1, 3). 
        map([](int x) { return x * 2; }). 
        map([](int x) { return x * x; }); 
    values.subscribe( 
        [](int v) {printf("OnNext: %dn", v); }, 
        []() {printf("OnCompletedn"); }); 
    return 0; 
} 
```

程序产生的输出如下：

```cpp
OnNext: 4 
OnNext: 16 
OnNext: 36 
OnCompleted 
```

在 C++中，我们可以很好地组合函数，因为 Lambda 函数和 Lambda 函数的惰性评估。RxCpp 库利用了这一事实来实现操作符。如果有三个函数（`F`、`G`、`H`）以`observable<T>`作为输入参数并返回`observable<T>`，我们可以象征性地将它们组合如下：

```cpp
F(G( H(x)) 
```

如果我们使用操作符链，可以写成如下形式：

```cpp
x.H().G().F() 
```

现在我们已经学会了操作符链实际上是在进行操作符组合。两者产生类似的结果，但操作符链更易读和直观。本节的一个目的是建立这样一个事实，即操作符组合和操作符链提供类似的功能。最初我们实现的操作符可以组合在一起（不能被链式调用），我们将学习如何创建适合操作符链的操作符。

# 编写基本的 RxCpp 自定义操作符

在上一节中，我们讨论了操作符链。操作符链是可能的，因为库存操作符是作为`observable<T>`类型的一部分实现的。我们最初要实现的操作符不能成为操作符链策略的一部分。在本节中，我们将实现一些 RxCpp 操作符，可以转换 Observable 并返回另一个 Observable。

# 将 RxCpp 操作符写为函数

为了开始讨论，让我们编写一个简单的操作符，它可以在 observable<string>上工作。该操作符只是在流中的每个项目之前添加文字`Hello`：

```cpp
//----------- operatorSimple.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <iostream> 
namespace rxu=rxcpp::util; 
#include <array> 
using namespace rxcpp; 
using namespace rxcpp::operators; 
// Write a Simple Reactive operator Takes an Observable<string> and 
// Prefix Hello to every item and return another Observable<string> 
observable<std::string> helloNames(observable<std::string> src ) { 
    return src.map([](std::string s) { return "Hello, " + s + "!"; }); 
} 
```

我们实现的自定义操作符是为了演示如何编写一个可以在 Observable 上工作的操作符。编写的操作符必须使用函数语义来调用，并且实现不适合操作符链。既然我们已经实现了一个操作符，让我们编写一个主函数来测试操作符的工作方式：

```cpp
int main() { 
     std::array< std::string,4 > a={{"Praseed", "Peter", "Sanjay","Raju"}}; 
     // Apply helloNames operator on the observable<string>  
     // This operator cannot be part of the method chaining strategy 
     // We need to invoke it as a function  
     // If we were implementing this operator as part of the
     //          RxCpp observable<T> 
     //   auto values = rxcpp::observable<>:iterate(a).helloNames(); 
     auto values = helloNames(rxcpp::observable<>::iterate(a));  
     //-------- As usual subscribe  
     values.subscribe(  
              [] (std::string f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
} 
```

程序将产生以下输出：

```cpp
Hello, Praseed! 
Hello, Peter! 
Hello, Sanjay! 
Hello, Raju! 
Hello World.. 
```

# 将 RxCpp 操作符写为 Lambda 函数

我们已经将我们的第一个自定义操作符写成了一个`unary`函数。所有操作符都是以 Observables 作为参数的`unary`函数。该函数以`observable<string>`作为参数，并返回另一个`observable<string>`。我们可以通过将操作符（内联）作为 Lambda 来实现相同的效果。让我们看看如何做到：

```cpp
//----------- operatorInline.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <iostream> 
namespace rxu=rxcpp::util; 
#include <array> 
using namespace rxcpp; 
using namespace rxcpp::operators; 
int main() { 
     std::array< std::string,4 > a={{"Praseed", "Peter", "Sanjay","Raju"}}; 
     auto helloNames = [] (observable<std::string> src ) { 
           return src.map([](std::string s) {  
             return "Hello, " + s + "!";  
             }); 
     }; 
     // type of values will be observable<string> 
     // Lazy Evaluation  
     auto values = helloNames(rxcpp::observable<>::iterate(a));  
     //-------- As usual subscribe  
     values.subscribe(  
              [] (std::string f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
} 
```

程序的输出如下：

```cpp
Hello, Praseed! 
Hello, Peter! 
Hello, Sanjay! 
Hello, Raju! 
Hello World.. 
```

输出显示，程序行为是相同的，无论是使用普通函数还是 Lambda 函数。Lambda 函数的优势在于调用站点的创建和函数的消耗。

# 组合自定义 RxCpp 操作符

我们已经在本书中学习了函数组合（第二章*，现代 C++及其关键习语之旅*）。函数组合是可能的，当一个函数的返回值与另一个函数的输入参数兼容时。在操作符的情况下，由于大多数操作符返回 Observables 并将 Observables 作为参数，它们适合函数组合。在本节中，我们的操作符适合组合，但它们还不能被链式调用。让我们看看如何组合操作符：

```cpp
//----------- operatorCompose.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <iostream> 
namespace rxu=rxcpp::util; 
#include <array> 
using namespace rxcpp; 
using namespace rxcpp::operators; 
int main() { 
     std::array< int ,4 > a={{10, 20,30,40}}; 
     // h-function (idempotent) 
     auto h = [] (observable<int> src ) { 
       return src.map([](int n ) { return n; }); 
     }; 
     // g-function 
     auto g = [] (observable<int> src ) { 
          return src.map([](int n ) { return n*2; }); 
     }; 
     // type of values will be observable<string> 
     // Lazy Evaluation ... apply h over observable<string> 
     // on the result, apply g  
     auto values = g(h(rxcpp::observable<>::iterate(a)));  
     //-------- As usual subscribe  
     values.subscribe(  
              [] (int f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
} 
```

程序的输出如下：

```cpp
20 
40 
60 
80 
Hello World.. 
```

# 不同类型的自定义操作符

RxCpp 库包含作为库存提供的不同类型的运算符。RxCpp 的默认运算符集对于大多数应用程序来说已经足够了。可用运算符的不同类型如下：

+   创建运算符

+   转换运算符

+   过滤运算符

+   组合运算符

+   错误处理运算符

+   实用运算符

+   布尔运算符

+   数学运算符

运算符的分类为开发人员提供了一个选择适当运算符的良好框架。在本节中，我们将实现以下内容：

+   自定义创建运算符

+   自定义转换运算符

+   涉及调度程序的自定义操作

# 编写自定义创建运算符

大多数 RxCpp 运算符函数接受 Observable 并返回一个 Observable 以实现运算符的组合。我们需要做一些额外的工作，以使组合具有可链式的方式（在下一节中，我们将介绍`lift<t>`和向`RxCpp`库中的`[observable<T>]` Observable 添加运算符的主题）。我们在本节中实现的运算符将帮助我们从输入数据创建一个 Observable。我们可以从任何类型的单个值、一系列值、STL 容器的迭代器、另一个 Observable 等创建 Observable 流。让我们讨论一个接受 STL 容器并创建 Observable 的示例程序，然后进行一些转换：

```cpp
//------ CustomOperator1.cpp 
#include "rxcpp/rx.hpp" 
namespace rx { 
    using namespace rxcpp;  
    using namespace rxcpp::operators; 
    using namespace rxcpp::sources; 
    using namespace rxcpp::util; 
} 

template<typename Container> 
rx::observable<std::string> helloNames(Container items) { 
    auto str = rx::observable<>::iterate(items); 
    return str. 
    filter([](std::string s){ 
        return s.length() > 5; 
    }). 
    map([](std::string s){ 
        return "Hello, " + s + "!"; 
    }). 
    //------ Translating exception 
    on_error_resume_next([](std::exception_ptr){ 
        return rx::error<std::string>(std::runtime_error("custom exception")); 
    }); 
} 
```

`helloNames()`函数接受任何标准库容器并创建一个字符串类型的 Observable（`observable<string>`）。然后对 Observable 进行过滤，以获取长度超过五个字符的项目，并在每个项目前加上`Hello`字符串。发生的异常将通过使用标准 RxCpp 运算符`on_error_resume_next()`进行转换：现在，让我们编写主程序来看看如何使用这个运算符：

```cpp
int main() { 
    //------ Create an observable composing the custom operator 
    auto names = {"Praseed", "Peter", "Joseph", "Sanjay"}; 
    auto value = helloNames(names).take(2); 

    auto error_handler = = { 
        try { rethrow_exception(e); } 
        catch (const std::exception &ex) { 
            std::cerr << ex.what() << std::endl; 
        } 
    }; 

    value. 
    subscribe( 
              [](std::string s){printf("OnNext: %sn", s.c_str());}, 
              error_handler, 
              [](){printf("OnCompletedn");}); 
} 
```

名字列表作为参数传递到新定义的运算符中，我们得到以下输出：

```cpp
OnNext: Hello, Praseed! 
OnNext: Hello, Joseph! 
OnCompleted
```

# 编写自定义转换运算符

让我们编写一个简单的程序，通过组合其他运算符来实现一个自定义运算符，在这个程序中，我们过滤奇数的数字流，将数字转换为其平方，并仅取流中的前三个元素：

```cpp
//------ CustomOperator1.cpp 
#include "rxcpp/rx.hpp" 
namespace rx { 
    using namespace rxcpp; 
    using namespace rxcpp::operators; 
    using namespace rxcpp::sources; 
    using namespace rxcpp::util; 
} 
//------ operator to filter odd number, find square & take first three items 
std::function<rx::observable<int>(rx::observable<int>)> getOddNumSquare() { 
    return [](rx::observable<int> item) { 
        return item. 
        filter([](int v){ return v%2; }). 
        map([](const int v) { return v*v; }). 
        take(3). 
        //------ Translating exception 
        on_error_resume_next([](std::exception_ptr){ 
            return rx::error<int>(std::runtime_error("custom exception")); }); 
    }; 
} 
int main() { 
    //------ Create an observable composing the custom operator 
    auto value = rxcpp::observable<>::range(1, 7) | 
    getOddNumSquare(); 
    value. 
    subscribe( 
              [](int v){printf("OnNext: %dn", v);}, 
              [](){printf("OnCompletedn");}); 
} 
```

在这个例子中，自定义运算符是用不同的方法实现的。运算符函数不是返回所需类型的简单 Observable，而是返回一个接受并返回*int*类型的 Observable 的函数对象。这允许用户使用管道(`|`)运算符执行高阶函数的执行。在编写复杂程序时，使用用户定义的转换实现自定义运算符并将其与现有运算符组合在一起非常方便。通常最好通过组合现有运算符来组合新运算符，而不是从头实现新运算符（不要重复造轮子！）。

# 编写涉及调度程序的自定义运算符

RxCpp 库默认是单线程的，RxCpp 将在调用订阅方法的线程中安排执行。有一些运算符接受调度程序作为参数，执行可以在调度程序管理的线程中进行。让我们编写一个程序来实现一个自定义运算符，以处理调度程序参数：

```cpp
//----------- CustomOperatorScheduler.cpp 
#include "rxcpp/rx.hpp" 
template <typename Duration> 
auto generateObservable(Duration durarion) { 
    //--------- start and the period 
    auto start = rxcpp::identity_current_thread().now(); 
    auto period = durarion; 
    //--------- Observable upto 3 items 
    return rxcpp::observable<>::interval(start, period).take(3); 
} 

int main() { 
    //-------- Create a coordination 
    auto coordination = rxcpp::observe_on_event_loop(); 
    //-------- Instantiate a coordinator and create a worker 
    auto worker = coordination.create_coordinator().get_worker(); 
    //----------- Create an Observable (Replay ) 
    auto values = generateObservable(std::chrono::milliseconds(2)). 
        replay(2, coordination); 
    //--------------- Subscribe first time 
    worker.schedule(& { 
        values.subscribe([](long v) { printf("#1 -- %d : %ldn", 
            std::this_thread::get_id(), v); }, 
                         []() { printf("#1 --- OnCompletedn"); }); 
    }); 
    worker.schedule(& { 
        values.subscribe([](long v) { printf("#2 -- %d : %ldn", 
            std::this_thread::get_id(), v); }, 
                         []() { printf("#2 --- OnCompletedn"); }); }); 
    //----- Start the emission of values 
    worker.schedule(& { 
        values.connect(); 
    }); 
    //------- Add blocking subscription to see results 
    values.as_blocking().subscribe(); 
    return 0; 
} 
```

# 编写可以链式组合的自定义运算符

RxCpp 库提供的内置运算符的一个关键优点是可以使用流畅的接口链式操作运算符。这显著提高了代码的可读性。到目前为止，我们创建的自定义运算符可以组合在一起，但不能像标准运算符那样链式组合。在本节中，我们将实现可以使用以下方法进行链式组合的运算符：

+   使用`lift<T>`元运算符

+   通过向 RxCpp 库添加代码来编写新运算符

# 使用 lift<t>运算符编写自定义运算符

RxCpp 库中的`observable<T>`实现中有一个名为`lift`（`lift<t>`）的操作符。实际上，它可以被称为元操作符，因为它具有将接受普通变量（`int`、`float`、`double`、`struct`等）的`一元`函数或函数对象转换为兼容处理`observable<T>`流的能力。`observable<T>::lift`的 RxCpp 实现期望一个 Lambda，该 Lambda 以`rxcpp::subscriber<T>`作为参数，并且在 Lambda 的主体内，我们可以应用一个操作（Lambda 或函数）。在本节中，可以对`lift<t>`操作符的目的有一个概述。

lift 操作符接受任何函数或 Lambda，该函数或 Lambda 将接受 Observable 的 Subscriber 并产生一个新的 Subscriber。这旨在允许使用`make_subscriber`的外部定义的操作符连接到组合链中。lift 的函数原型如下：

```cpp
template<class ResultType , class operator > 
auto rxcpp::operators::lift(Operator && op) -> 
                 detail::lift_factory<ResultType, operator> 
```

`lift<t>`期望的 Lambda 的签名和主体如下：

```cpp
={ 
         return rxcpp::make_subscriber<T>( 
                dest,rxcpp::make_observer_dynamic<T>( 
                      ={ 
                         //---- Apply an action Lambda on each items 
                         //---- typically "action_lambda" is declared in the 
                         //---- outside scope (captured)
                         dest.on_next(action_lambda(n)); 
                      }, 
                      ={dest.on_error(e);}, 
                      [=](){dest.on_completed();})); 
}; 
```

为了理解`lift<T>`操作符的工作原理，让我们编写一个使用它的程序。`lift<T>`的优势在于所创建的操作符可以成为 RxCpp 库的操作符链式结构的一部分。

```cpp
//----------- operatorLiftFirst.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <iostream> 
namespace rxu=rxcpp::util; 
#include <array> 
using namespace rxcpp; 
using namespace rxcpp::operators; 

int main() { 
     std::array< int ,4 > a={{10, 20,30,40}}; 
     //////////////////////////////////////////////////// 
     // The following Lambda will be lifted  
     auto lambda_fn = [] ( int n ) { return n*2; }; 
     ///////////////////////////////////////////////////////////// 
     // The following Lambda expects a rxcpp::subscriber and returns 
     // a subscriber which implements on_next,on_error,on_completed 
     // The Lambda lifting happens because, we apply lambda_fn on  
     // each item. 
     auto transform = ={ 
         return rxcpp::make_subscriber<int>( 
                dest,rxcpp::make_observer_dynamic<int>( 
                      ={ 
                         dest.on_next(lambda_fn(n)); 
                      }, 
                      ={dest.on_error(e);}, 
                      [=](){dest.on_completed();})); 
     }; 
     // type of values will be observable<int> 
     // Lazy Evaluation  
     auto values = rxcpp::observable<>::iterate(a);  
     //-------- As usual subscribe  
     values.lift<int>(transform).subscribe(  
              [] (int f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
} 
```

我们现在已经学会了如何使用`lift<t>`操作符。`observable<T>`实例及其 lift 方法接受具有特定参数类型的 Lambda 并产生一个`observable<T>`。`lift<T>`的优势在于我们可以使用操作符链式结构。

# 将任意 Lambda 转换为自定义 Rx 操作符

在前一节中，我们了解到可以使用`lift<t>`操作符来实现自定义操作符，这些操作符可以成为 RxCpp 库的操作符链式结构的一部分。`lift<T>`的工作有点复杂，我们将编写一个`Adapter`类来将接受基本类型参数的任意 Lambda 转换为`lift<T>`操作符可以应用的形式。

适配器代码将帮助我们进行这样的调用：

```cpp
observable<T>::lift<T>( liftaction( lambda<T> ) )
```

让我们编写一个`Adapter`类实现和一个通用函数包装器，以便在程序中使用：

```cpp
//----------- operatorLiftSecond.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <iostream> 
namespace rxu=rxcpp::util; 
#include <array> 
using namespace rxcpp; 
using namespace rxcpp::operators; 
///////////////////////////////////////////////// 
// The LiftAction class  ( an adapter class) converts an Action ( a Lambda ) 
// and wraps it into a form which can help us to connect 
// to an observable<T> using the observable<T>::lift<T> method.  
template<class Action> 
struct LiftAction { 
    typedef typename std::decay<Action>::type action_type; 
    action_type action; 

    LiftAction(action_type t): action(t){} 
    ////////////////////////////////////// 
    // Create an Internal observer to gather  
    // data from observable<T>  
    // 
    template<class Subscriber> 
    struct action_observer : public  
              rxcpp::observer_base<typename  
              std::decay<Subscriber>::type::value_type> 
    { 
        ///////////////////////////////////////////// 
        // typedefs for  
        //        * this_type (action_observer) 
        //        * base_type (observable_base)  
        //        * value_type  
        //        * dest_type 
        //        * observer_type 
        typedef action_observer<Subscriber> this_type; 
        typedef rxcpp::observer_base<typename             
                std::decay<Subscriber>::type::value_type> base_type; 
        typedef typename base_type::value_type value_type; 
        typedef typename std::decay<Subscriber>::type dest_type; 
        typedef rxcpp::observer<value_type, this_type> observer_type; 

        //------ destination subscriber and action 
        dest_type dest; 
        action_type action; 
        action_observer(dest_type d, action_type t) 
            : dest(d), action(t){} 

        //--------- subscriber/observer methods 
        //--------  on_next implementation needs more  
        //--------- robustness by supporting exception handling 
        void on_next(typename dest_type::value_type v) const  
        {dest.on_next(action(v));} 
        void on_error(std::exception_ptr e) const  
        { dest.on_error(e);} 
        void on_completed() const { 
            dest.on_completed(); 
        } 
        //--------- Create a subscriber with requisite parameter 
        //--------- types 
        static rxcpp::subscriber<value_type, observer_type>  
                 make(const dest_type& d, const action_type& t) { 
            return rxcpp::make_subscriber<value_type> 
                 (d, observer_type(this_type(d, t))); 
        } 
    }; 
```

在 RxCpp 操作符实现中，我们将有一个内部 Observer 拦截流量，并在将控制传递给链中的下一个操作符之前对项目应用一些逻辑。`action_observer`类就是按照这些方式结构的。由于我们使用 Lambda（延迟评估），只有当调度程序触发执行时，流水线中接收到数据时才会发生执行：

```cpp
    template<class Subscriber> 
    auto operator()(const Subscriber& dest) const 
        -> decltype(action_observer<Subscriber>::make(dest, action)) { 
        return      action_observer<Subscriber>::make(dest, action); 
    } 
}; 
////////////////////////////////////// 
// liftaction takes a Universal reference  
// and uses perfect forwarding  
template<class Action> 
auto liftaction(Action&& p) ->  LiftAction<typename std::decay<Action>::type> 
{  
   return  LiftAction<typename  
           std::decay<Action>::type>(std::forward<Action>(p)); 
} 
```

现在我们已经学会了如何实现`Adapter`类以将 Lambda 转换为`lift<T>`可以接受的形式，让我们编写一个程序来演示如何利用前面的代码：

```cpp
int main() { 
     std::array< int ,4 > a={{10, 20,30,40}}; 
     auto h = [] (observable<int> src ) { 
         return src.map([](int n ) { return n; }); 
     }; 
     auto g = [] (observable<int> src ) { 
         return src.map([](int n ) { return n*2; }); 
     }; 
     // type of values will be observable<int> 
     // Lazy Evaluation  ... the Lift operator 
     // converts a Lambda to be part of operator chaining
     auto values = g(h(rxcpp::observable<>::iterate(a))) 
       .lift<int> (liftaction( [] ( int r ) { return 2*r; }));  
     //-------- As usual subscribe  
     values.subscribe(  
              [] (int f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
} 
```

程序的输出如下：

```cpp
40 
80 
120 
160 
Hello World.. 
```

# 在库中创建自定义 RxCpp 操作符

`RxCpp`库中的每个操作符都在`rxcpp::operators`命名空间下定义。在`rxcpp::operators`命名空间内，库设计者创建了一个名为 details 的嵌套命名空间，其中通常指定了操作符逻辑的实现。为了演示从头开始实现操作符，我们克隆了 map 操作符的实现，创建了另一个名为`eval`的操作符。`eval`的语义与`map`操作符相同。源代码清单可在与本书相关的 GitHub 存储库中的特定章节文件夹中找到。

我们决定将书中的代码移动到 GitHub 存储库，因为清单有点长，对于理解在`RxCpp`库中实现操作符的概念没有太大贡献。前面概述的`liftaction`实现向我们展示了如何编写内部 Observer。每个操作符实现都遵循一个标准模式：

+   它通过创建一个私有 Observer 订阅源 Observable

+   根据操作符的目的转换 Observable 的元素

+   将转换后的值推送给其自己的订阅者

`eval`运算符实现的骨架源代码如下。源文件的实现包括以下内容：

| **源文件** | **关键更改** |
| --- | --- |

| `rx-eval.hpp` | `eval`运算符的实现：

```cpp

//rx-eval.hpp   
#if   !defined(RXCPP_OPERATORS_RX_EVAL_HPP)   
#define   RXCPP_OPERATORS_RX_EVAL_HPP   
//------------ all headers are   included here   
#include "../rx-includes.hpp"   
namespace rxcpp {   
    namespace operators {   
        namespace detail {   
          //-------------- operator   implementation goes here   
        }
    }
}
#endif   

```

|

| `rx-includes.h` | 修改后的头文件，包含了`Rx-eval.hpp`的引入。`rx-includes.h`将在文件中添加一个额外的条目，如下所示：

```cpp
#include "operators/rx-eval.hpp"   
```

|

| `rx-operators.h` | 修改后的头文件，包含了`eval_tag`的定义。`rx-operators.h`包含以下标签条目：

```cpp
struct eval_tag {   
    template<class Included>   
    struct include_header{   
          static_assert(Included::value, 
           "missing include: please 
                   #include   <rxcpp/operators/rx-eval.hpp>");   
};   
};   
```

|

| `rx-observables.h` | 修改后的头文件，其中包含`eval`运算符的定义：

```cpp
template<class... AN>   
auto eval(AN&&... an)   const-> decltype(observable_member(eval_tag{},   
 *(this_type*)nullptr,   std::forward<AN>(an)...)){   
        return    observable_member(eval_tag{},                 
                   *this, std::forward<AN>(an)...);   
}   
```

|

让我们编写一个使用`eval`运算符的程序。`eval`运算符的原型（类似于`map`）如下：

```cpp
observaable<T>::eval<T>( lambda<T>)
```

你可以检查实现的源代码，以更好地理解`eval`运算符。现在，让我们编写一个利用`eval`运算符的程序：

```cpp
//----------- operatorComposeCustom.cpp 
#include "rxcpp/rx.hpp" 
#include "rxcpp/rx-test.hpp" 
#include <iostream> 
namespace rxu=rxcpp::util; 
#include <array> 
using namespace std; 
using namespace rxcpp; 
using namespace rxcpp::operators; 
int main() { 
     std::array< string ,4 > a={{"Bjarne","Kirk","Herb","Sean"}}; 
     auto h = [] (observable<string> src ) { 
          return src.eval([](string s ) { return s+"!"; }); 
     }; 
     //-------- We will Lift g using eval 
     auto g = [](string s) { return "Hello : " + s; }; 
     // use apply h first and then call eval 
     auto values = h(rxcpp::observable<>::iterate(a)).eval(g);  
     //-------- As usual subscribe  
     values.subscribe(  
              [] (string f) { std::cout << f <<  std::endl; } ,  
              [] () {std::cout << "Hello World.." << std::endl;} ); 
} 
```

程序的输出如下：

```cpp
Hello : Bjarne! 
Hello : Kirk! 
Hello : Herb! 
Hello : Sean! 
Hello World.. 
```

编写以通用方式实现的自定义运算符需要对 RxCpp 内部有深入的了解。在尝试自定义运算符之前，您需要了解一些基本运算符的实现。我们编写的运算符可以成为您实现此类运算符的起点。再次强调，从头开始编写自定义运算符应该是最后的选择！

# 摘要

在本章中，我们学习了如何编写自定义运算符。我们首先编写了可以执行基本任务的简单运算符。尽管我们编写的运算符（最初）是可组合的，但我们无法像标准的 RxCpp 运算符那样将它们链接在一起。在编写了不同类型的运算符之后，我们使用`lift<T>`元运算符实现了可链接的自定义运算符。最后，我们看到了如何将运算符添加到`observable<T>`中。在下一章中，我们将深入探讨 Rx 编程的设计模式和习惯用法。我们将从 GOF 设计模式开始，并实现不同的响应式编程模式。
