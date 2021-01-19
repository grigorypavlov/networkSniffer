package com.example.networksniffer.observerpattern;

public interface IPublisher {
    void Subscribe(ISubscriber s);
    void Unsubscribe(ISubscriber s);
    void Notify();
}
