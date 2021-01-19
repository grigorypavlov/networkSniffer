package com.example.networksniffer.observerpattern;

import java.util.ArrayList;

public interface IPublisher {
    ArrayList<ISubscriber> subscribers = new ArrayList();

    default void Subscribe(ISubscriber s) {
        subscribers.add(s);
    };

    default void Unsubscribe(ISubscriber s) {
        subscribers.remove(s);
    };

    default void Notify() {
        for (ISubscriber s : subscribers) {
            s.Update(null);
        }
    };
}
