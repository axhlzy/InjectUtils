#pragma once

#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/sync/interprocess_semaphore.hpp>
#include <iostream>
#include <string>

namespace bip = boost::interprocess;

struct Message {
    int id;
    char data[256];
};

class MessageQueue {
public:
    MessageQueue() {
        try {
            managed_shm = bip::managed_shared_memory(bip::open_or_create, "MySharedMemory", 65536);
        } catch (const bip::interprocess_exception &ex) {
            std::cerr << "Error creating shared memory: " << ex.what() << std::endl;
            return;
        }
        messages = managed_shm.construct<bip::vector<Message>>("MessageVector")();
        sem_produce = managed_shm.construct<bip::interprocess_semaphore>("ProducerSemaphore")(0);
        sem_consume = managed_shm.construct<bip::interprocess_semaphore>("ConsumerSemaphore")(0);
    }

    void send(const Message &msg) {
        messages->push_back(msg);
        sem_produce->post(); // 释放一个信号量，表示有新消息
    }

    Message receive() {
        sem_produce->wait();                // 等待直到有新消息
        Message msg = messages->front();    // 获取消息
        messages->erase(messages->begin()); // 移除已处理的消息
        return msg;
    }

private:
    bip::managed_shared_memory managed_shm;
    bip::vector<Message> *messages;
    bip::interprocess_semaphore *sem_produce;
    bip::interprocess_semaphore *sem_consume;
};