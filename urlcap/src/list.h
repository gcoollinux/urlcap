/*
 * =====================================================================================
 *
 *       Filename:  list.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月16日 17时05分32秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef LIST_H
#define LIST_H
struct Node{
    void *value;
    struct Node *next;
};

struct Queue{
    struct Node *head;
    struct Node *tail;
    pthread_mutex_t mutex;
    int count;
};

void initQueue(struct Queue *queue);
int setQueue(struct Queue *queue,void *value);
void* getQueue(struct Queue *queue);
struct Node* findQueue(struct Queue *queue,void *value);
void desQueue(struct Queue *queue);
#endif
