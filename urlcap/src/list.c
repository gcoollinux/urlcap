/*
 * =====================================================================================
 *
 *       Filename:  Queue.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年11月15日 13时11分23秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "list.h"


void initQueue(struct Queue *queue)
{
   if(queue)
   {
       queue->head = NULL;
       queue->tail = NULL;
       queue->count = 0;
       pthread_mutex_init(&queue->mutex,NULL);
   }
}

int setQueue(struct Queue *queue,void *value)
{
    struct Node *node;

    if(!queue)
    {
        return -1;
    }
    node = (struct Node*)malloc(sizeof(struct Node));
    if(!node)
    {
        return -1;
    }
    
    pthread_mutex_lock(&queue->mutex);
    node->value = value;
    node->next = NULL;
    if(!queue->head)
    {
        queue->head = node;
    }
    else
    {
        if(!queue->tail)
        {
            queue->tail = node;
        }
        else
        {
            queue->tail->next = node;
            queue->tail = node;
        }
    }
    queue->count++;
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

void* getQueue(struct Queue *queue)
{
    void* value;
    struct Node *node;
    
    if(!queue)
    {
        return NULL;
    }

    value = NULL;
    pthread_mutex_lock(&queue->mutex);
    node = queue->head;
    if(node)
    {
        queue->head = node->next;
        value = node->value;
        free(node);
    }
    else
    {
        if(queue->head == queue->tail)
        {
            queue->head = queue->tail;
            queue->tail = NULL;
        }
    }
    if(queue->count!=0)
    {
        queue->count--;
    }
    pthread_mutex_unlock(&queue->mutex);
    return value;
}

struct Node* findQueue(struct Queue *queue,void *value)
{
    struct Node *node;
    
    if(!queue)
        return NULL;
    pthread_mutex_lock(&queue->mutex);
    node =queue->head;
    while(node)
    {
        if(node->value == value)
        {
            return node;
        }
        node  = node->next;
    }
    pthread_mutex_unlock(&queue->mutex);
    return NULL;
}

void desQueue(struct Queue *queue)
{
   struct Node *node;
   struct Node *next_node;
   void* value;
   node = queue->head;
   while(node)
   {
       value = node->value;
       if(value)
       {
           free(value);
       }
       next_node = node->next;
       free(node);
       node = next_node;
   }
   queue->count = 0;
   pthread_mutex_destroy(&queue->mutex);
}
