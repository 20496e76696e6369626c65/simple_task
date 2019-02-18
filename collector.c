#include <stdio.h>
#include <stdlib.h>

#define STACK_MAX_SIZE 256
#define IGCT 8

typedef enum 
{
	INT,
	TWIN,
} ObjectType;

typedef struct sObject
{

	ObjectType type;
	unsigned char marked;

	struct sObject* next;
	
	union 
	{
		int value;

		struct 
		{
			struct ObjectType* head;
			struct ObjectType* tail;
		};
	};
}Object;

typedef struct
{
	Object* stack[STACK_MAX_SIZE];
	int stackSize;

	Object* firstObj;
	int numObj;
	int maxObj;
}Vm;

void push(Vm* vm, Object* val)
{
	vm->stack[vm->stackSize++] = val;
}

Object* pop(Vm* vm)
{
	return vm->stack[--vm->stackSize];
}


Vm* newVm()
{
	Vm* mainVm = (Vm*)malloc(sizeof(Vm));
	mainVm->stackSize = 0;
	mainVm->firstObj = NULL;
	mainVm->numObj = 0;
	mainVm->maxObj = IGCT;
	return mainVm;
}



void mark(Object* obj)
{
	if (obj->marked) return;

	obj->marked = 1;

	if (obj->type == TWIN)
	{
		mark(obj->head);
		mark(obj->tail);
	}
}

void markAll(Vm* vm)
{
	for (int i = 0; i < vm->stackSize; i++)
	{
		mark(vm->stack[i]);
	}
}

void markSpeep(Vm* vm)
{
	Object** obj = &vm->firstObj;
	while (*obj)
	{
		if (!(*obj)->marked)
		{
			Object* unreached = *obj;
			*obj = unreached->next;
			free(unreached);
			vm->numObj--;
		}
		else
		{
			(*obj)->marked = 0;
			obj = &(*obj)->next;
		}
	}
}

void gc(Vm* vm)
{
	int numObj = vm->numObj;
	markAll(vm);
	markSpeep(vm);

	vm->maxObj = vm->numObj * 2;
	printf("Collected %d objects, %d left.\n", numObj - vm->numObj, vm->numObj);
}


Object* newObject(Vm* vm, ObjectType type)
{
	if (vm->numObj == vm->maxObj) gc(vm);


	Object* obj = (Object*)malloc(sizeof(Object));
	obj->type = type;
	obj->next = vm->firstObj;
	vm->firstObj = obj;
	obj->marked = 0;
	vm->numObj++;

	return obj;
}

void pushInt(Vm* vm, int tmp)
{
	Object* obj = newObject(vm, INT);
	obj->value = tmp;
	push(vm, obj);
}


Object* pushPair(Vm* vm)
{
	Object* obj = newObject(vm, TWIN);
	obj->tail = pop(vm);
	obj->head = pop(vm);

	push(vm, obj);
	return obj;
}


void objectPrint(Object* obj) {
	switch (obj->type) {
	case INT:
		printf("%d", obj->value);
		break;

	case TWIN:
		printf("(");
		objectPrint(obj->head);
		printf(", ");
		objectPrint(obj->tail);
		printf(")");
		break;
	}
}

void freeVM(Vm *vm) {
	vm->stackSize = 0;
	gc(vm);
	free(vm);
}

int main(int argc, const char** argv)
{
	printf("1: Objects on the stack are preserved.\n");

	Vm* vm = newVm();

	for (int i = 0; i < 1000; i++) {
		for (int j = 0; j < 20; j++) {
			pushInt(vm, i);
		}

		for (int k = 0; k < 20; k++) {
			pop(vm);
		}
	}
	freeVM(vm);
	system("pause");
	return 0;
}