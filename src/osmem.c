// SPDX-License-Identifier: BSD-3-Clause

#include "../utils/osmem.h"
#define MMAP_THRESHOLD (128 * 1024)
#define PAGE_SIZE (4 * 1024)

struct block_meta *head;
void coalesce(struct block_meta *blk);
void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	struct block_meta *p, *best = NULL, *ant;
	size_t best_size = MMAP_THRESHOLD;
	size_t total_size = ALIGN(STRUCT_SIZE) + ALIGN(size);
	int heap_used = 0;

	if (!head) {
		if (total_size < MMAP_THRESHOLD) {
			head = (struct block_meta *)sbrk(MMAP_THRESHOLD);
			DIE(head == (void *)-1, "eroare sbrk");
			head->size = MMAP_THRESHOLD - ALIGN(STRUCT_SIZE);
			head->status = STATUS_ALLOC;
			head->prev = NULL;
			head->next = NULL;
			return (void *)head + ALIGN(STRUCT_SIZE);
		}
		head = (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		DIE(head == (void *)-1, "eroare mmap");
		head->size = size;
		head->status = STATUS_MAPPED;
		head->next = NULL;
		head->prev = NULL;
		return (void *)head + ALIGN(STRUCT_SIZE);
	}

	if (total_size < MMAP_THRESHOLD) {
		for (p = head; p; p = p->next) {
			if (p->status == STATUS_FREE)
				coalesce(p);
		}
		for (p = head, ant = NULL; p; ant = p, p = p->next) {
			if (heap_used == 0 && (p->status == STATUS_ALLOC || p->status == STATUS_FREE))
				heap_used = 1;
			if (p->status == STATUS_FREE && ALIGN(p->size) >= ALIGN(size) && ALIGN(p->size) < ALIGN(best_size)) {
				best = p;
				best_size = p->size;
			}
		}
		if (!ant)
			ant = head;
		if (!heap_used) {
			ant->next = (struct block_meta *)sbrk(MMAP_THRESHOLD);
			DIE(ant->next == (void *)-1, "eroare sbrk");
			ant->next->size = MMAP_THRESHOLD - ALIGN(STRUCT_SIZE);
			ant->next->status = STATUS_ALLOC;
			ant->next->prev = ant;
			ant->next->next = NULL;
			return (void *)ant->next + ALIGN(STRUCT_SIZE);
		}
		if (!best) {
			if (ant->status != STATUS_FREE) {
				ant->next = (struct block_meta *)sbrk(total_size);
				DIE(ant->next == (void *)-1, "eroare sbrk");
				ant->next->size = size;
				ant->next->status = STATUS_ALLOC;
				ant->next->prev = ant;
				ant->next->next = NULL;
				return (void *)ant->next + ALIGN(STRUCT_SIZE);
			}
			void *ret = sbrk(ALIGN(size) - ALIGN(ant->size));

			DIE(ret == (void *)-1, "eroare sbrk");
			ant->size = size;
			ant->status = STATUS_ALLOC;
			return (void *)ant + ALIGN(STRUCT_SIZE);
		}
		best->status = STATUS_ALLOC;
		if (ALIGN(best->size) > total_size) {
			struct block_meta *new = (struct block_meta *)((void *)best + total_size);

			new->prev = best;
			new->next = best->next;
			if (best->next)
				best->next->prev = new;
			best->next = new;
			new->size = ALIGN(best->size) - total_size;
			best->size = size;
			new->status = STATUS_FREE;
		}
		return (void *)best + ALIGN(STRUCT_SIZE);
	}
	p = head;
	while (p && p->next)
		p = p->next;
	p->next = (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	DIE(p->next == (void *)-1, "eroare mmap");
	p->next->size = size;
	p->next->status = STATUS_MAPPED;
	p->next->next = NULL;
	p->next->prev = p;
	return (void *)p->next + ALIGN(STRUCT_SIZE);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;
	struct block_meta *p = (struct block_meta *)(ptr - ALIGN(STRUCT_SIZE));

	if (p->status == STATUS_FREE) {
		return;
	} else if (p->status == STATUS_ALLOC) {
		p->status = STATUS_FREE;
		return;
	}
	struct block_meta *temp = p;

	if (p->next)
		p->next->prev = p->prev;
	if (p->prev)
		p->prev->next = p->next;
	else
		head = NULL;
	int ret = munmap((void *)temp, ALIGN(STRUCT_SIZE) + ALIGN(p->size));

	DIE(ret == -1, "eroare munmap");
}

void coalesce(struct block_meta *blk)
{
	int gata = 0;

	while (!gata) {
		gata = 1;
		for (struct block_meta *p = head; p; p = p->next) {
			if (p->status == STATUS_FREE && (size_t)((void *)p-(void *)blk) == ALIGN(STRUCT_SIZE) + ALIGN(blk->size)) {
				if (p->prev)
					p->prev->next = p->next;
				if (p->next)
					p->next->prev = p->prev;
				blk->size = ALIGN(blk->size) + ALIGN(STRUCT_SIZE) + p->size;
				p = blk;
				gata = 0;
			}
		}
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;
	struct block_meta *p, *best = NULL, *ant;
	size_t best_size = MMAP_THRESHOLD;
	size_t payload_size = nmemb * size;
	size_t total_size = ALIGN(STRUCT_SIZE) + ALIGN(payload_size);
	int heap_used = 0;

	if (!head) {
		if (total_size < PAGE_SIZE) {
			head = (struct block_meta *)sbrk(MMAP_THRESHOLD);
			DIE(head == (void *)-1, "eroare sbrk");
			head->size = MMAP_THRESHOLD - ALIGN(STRUCT_SIZE);
			head->status = STATUS_ALLOC;
			head->prev = NULL;
			head->next = NULL;
			memset((void *)head + ALIGN(STRUCT_SIZE), 0, ALIGN(head->size));
			return (void *)head + ALIGN(STRUCT_SIZE);
		}
		head = (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		DIE(head == (void *)-1, "eroare mmap");
		head->size = payload_size;
		head->status = STATUS_MAPPED;
		head->next = NULL;
		head->prev = NULL;
		memset((void *)head + ALIGN(STRUCT_SIZE), 0, ALIGN(head->size));
		return (void *)head + ALIGN(STRUCT_SIZE);
	}
	if (total_size < PAGE_SIZE) {
		for (p = head; p; p = p->next) {
			if (p->status == STATUS_FREE)
				coalesce(p);
		}
		for (p = head, ant = NULL; p; ant = p, p = p->next) {
			if (heap_used == 0 && (p->status == STATUS_ALLOC || p->status == STATUS_FREE))
				heap_used = 1;
			if (p->status == STATUS_FREE && ALIGN(p->size) >= ALIGN(payload_size) && ALIGN(p->size) < ALIGN(best_size)) {
				best = p;
				best_size = p->size;
			}
		}
		if (!heap_used) {
			if (!ant)
				ant = head;
			ant->next = (struct block_meta *)sbrk(MMAP_THRESHOLD);
			DIE(ant->next == (void *)-1, "eroare sbrk");
			ant->next->size = MMAP_THRESHOLD - ALIGN(STRUCT_SIZE);
			ant->next->status = STATUS_ALLOC;
			ant->next->prev = ant;
			ant->next->next = NULL;
			memset((void *)ant->next + ALIGN(STRUCT_SIZE), 0, ALIGN(ant->next->size));
			return (void *)ant->next + ALIGN(STRUCT_SIZE);
		}

		if (!best) {
			if (!ant)
				ant = head;
			if (ant->status != STATUS_FREE) {
				ant->next = (struct block_meta *)sbrk(total_size);
				DIE(ant->next == (void *)-1, "eroare sbrk");
				ant->next->size = payload_size;
				ant->next->status = STATUS_ALLOC;
				ant->next->prev = ant;
				ant->next->next = NULL;
				memset((void *)ant->next + ALIGN(STRUCT_SIZE), 0, ALIGN(ant->next->size));
				return (void *)ant->next + ALIGN(STRUCT_SIZE);
			}
			void *ret = sbrk(ALIGN(payload_size) - ALIGN(ant->size));

			DIE(ret == (void *)-1, "eroare sbrk");
			ant->size = payload_size;
			ant->status = STATUS_ALLOC;
			memset((void *)ant + ALIGN(STRUCT_SIZE), 0, ALIGN(ant->size));
			return (void *)ant + ALIGN(STRUCT_SIZE);
		}
		best->status = STATUS_ALLOC;
		memset((void *)best + ALIGN(STRUCT_SIZE), 0, ALIGN(best->size));
		if (ALIGN(best->size) > total_size) {
			struct block_meta *new = (struct block_meta *)((void *)best + total_size);

			new->prev = best;
			new->next = best->next;
			if (best->next)
				best->next->prev = new;
			best->next = new;
			new->size = ALIGN(best->size) - total_size;
			best->size = payload_size;
			new->status = STATUS_FREE;
		}
		return (void *)best + ALIGN(STRUCT_SIZE);

	}
	p = head;
	while (p && p->next)
		p = p->next;
	p->next = (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	DIE(p->next == (void *) -1, "eroare mmap");
	p->next->size = payload_size;
	p->next->status = STATUS_MAPPED;
	p->next->next = NULL;
	p->next->prev = p;
	memset((void *)p->next + ALIGN(STRUCT_SIZE), 0, ALIGN(p->next->size));
	return (void *)p->next + ALIGN(STRUCT_SIZE);
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *blk = (struct block_meta *)(ptr - ALIGN(STRUCT_SIZE));
	size_t total_size = ALIGN(STRUCT_SIZE) + ALIGN(size);

	if (blk->status == STATUS_ALLOC) {
		if (size < ALIGN(blk->size)) {
			if (ALIGN(blk->size) > total_size) {
				struct block_meta *new = (struct block_meta *)((void *)blk + total_size);

				new->prev = blk;
				new->next = blk->next;
				if (blk->next)
					blk->next->prev = new;
				blk->next = new;
				new->size = ALIGN(blk->size) - total_size;
				blk->size = size;
				new->status = STATUS_FREE;
			}
			return (void *)blk + ALIGN(STRUCT_SIZE);
		} else if (ALIGN(size) == ALIGN(blk->size)) {
			return ptr;
		} else if (size > ALIGN(blk->size) && total_size < MMAP_THRESHOLD && (size_t)(sbrk(0) - (void *)blk) != ALIGN(STRUCT_SIZE) + ALIGN(blk->size)) {
			coalesce(blk);
			if (size <= ALIGN(blk->size)) {
				if (ALIGN(blk->size) > total_size) {
					struct block_meta *new = (struct block_meta *)((void *)blk + total_size);

					new->prev = blk;
					new->next = blk->next;
					if (blk->next)
						blk->next->prev = new;
					blk->next = new;
					new->size = ALIGN(blk->size) - total_size;
					blk->size = size;
					new->status = STATUS_FREE;
				}
				return (void *)blk + ALIGN(STRUCT_SIZE);
			}
			struct block_meta *p, *ant, *best = NULL;
			size_t best_size = MMAP_THRESHOLD;

			for (p = head; p; p = p->next) {
				if (p->status == STATUS_FREE && (size_t)((void *)blk-(void *)p) != ALIGN(STRUCT_SIZE) + ALIGN(p->size)) {
					//ultima conditie e pentru a evita coalesce la stanga
					coalesce(p);
				}
			}
			for (p = head, ant = NULL; p; ant = p, p = p->next) {
				if (p->status == STATUS_FREE && ALIGN(p->size) >= ALIGN(size) && ALIGN(p->size) < ALIGN(best_size)) {
					best = p;
					best_size = p->size;
				}
			}
			blk->status = STATUS_FREE;
			if (!best) {
				if (!ant)
					ant = head;
				if (ant->status != STATUS_FREE) {
					ant->next = (struct block_meta *)sbrk(total_size);
					DIE(ant->next == NULL, "eroare sbrk");
					ant->next->size = size;
					ant->next->status = STATUS_ALLOC;
					ant->next->prev = ant;
					ant->next->next = NULL;
					memcpy((void *)ant->next + ALIGN(STRUCT_SIZE), (void *)blk + ALIGN(STRUCT_SIZE), size);
					return (void *)ant->next + ALIGN(STRUCT_SIZE);
				}
				void *ret = sbrk(ALIGN(size) - ALIGN(ant->size));

				DIE(ret == (void *)-1, "eroare sbrk");
				ant->size = size;
				ant->status = STATUS_ALLOC;
				memcpy((void *)ant + ALIGN(STRUCT_SIZE), (void *)blk + ALIGN(STRUCT_SIZE), size);
				return (void *)ant + ALIGN(STRUCT_SIZE);
			}
			best->status = STATUS_ALLOC;
			if (ALIGN(best->size) > total_size) {
				struct block_meta *new = (struct block_meta *)((void *)best + total_size);

				new->prev = best;
				new->next = best->next;
				if (best->next)
					best->next->prev = new;
				best->next = new;
				new->size = ALIGN(best->size) - total_size;
				best->size = size;
				new->status = STATUS_FREE;
			}
			memcpy((void *)best + ALIGN(STRUCT_SIZE), (void *)blk + ALIGN(STRUCT_SIZE), blk->size);
			return (void *)best + ALIGN(STRUCT_SIZE);
		} else if (size > ALIGN(blk->size) && total_size < MMAP_THRESHOLD) {
			void *ret = sbrk(ALIGN(size) - ALIGN(blk->size));

			DIE(ret == (void *)-1, "eroare sbrk");
			blk->size = size;
			return (void *)blk + ALIGN(STRUCT_SIZE);
		} else if (size > ALIGN(blk->size) && total_size >= MMAP_THRESHOLD) {
			struct block_meta *aux = (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

			DIE(aux == (void *)-1, "eroare mmap");
			aux->size = size;
			aux->status = STATUS_MAPPED;
			aux->prev = blk;
			aux->next = blk->next;
			if (aux->next)
				aux->next->prev = aux;
			blk->next = aux;
			blk->status = STATUS_FREE;
			memcpy((void *)aux + ALIGN(STRUCT_SIZE), (void *)blk + ALIGN(STRUCT_SIZE), blk->size);
			return (void *)aux + ALIGN(STRUCT_SIZE);
		}
	} else if (blk->status == STATUS_MAPPED) {
		if (size < blk->size && total_size < MMAP_THRESHOLD) {
			void *ret = os_malloc(size);

			DIE(ret == (void *)-1, "eroare os_malloc");
			if (blk->prev)
				blk->prev->next = blk->next;
			if (blk->next)
				blk->next->prev = blk->prev;
			memcpy(ret, (void *)blk + ALIGN(STRUCT_SIZE), size);
			DIE(munmap(blk, ALIGN(STRUCT_SIZE) + ALIGN(blk->size)) == -1, "eroare munmap");
			return (void *)ret;

		} else if ((size < blk->size && total_size > MMAP_THRESHOLD) || size > blk->size) {
			struct block_meta *aux = (struct block_meta *)mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

			DIE(aux == (void *)-1, "eroare mmap");
			aux->size = size;
			aux->status = STATUS_MAPPED;
			aux->prev = blk->prev;
			aux->next = blk->next;
			if (aux->prev)
				aux->prev->next = aux;
			if (aux->next)
				aux->next->prev = aux;
			memcpy((void *)aux + ALIGN(STRUCT_SIZE), (void *)blk + ALIGN(STRUCT_SIZE), size);
			DIE(munmap(blk, ALIGN(STRUCT_SIZE) + ALIGN(blk->size)) == -1, "eroare munmap");
			return (void *)aux + ALIGN(STRUCT_SIZE);
		}
	}
	return NULL;
}
