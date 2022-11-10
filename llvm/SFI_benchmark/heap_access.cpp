//
// Created by Jerry Zhang on 11/9/22.
//


#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define EXE_TIMES 1000000000
clock_t start, end;
double cpu_time_used;

int main() {
  int *memory = (int *)malloc(sizeof(int) * 10);
  start = clock();
  for (int i = 0; i < EXE_TIMES; i++) {
    memory[3] = 10023;
  }
  end = clock();
  cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
  printf("time used: %lf\n", cpu_time_used);
  return 0;
}