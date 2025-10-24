#include <stdio.h>
#include <rte_eal.h>
#include <rte_lcore.h>

int main(int argc, char **argv)
{
    int ret;
    unsigned lcore_id;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error al inicializar EAL\n");

    printf("Listado de lcores trabajadores:\n");
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        printf(" - lcore_id = %u\n", lcore_id);
    }

    rte_eal_cleanup();

    return 0;
}
