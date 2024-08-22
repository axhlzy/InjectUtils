#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_help(const char* name)
{
    fprintf(stdout, "OVERVIEW: Converts binary file to C header\n\n");
    fprintf(stdout, "USAGE: %s [-i <input>] [-o <output>] [-n <name>] [-d] [-e] [-s] [-z]\n\n", name);
    fprintf(stdout, "OPTIONS:\n"
        "	-d				Print decimal instead of hex literals\n"
        "	-e				Output a variable that holds a pointer to the last element of the data\n"
        "	-i <input>		Specify the input file (default: stdin)\n"
        "	-n <name>		Specify the variable name (default: data)\n"
        "	-o <output>		Specify the output file (default: stdout)\n"
        "	-s				Output a variable for data size\n"
        "	-z				Add a zero to the end of the array\n");
}

static void generate_output(FILE* input_s,
                            FILE* output_s,
                            const char* name,
                            int zero_terminate,
                            int decimal,
                            int end_variable,
                            int size_variable)
{
    int byte;
    unsigned int i = 0U;

    fprintf(output_s, "unsigned char %s[] = {", name);

    while ((byte = getc(input_s)) != EOF)
    {
        if (i != 0U) fprintf(output_s, ", ");
        fprintf(output_s, decimal ? "%d" : "0x%02X", byte);
        ++i;
    }

    if (zero_terminate)
    {
        if (i != 0U) fprintf(output_s, ", ");
        fprintf(output_s, decimal ? "0" : "0x00");
        ++i;
    }

    fprintf(output_s, "};\n");

    if (i > 0U && end_variable)
        fprintf(output_s, "unsigned char* %s_end = %s + %uU;\n", name, name, i - 1U);

    if (size_variable)
        fprintf(output_s, "unsigned int %s_size = %uU;\n", name, i);
}

int main(int argc, char* argv[])
{
    int result = EXIT_FAILURE;
    int arg;
    FILE* input_f = NULL;
    FILE* output_f = NULL;
    const char* input = NULL;
    const char* output = NULL;
    const char* name = "data";

    int zero_terminate = 0;
    int decimal = 0;
    int end_variable = 0;
    int size_variable = 0;

    if (argc < 2)
    {
        print_help(argv[0]);
        return EXIT_SUCCESS;
    }

    for (arg = 1; arg < argc; ++arg)
    {
        if (strcmp(argv[arg], "-h") == 0 ||
            strcmp(argv[arg], "--help") == 0)
        {
            print_help(argv[0]);
            return EXIT_SUCCESS;
        }
        else if (strcmp(argv[arg], "-i") == 0)
        {
            if (++arg >= argc)
            {
                fprintf(stderr, "Missing argument for -i\n");
                return EXIT_FAILURE;
            }
            input = argv[arg];
        }
        else if (strcmp(argv[arg], "-o") == 0)
        {
            if (++arg >= argc)
            {
                fprintf(stderr, "Missing argument for -o\n");
                return EXIT_FAILURE;
            }
            output = argv[arg];
        }
        else if (strcmp(argv[arg], "-n") == 0)
        {
            if (++arg >= argc)
            {
                fprintf(stderr, "Missing argument for -n\n");
                return EXIT_FAILURE;
            }
            name = argv[arg];
        }
        else if (strcmp(argv[arg], "-z") == 0)
            zero_terminate = 1;
        else if (strcmp(argv[arg], "-d") == 0)
            decimal = 1;
        else if (strcmp(argv[arg], "-s") == 0)
            size_variable = 1;
        else if (strcmp(argv[arg], "-e") == 0)
            end_variable = 1;
        else
        {
            fprintf(stderr, "Invalid argument: %s\n", argv[arg]);
            return EXIT_FAILURE;
        }
    }

    if (input)
    {
        input_f = fopen(input, "rb");

        if (!input_f)
        {
            fprintf(stderr, "Failed to open input file\n");
            goto exit;
        }
    }

    if (output)
    {
        output_f = fopen(output, "w");

        if (!output_f)
        {
            fprintf(stderr, "Failed to open output file\n");
            goto exit;
        }
    }

    generate_output(input_f ? input_f : stdin,
                    output_f ? output_f : stdout,
                    name, zero_terminate, decimal, end_variable, size_variable);

    result = EXIT_SUCCESS;
exit:
    if (input_f) fclose(input_f);
    if (output_f) fclose(output_f);

    return result;
}