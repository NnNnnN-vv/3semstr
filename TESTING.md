# Тестирование CSPRNG: NIST STS

## Процедура

100 последовательностей по 1 000 000 бит из `generate_random_bytes`, NIST STS 2.1.2, 15 тестов, параметры по умолчанию.

```
python -m src.csprng D:\nist\sts-2.1.2\sts-2.1.2\data\cryptocore.bin 12500000
cd D:\nist\sts-2.1.2\sts-2.1.2
mingw32-make CC=gcc
.\assess.exe 1000000
```

Ответы `assess`: `0`, `data/cryptocore.bin`, `1`, `0`, `100`, `1`.

## Результаты

`experiments/AlgorithmTesting/finalAnalysisReport.txt`:

```
------------------------------------------------------------------------------
RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES
------------------------------------------------------------------------------
   generator is <data/cryptocore.bin>
------------------------------------------------------------------------------
 C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST
------------------------------------------------------------------------------
 10   8  12  11  10   9  12   7  13   8  0.935716     98/100     Frequency
  6   6  11  12  13   9  11   7  14  11  0.595549     98/100     BlockFrequency
 11  10   9  12   9   7  13  12   9   8  0.946308     98/100     CumulativeSums
  9   9   7  10  12  13  13   7  12   8  0.834308     98/100     CumulativeSums
  8   9  10  13  16  10   6   9  13   6  0.419021    100/100     Runs
 12   5  12  11   9   7   9  11  12  12  0.798139    100/100     LongestRun
  4   9  12  13  15  10  13   7  10   7  0.334538    100/100     Rank
 13  13   9   8  12   9  11   9   6  10  0.867692     98/100     FFT
 10   7  13  21   6  11   6   6   9  11  0.025193    100/100     NonOverlappingTemplate
 11  13  11  11  13   8  13   6   6   8  0.637119    100/100     NonOverlappingTemplate
  8   9   4   6  14  12  15  10  11  11  0.319084    100/100     NonOverlappingTemplate
 10   9  11  12   7  12   7  12  12   8  0.911413     99/100     NonOverlappingTemplate
 10   8   6  13   7   9  15   5  12  15  0.224821    100/100     NonOverlappingTemplate
 11  13  11   5   9   8   9   5  19  10  0.096578     98/100     NonOverlappingTemplate
 14   9   9   5  15   9   7   9  10  13  0.455937     99/100     NonOverlappingTemplate
  4  10  17  12   8   4   6  14  12  13  0.042808    100/100     NonOverlappingTemplate
  6   9  10  11   9   7  11   8  17  12  0.474986     99/100     NonOverlappingTemplate
 10   2   6   8  13  12  22   5  11  11  0.001509    100/100     NonOverlappingTemplate
 10   8  14   8  13  10   5  10  12  10  0.719747     99/100     NonOverlappingTemplate
  9  12  15  12   7   4  15   9  10   7  0.249284     99/100     NonOverlappingTemplate
  7   9   9  18   6  13   8  10  10  10  0.319084    100/100     NonOverlappingTemplate
  8   7  11  12  11   5  12  11   9  14  0.678686     99/100     NonOverlappingTemplate
 11   9  11  11  11  10   7  10  12   8  0.987896     97/100     NonOverlappingTemplate
  7  10   4  12  12  10   7   8  13  17  0.191687    100/100     NonOverlappingTemplate
 13  11  11   9  14   6   9   7  11   9  0.779188     99/100     NonOverlappingTemplate
  9   6  13   6  11  12   8  11  11  13  0.719747    100/100     NonOverlappingTemplate
  6   6  14   9   6   7  16   8   9  19  0.020548    100/100     NonOverlappingTemplate
 18  12   7   6  10   6  13  11  10   7  0.171867     96/100     NonOverlappingTemplate
 11   6  10  10  10  13  11   9   9  11  0.964295     99/100     NonOverlappingTemplate
  9  10   9   6  11  16  10   7  12  10  0.657933     98/100     NonOverlappingTemplate
 11   9  13  13   8   5   8  15   6  12  0.366918     98/100     NonOverlappingTemplate
  9   8  16  11   9   7   8  11  10  11  0.759756    100/100     NonOverlappingTemplate
 12   8   7  14  14  10   8   8  13   6  0.514124    100/100     NonOverlappingTemplate
  7  14   8   8   9  11   3  12  10  18  0.085587     98/100     NonOverlappingTemplate
  7   9  11   9  12  13   6  12   9  12  0.834308    100/100     NonOverlappingTemplate
 10  13   9  10  11  10  11   7   7  12  0.946308     98/100     NonOverlappingTemplate
  6  12  12  11   6  11  12  11  10   9  0.851383     99/100     NonOverlappingTemplate
 14   8  12   9   6   8  14   7  10  12  0.595549     98/100     NonOverlappingTemplate
 14   7   8   8   6  13  13   7  14  10  0.419021     99/100     NonOverlappingTemplate
 11   5  10   9   8   9  15  10  10  13  0.678686    100/100     NonOverlappingTemplate
 15   7  12  12   6   4  11  14   4  15  0.045675    100/100     NonOverlappingTemplate
  6  11  10   6   9  13   9  15  10  11  0.637119     99/100     NonOverlappingTemplate
  4  13  13  13   9  12  12   7   7  10  0.437274    100/100     NonOverlappingTemplate
  9  12   7  10  11  11  12  10   8  10  0.983453     99/100     NonOverlappingTemplate
 11   5  12  13   6  13  13   9  11   7  0.494392     99/100     NonOverlappingTemplate
  6  11  15  12  11  12   5   9  11   8  0.514124     98/100     NonOverlappingTemplate
  9   9   6   9  14  14  10  12   6  11  0.616305     98/100     NonOverlappingTemplate
  8  14  10   6   8  14  10   8  10  12  0.699313     98/100     NonOverlappingTemplate
 12  11   7  10  14  10   7   7  16   6  0.350485     98/100     NonOverlappingTemplate
  5  14   7  12   9  12   8   6  14  13  0.319084    100/100     NonOverlappingTemplate
 14  11   5   9  21   6   8   8   8  10  0.023545     99/100     NonOverlappingTemplate
 14   7  11  10   7   5  13   9  10  14  0.474986     99/100     NonOverlappingTemplate
  8  12  15   8  16   9  10  10   5   7  0.289667    100/100     NonOverlappingTemplate
 13   5   8  10   8   8  11  11  16  10  0.494392     99/100     NonOverlappingTemplate
 10   8   8  16  15   8   7  10   9   9  0.494392     99/100     NonOverlappingTemplate
 11  16   8   7   8  10  10  10   8  12  0.719747     98/100     NonOverlappingTemplate
 11   9  11  11  12   3   9   6  11  17  0.191687     98/100     NonOverlappingTemplate
  6  16  15  10  10   8   9   6   8  12  0.304126     98/100     NonOverlappingTemplate
 10   7   5   6   7  13  12  11  14  15  0.249284     99/100     NonOverlappingTemplate
 13   8  11   7  13  10  10   8  11   9  0.924076    100/100     NonOverlappingTemplate
 12  16  14   9   6   7   7  11   9   9  0.401199    100/100     NonOverlappingTemplate
 13   9   6   9   7  11  13  12   4  16  0.202268     99/100     NonOverlappingTemplate
  4  14  14  11   9  11  10  11   9   7  0.514124    100/100     NonOverlappingTemplate
 10  11   9  10  10  13   5  15   7  10  0.637119     97/100     NonOverlappingTemplate
 12  12  10   7  13   7  14   4   7  14  0.262249    100/100     NonOverlappingTemplate
 16  10  11   9  13   8  11  10   4   8  0.419021    100/100     NonOverlappingTemplate
 14  11  10   3   9   8  10   7  13  15  0.249284    100/100     NonOverlappingTemplate
  6  12   6   9  12   7   6  14  17  11  0.153763     98/100     NonOverlappingTemplate
  9   7  12  10  10   8   9   8  10  17  0.616305     99/100     NonOverlappingTemplate
  8   9  17  11  14  14   6   6   5  10  0.108791     99/100     NonOverlappingTemplate
  7   8  12   8   9  10  20   6  10  10  0.129620     99/100     NonOverlappingTemplate
  9   8   7  15   8  16  11  11   8   7  0.401199     99/100     NonOverlappingTemplate
 11   5  16   9   6  13   9  11   8  12  0.366918     98/100     NonOverlappingTemplate
  9   8  15   5  10  14   9   8  11  11  0.554420     99/100     NonOverlappingTemplate
  9  11   6  11   8  12  13   9  13   8  0.834308     98/100     NonOverlappingTemplate
  9  10  15  10   5   7   9  10  13  12  0.595549     99/100     NonOverlappingTemplate
 10  10   7   6  10   5  10  17  11  14  0.236810     99/100     NonOverlappingTemplate
 12   8   9   8  14   8  13  10   6  12  0.719747     99/100     NonOverlappingTemplate
  4   9   9  16   9  11   9   9  11  13  0.455937     99/100     NonOverlappingTemplate
 11   8  11  18  10  14   9   6   7   6  0.171867    100/100     NonOverlappingTemplate
 10   6  12   8   9  11  12  15   4  13  0.350485     99/100     NonOverlappingTemplate
  3   9   6  11  17  11  15  10  10   8  0.102526     99/100     NonOverlappingTemplate
 10   7  13  21   6  11   6   6   8  12  0.020548    100/100     NonOverlappingTemplate
  8  12  10   8   9  14   4  10  12  13  0.554420     98/100     NonOverlappingTemplate
 11   9   9  14   5  16   8  10   8  10  0.455937    100/100     NonOverlappingTemplate
 12   6  21   9   5   5  11  12   6  13  0.008266    100/100     NonOverlappingTemplate
  8   7  10   8  12  12   4  12  14  13  0.437274     97/100     NonOverlappingTemplate
  8  11  13   8   9   5  12  14  10  10  0.699313     99/100     NonOverlappingTemplate
 17   6   8   8  14  15   8   8   7   9  0.153763     99/100     NonOverlappingTemplate
 12   4   7   9  11  13  10  13  10  11  0.637119    100/100     NonOverlappingTemplate
 12   9   7  13  12   8  14  10   4  11  0.494392     99/100     NonOverlappingTemplate
 10   4   9   8  11  14  10  11  10  13  0.657933    100/100     NonOverlappingTemplate
 15  12   8  13  10  10   6  14   8   4  0.249284     99/100     NonOverlappingTemplate
 15  13   6  10   3  14  12   6  10  11  0.137282    100/100     NonOverlappingTemplate
 14  11  11  13   9   9   5  10  10   8  0.759756     98/100     NonOverlappingTemplate
 13  10  10   9   8  11   7  13   8  11  0.924076     98/100     NonOverlappingTemplate
  7  10  15   6   6   9  10  13  16   8  0.236810    100/100     NonOverlappingTemplate
  9   9  13  12  14   7   6  14   9   7  0.514124     99/100     NonOverlappingTemplate
 14   8   9  10   9   8   7  14  12   9  0.779188    100/100     NonOverlappingTemplate
 13  10  10  10  13   9   8   7   7  13  0.834308     97/100     NonOverlappingTemplate
  8   7   8  11  10  11   8  15  11  11  0.834308    100/100     NonOverlappingTemplate
 10  12  12   8  11  12  11  10  10   4  0.798139    100/100     NonOverlappingTemplate
  9  10   7   9   9  13  13   7  14   9  0.779188     99/100     NonOverlappingTemplate
  9   5   8  14   8  13  14  10  10   9  0.574903     99/100     NonOverlappingTemplate
  8   6   7   9   9  12  10  12  11  16  0.574903     99/100     NonOverlappingTemplate
 11  10   8  14  11   7   8  10   9  12  0.911413     99/100     NonOverlappingTemplate
 15   7  12   8   7   9   8  14  13   7  0.437274    100/100     NonOverlappingTemplate
  7  11   6  10  12  15  13   8  11   7  0.554420    100/100     NonOverlappingTemplate
 12  13   7   7   6  13  10  13   8  11  0.637119     99/100     NonOverlappingTemplate
 10   7  10  14  12  13   7   6   8  13  0.574903    100/100     NonOverlappingTemplate
  7   9   8  10  10  13  10   7  15  11  0.759756    100/100     NonOverlappingTemplate
 13  14   2   5   6  12   9  14  12  13  0.058984     97/100     NonOverlappingTemplate
  7  10   9  10  12   8   7   8  13  16  0.574903    100/100     NonOverlappingTemplate
  9  13  10   8  11   9  13   9   9   9  0.971699    100/100     NonOverlappingTemplate
 12  11  12  11  12   6   8  13  10   5  0.657933     99/100     NonOverlappingTemplate
  5  13   2  10  14   8  13  11  15   9  0.080519     99/100     NonOverlappingTemplate
  6  11   6  13  13  13   4  11  10  13  0.304126    100/100     NonOverlappingTemplate
 10  11   8  10  11   9  11  10   9  11  0.999438     99/100     NonOverlappingTemplate
  8  12  16   3  14  10   7   8  14   8  0.115387    100/100     NonOverlappingTemplate
 11   7   8   7  10  13   6   7  17  14  0.202268     98/100     NonOverlappingTemplate
  9  11   6   7  13   8   6  15  10  15  0.304126     98/100     NonOverlappingTemplate
 12  14   6  10  13  13   7   2   9  14  0.108791     99/100     NonOverlappingTemplate
 10  15   7   2  12   8  15  11  12   8  0.122325    100/100     NonOverlappingTemplate
 11   6   9  11  12  12   4  12  12  11  0.616305    100/100     NonOverlappingTemplate
  3  13  14  11  12   9   9  11   6  12  0.334538    100/100     NonOverlappingTemplate
 10   9  13  14   5   9   8   8   9  15  0.474986    100/100     NonOverlappingTemplate
 10  11   7   6   8   6  14  12  11  15  0.419021    100/100     NonOverlappingTemplate
 12   4  14  13  12   8   7   9   7  14  0.289667     99/100     NonOverlappingTemplate
 10  15  12  10   9  13   8   9   8   6  0.699313    100/100     NonOverlappingTemplate
 15  14   7   9   7  11  10   7  15   5  0.213309     99/100     NonOverlappingTemplate
  9  11  11  10   6  11  13   7  11  11  0.911413     99/100     NonOverlappingTemplate
  9  14   8   8   8  11  10  13  12   7  0.816537    100/100     NonOverlappingTemplate
  9   8   8  12  12  14   7  10   8  12  0.834308     99/100     NonOverlappingTemplate
  9   6  13  11  12  11  12   5   8  13  0.595549    100/100     NonOverlappingTemplate
 15  10   9   9  10  11  11   8   9   8  0.924076     98/100     NonOverlappingTemplate
 12   6   9  11   6  12   9  13  13   9  0.719747     99/100     NonOverlappingTemplate
 14  11   8   7   6  18   5  16   5  10  0.020548     98/100     NonOverlappingTemplate
 12   7  14   4   7  12  16   5  10  13  0.096578    100/100     NonOverlappingTemplate
  9   7   8  11   8  17  13   8   9  10  0.514124     99/100     NonOverlappingTemplate
  8  10  10  13  11   9  14   6   6  13  0.616305     99/100     NonOverlappingTemplate
 12  12  12   5  13   6   9   7  15   9  0.366918     99/100     NonOverlappingTemplate
 11  13  11  16   8   7   9  10  11   4  0.366918    100/100     NonOverlappingTemplate
  6  12  14  11  11   7  10  10  10   9  0.851383    100/100     NonOverlappingTemplate
 15   8   8  15   5  15   9   5  10  10  0.145326    100/100     NonOverlappingTemplate
  8  11   9  14   9  15  10   8   9   7  0.719747     98/100     NonOverlappingTemplate
 10  16  10   7  13   5  11   9   7  12  0.401199     99/100     NonOverlappingTemplate
 12   8   9  13  11  13   6  10  11   7  0.798139    100/100     NonOverlappingTemplate
  8  13   8   9  11   7  13  11  10  10  0.924076     99/100     NonOverlappingTemplate
 10   8  11  10   8   9  13  10  12   9  0.983453     97/100     NonOverlappingTemplate
  6  14   7  10   8   8  18   8  10  11  0.224821     99/100     NonOverlappingTemplate
  9   7  16  10  10   9  10   9   6  14  0.534146    100/100     NonOverlappingTemplate
  6   8  13  11   8   9   9  11  12  13  0.834308     99/100     NonOverlappingTemplate
  8  11   6   9  13  14  11   8  14   6  0.494392    100/100     NonOverlappingTemplate
  8  14  11  11  12   7  11  13   3  10  0.401199     98/100     NonOverlappingTemplate
 12   6  12   8   8  10  13  10  11  10  0.897763    100/100     NonOverlappingTemplate
  3   9   6  11  18  10  15  10  10   8  0.066882     99/100     NonOverlappingTemplate
 15   6  13   6  10   9   8  10  10  13  0.534146    100/100     OverlappingTemplate
 12   8  15  11   6   8  10  12   3  15  0.153763    100/100     Universal
 15  15   5  11   6  12  10   7   9  10  0.304126     97/100     ApproximateEntropy
  6   7   3   2   6  10   5   6   8   6  0.275709     58/59      RandomExcursions
  6   5   4   7   4  10   4   1   4  14  0.001895     59/59      RandomExcursions
  6   3   4   4   2   7   9   8   6  10  0.115387     58/59      RandomExcursions
  7   4   6   6   6   2   3   9   8   8  0.275709     56/59      RandomExcursions
  5   4  10   9   6   5   7   5   5   3  0.334538     59/59      RandomExcursions
  9   8   1   4  12   6   6   4   3   6  0.019188     59/59      RandomExcursions
  6   5   5   4   6   5   4   8   8   8  0.719747     58/59      RandomExcursions
 10   3   5   8   8   9   5   4   4   3  0.129620     56/59      RandomExcursions
  7   3   9   4   4   7   7   8   6   4  0.437274     59/59      RandomExcursionsVariant
  6   6   8   7   3   2  10   7   5   5  0.249284     59/59      RandomExcursionsVariant
  5   8   7   7   2   2   9   6   8   5  0.202268     59/59      RandomExcursionsVariant
  8   1   8   5   5   6   4   6   8   8  0.275709     59/59      RandomExcursionsVariant
  8   0   7   4   7   5   6  13   6   3  0.007160     57/59      RandomExcursionsVariant
  8   3   6   7   3   7   4  14   4   3  0.007160     57/59      RandomExcursionsVariant
  8   1  12   6   2   3   8   7   6   6  0.014550     58/59      RandomExcursionsVariant
  7   2   6   7   2  11   4  10   8   2  0.010988     58/59      RandomExcursionsVariant
  4   4   4   5   7   7  10   5   8   5  0.437274     59/59      RandomExcursionsVariant
  4   7   3   8   4   5   5   5   8  10  0.304126     57/59      RandomExcursionsVariant
  6   4   6   9   5   7   6   5   7   4  0.759756     58/59      RandomExcursionsVariant
  8   5   5   7   7   5   6   7   2   7  0.637119     59/59      RandomExcursionsVariant
  9   5   4   9   8   7   3   3   6   5  0.275709     58/59      RandomExcursionsVariant
  9   5   6   5   5   6   8   3   6   6  0.678686     58/59      RandomExcursionsVariant
  8   7   4   8   3   5   6   6   8   4  0.554420     58/59      RandomExcursionsVariant
 10   7   7   3   6   3   2   2  12   7  0.007160     58/59      RandomExcursionsVariant
 13   3   4   6   3   3   7   4   6  10  0.009535     58/59      RandomExcursionsVariant
 10   5   2   5   6   5   8   4   5   9  0.202268     59/59      RandomExcursionsVariant
  5  12  12  12  13   6   6  13   8  13  0.350485    100/100     Serial
  8  15  10   9  10  10  10  10   7  11  0.911413     99/100     Serial
 13  12  10   7  12   7   9  11  10   9  0.924076    100/100     LinearComplexity


- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
The minimum pass rate for each statistical test with the exception of the
random excursion (variant) test is approximately = 96 for a
sample size = 100 binary sequences.

The minimum pass rate for the random excursion (variant) test
is approximately = 56 for a sample size = 59 binary sequences.

For further guidelines construct a probability table using the MAPLE program
provided in the addendum section of the documentation.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

Тесты пройдены.
