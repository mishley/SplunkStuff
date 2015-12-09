#!/usr/bin/env python
#
# no license because I'm lazy

import sys
import math
import re
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from collections import Counter

def entropyCalc(s):
    p, lns = Counter(s), float(len(s))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

scoreTable = {"a": 1, "c": 3, "b": 3, "e": 1, "d": 2, "g": 2, "f": 4, "i": 1, "h": 4, "k": 5, "j": 8, "m": 3, "l": 1, "o": 1, "n": 1, "q": 10, "p": 3, "s": 1, "r": 1, "u": 1, "t": 1, "w": 4, "v": 4, "y": 4, "x": 8, "z": 10}
def scrabbleCalc(s):
    s = s.lower()
    t = []
    for l in s:
        if l in scoreTable.keys():
            t.append(scoreTable[l])
    return sum(t)

@Configuration()
class scrabbleCommand(StreamingCommand):
    """ Calculates a "Scrabble score" for the given field and returns the result
    in the return field. Can also be used to calculate the entropy of a given
    string instead.

    ##Syntax

    .. code-block::
        scrabble fieldname=<field> entropy=<boolean> <returnfield>

    ##Description

    The "Scrabble score" of a given `fieldname` is calculated and returned via a
    new field `returnfield`. If `fieldname` does not exist in the result, event 
    records are passed through to the next pipeline processor unmodified. If 
    `returnfield` exists, its value is replaced. If `returnfield` does not exist,
    it is created.
    
    A Scrabble score is determined by evaluating each character
    of the alphabet in a given fieldname-value against the following table:
    
    1 point: E, A, I, O, N, R, T, L, S, U
    2 points: D, G
    3 points: B, C, M, P
    4 points: F, H, V, W, Y
    5 points: K
    8 points: J, X
    10 points: Q, Z
    
    The sum of the score of all letters is then returned in a new field, 
    specified by the <returnfield> argument. Any non-letter string characters 
    are effectively ignored in the calculation by returning a value of 0.
    
    This command can also be used to calculate the Shannon entropy of a given input
    field value. If the entropy argument is set to True, the cumulative entropy of 
    the string is calculated and returned instead of the Scrabble score. This 
    calculation is byte-centric, it therefore does take into account the values of
    numeric and special characters.
    
    Example entropy values of English words and randomly-generated strings:
    
    English dictionary word entropy value examples:
    Burton -> 2.584963
    jingoism -> 2.750000
    scanties -> 2.750000
    calypso -> 2.807355
    potfuls -> 2.807355
    tackles -> 2.807355
    lighthearted -> 3.084963
    topographers -> 3.084963
    Srivijaya's -> 3.095795
    
    Randomly-generated string entropy value examples:
    $1_)'ejuaa!m)na|)ZFm -> 3.746439
    SI[bkpVS[CVx[mGPljGs -> 3.784184
    EpTRpCUKoZCU]jvbFzv] -> 3.821928
    c525IFWRaShQphuQN2em -> 3.921928
    CEaiOZTjYOsDRroYpEBT -> 3.921928
    YlFxlVpaH]O1fd]ynVSF -> 3.921928
    dY(wy])=F!?|}>4)C/d1 -> 4.121928
    pdFqCxnTxbE2eWokVEBQ -> 4.121928
    \6">y.&dR:n{X!+Hc[my -> 4.221928

    ##Example

    Calculate the Scrabble score of a fieldname "url" and return the value
    in the new field "url_score":

    .. code-block::
        | scrabble fieldname=url returnfield=url_score
    
    Calculate the entropy of a given fieldname "filename" and return the 
    value in the new field "filename_score":
    
    .. code-block::
        | scrabble fieldname=filename returnfield=filename_score entropy=t

    """
    fieldname = Option(
        doc='''
        **Syntax:** **fieldname=***<fieldname>*
        **Description:** Name of the field that will be used to calculate score''',
        require=True, validate=validators.Fieldname())

    returnfield = Option(
        doc='''
        **Syntax:** **returnfield=***<fieldname>*
        **Description:** Name of the field that will hold the score''',
        require=True, validate=validators.Fieldname())

    entropy = Option(
        doc='''
        **Syntax:** **pattern=***<boolean>*
        **Description:** Boolean to enable entropy calculation, disabled by default.''',
        require=False, default=False, validate=validators.Boolean())

    def stream(self, records):
        self.logger.debug('scrabbleCommand: %s' % self)  # logs command line
        for record in records:
            if not record[self.fieldname]:
                yield record
                continue
            score = 0.0
            if self.entropy:
                score += entropyCalc(record[self.fieldname])
            else:
                score += scrabbleCalc(record[self.fieldname])
            record[self.returnfield] = score
            yield record

dispatch(scrabbleCommand, sys.argv, sys.stdin, sys.stdout, __name__)
