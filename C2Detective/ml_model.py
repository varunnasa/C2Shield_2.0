import sys
import csv
import collections
import string
import math
import json
import re
import pandas as pd
import pickle
from string import ascii_lowercase as al, ascii_uppercase as au, digits as dg, punctuation as pt
import matplotlib.pyplot as plt
import numpy as np
from pandas.plotting import scatter_matrix
from sklearn.model_selection import (StratifiedShuffleSplit, cross_val_predict,
RandomizedSearchCV, GridSearchCV, cross_validate)
from sklearn.linear_model import SGDClassifier, LogisticRegression
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
f1_score, precision_recall_curve)
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.neighbors import KNeighborsClassifier
from scipy.stats import randint
from sklearn.ensemble import (VotingClassifier, RandomForestClassifier,
ExtraTreesClassifier)
# from sklearn.externals import joblib
from tabulate import tabulate
# from feature_vector_creation import *


"""
Helper Functions and Classes
"""


url_characters = al + au + dg + "$-_+!*'()," # Common characters in an URL


class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'


def get_letters_ratio(original_string):
    """
    Get the ratio of letters in a string
    """
    if len(original_string) > 0:
        return len(list(filter(str.isalpha, original_string))) / len(original_string)
    return 0


def get_digits_ratio(original_string):
    """
    Get the ratio of digits in a string
    """
    if len(original_string) > 0:
        return len(list(filter(lambda ch: not ch.isalpha() and ch.isalnum(), original_string))) / len(original_string)
    return 0


def get_symbols_ratio(original_string):
    """
    Get the ratio of symbols in a string
    """
    if len(original_string) > 0:
        return len(list(filter(lambda ch: not ch.isalnum(), original_string))) / len(original_string)
    return 0


def get_longest_number_string(original_string):
    """
    Get the longest string of consecutive numbers in a string
    For example in 'a1b23c456de7f' it would return '456'
    """
    longest_number_string = ''
    regex = r'([0-9]+)'
    matches = re.findall(regex, original_string)
    if matches:
        longest_number_string = max(matches, key=len)
    return longest_number_string


def get_longest_number_string_ratio(original_string):
    """
    Wrapper for get_longest_number_string
    It returns the ratio compared to the total length
    """
    if len(original_string) > 0:
        return len(get_longest_number_string(original_string)) / len(original_string)
    return 0


def get_longest_letters_string(original_string):
    """
    Get the longest string of consecutive letters in a string
    For example in 'a1b23c456de7f' it would return 'de'
    """
    longest_letters_string = ''
    regex = r'([a-zA-Z]+)'
    matches = re.findall(regex, original_string)
    if matches:
        longest_letters_string = max(matches, key=len)
    return longest_letters_string


def get_longest_letters_string_ratio(original_string):
    """
    Wrapper for get_longest_letters_string
    It returns the ratio compared to the total length
    """
    if len(original_string) > 0:
        return len(get_longest_letters_string(original_string)) / len(original_string)
    return 0


def get_all_substrings(original_string):
    """
    Get all the contiguous substrings in a string
    """
    substrings = []
    for i in range(len(original_string)):
        for j in range(i, len(original_string)):
            substrings.append(original_string[i:j+1])
    return substrings


def has_digits_or_punctuation(original_string):
    """
    Check if a string has any digit or symbols
    """
    return any(char.isdigit() or char in pt for char in original_string)


# nltk.download('words')

def get_longest_meaningful_word(original_string):
    """
    Get the longest substring that belongs to the English dictionary
    has_digits_or_punctuation is needed because enchant understands digit
    strings and some symbols as valid words
    """
    english_vocab = set(words.words())
    substrings = set(get_all_substrings(original_string))
    longest_meaningful_word = ''
    for substring in substrings:
        if (not has_digits_or_punctuation(substring) and
            substring.lower() in english_vocab and
            len(substring) > len(longest_meaningful_word)):
            longest_meaningful_word = substring
    return longest_meaningful_word


def get_longest_meaningful_word_ratio(original_string):
    """
    Wrapper for get_longest_meaningful_word
    It returns the ratio compared to the total length
    """
    if len(original_string) > 0:
        return len(get_longest_meaningful_word(original_string)) / len(original_string)
    return 0


# Iterator to calculate entropies.
# ord(c) returns an integer representing the Unicode character.
def range_url(): return (ord(c) for c in url_characters)


def metric_entropy(data, iterator=range_url):
    """
    Returns the metric entropy (Shannon's entropy divided by string length)
    for some data given a set of possible data elements
    Based on: http://pythonfiddle.com/shannon-entropy-calculation/
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator():
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy / len(data)


"""
Functions to create feature vectors. Each function creates a different type of vector.
Several functions are created to check the performance of different feature vectors.
"""


def extract_features_with_letter_counting(query, attack):
    """
    Extract the features for a DNS query string counting all the letters in the string
    in proportion with the total length of the query
    The features are:
        - Count of alphanumeric characters (a: 0.375, b: 0.25, c: 0.125...)
        - Number of non-alphanumeric characters (symbols: 0.125)
        - Longest consecutive number in the string (longest_number: 0.25)
    """
    length = len(query)
    if length > 0:
        # Create dictionary with the number of repetitions of the alphanumeric
        # characters in proportion with the length of the query
        features = {x:(query.count(x) / length) for x in al+dg}
    else:
        # Create emtpy dictionary for empty string
        features = {x:0 for x in al+dg}
    # The symbols in proportion with the total length
    features['symbols'] = get_symbols_ratio(query)
    # Feature that measures the longest string of numbers that are together in proportion with the total length
    features['longest_number'] = get_longest_number_string_ratio(query)
    features['attack'] = attack
    return features


def extract_features_with_letters_and_numbers(query, attack):
    """
    Extract the features for a DNS query string counting all the letters,
    numbers and symbols in proportion with the total length of the query
    The features are:
        - Count of letters (letters: 0.8)
        - Count of numbers (numbers: 0.1)
        - Number of non-alphanumeric characters (symbols: 0.1)
        - Longest consecutive number in the string (longest_number: 0.1)
    """
    features = {}
    # Count the letters
    features['letters'] = get_letters_ratio(query)
    # Count the numbers
    features['numbers'] = get_digits_ratio(query)
    # Count the symbols
    features['symbols'] = get_symbols_ratio(query)
    # Count the longest number
    features['longest_number'] = get_longest_number_string_ratio(query)
    features['attack'] = attack
    return features


def extract_features_reduced(query, attack):
    """
    Extract the features for a DNS query string
    The features are:
        - Number of alphanumeric characters in proportion to the query's length (alphanumeric: 0.8)
        - Longest consecutive number in the string in proportion to the query's length (longest_number: 0.1)
    """
    length = len(query)
    # Create dictionary to hold the values
    features = {'alphanumeric': 0, 'longest_number': 0}
    if length > 0:
        # Alphanumeric characters in query
        query_alphanumeric = list(filter(str.isalnum, query))
        # Count the number of repetitions of the alphanumeric characters
        features['alphanumeric'] = len(query_alphanumeric) / length
        # Feature that measures the longest string of numbers that are together
        features['longest_number'] = get_longest_number_string_ratio(query)
    features['attack'] = attack
    return features


def extract_features_entropy_and_ratios(query, attack):
    """
    Extract the features for a DNS query string
    The features are:
        - Letters ratio
        - Digits ratio
        - Entropy
        - Longest letters string
        - Longest digit string
        - Longest meaningful word
        - Symbols ratio
    Note: The features have the naming format "x_feature", where x is a number,
    to keep the previous feature order after they were renamed for consistency
    """
    features = {}
    features['attack'] = attack
    features['0_letters'] = get_letters_ratio(query)
    features['1_numbers'] = get_digits_ratio(query)
    features['2_entropy'] = metric_entropy(query)
    features['3_longest_letters'] = get_longest_letters_string_ratio(query)
    features['4_longest_number'] = get_longest_number_string_ratio(query)
    # features['5_longest_meaningful'] = get_longest_meaningful_word_ratio(query)
    features['5_symbols'] = get_symbols_ratio(query)
    return features


"""
Main functions
TODO: Refactor to use 'parse_BRO_log_file'
"""


def create_feature_vector_from_log_file(infile, FV_function,query_prediction):
    """
    Open log file with DNS queries and create feature vector
    infile: log file
    FV_function: chosen function to create feature vector
    """
    slash_position = infile.rfind('/') # used in case the infile is a path to the file
    outfile = infile[:slash_position + 1] + "FV_" + infile[slash_position + 1:]

    feature_dictionary_list = []

    with open(infile) as inf, open(outfile, 'w') as outf:
        for row in inf:
            row = json.loads(row)
            if "query" in row:
                if "qtype" in row and row["qtype"]==33:
                    continue
                
                IP = row['id.resp_h']
                query = row['query'].split('.')[0]
                # print(type(".".join(row["query"].split('.')[-2:])))
                flag = False
                with open("config/domain_whitelist.txt", "r") as file:
                    # Iterate through each line in the file
                    for line in file:
                        # print(line.strip())
                        if line.strip() == ".".join(row["query"].split('.')[-2:]) :
                            flag = True
                            break
                if flag:
                    # print(".".join(row["query"].split('.')[-2:]), "found in whitelist")
                    continue
                
                query_prediction.append({'src':IP , 'query': row['query'] , 'prediction': None})
                # Determine the attack tag and extract features for query
                attack = 1 if IP == '1.1.1.1' else 0
                features = FV_function(query, attack)
                outf.write("%s - %s | Features: %s\n" % (query, IP, features))
                # Append to features list
                feature_dictionary_list.append(features)
        # Create DataFrame from dictionary
        df = pd.DataFrame(feature_dictionary_list).fillna(0)
    return df


def create_feature_vector_from_log_file_tunnelling(infile, FV_function):
    """
    Open log file with DNS queries and create feature vector.
    Treats files with tunnelling data, where the attacks are directed to
    the domain 'test.com'.
    infile: log file
    FV_function: chosen function to create feature vector
    """
    slash_position = infile.rfind('/') # used in case the infile is a path to the file
    outfile = infile[:slash_position + 1] + "FV_" + infile[slash_position + 1:]

    feature_dictionary_list = []

    with open(infile) as inf, open(outfile, 'w') as outf:
        for row in csv.reader(inf, delimiter='\t'):
            if row and row[0][0] != '#':
                # Parse the domain and query from file
                try:
                    domain = row[9].split('.')[-2] + '.' + row[9].split('.')[-1]
                except IndexError:
                    domain = ''
                query = row[9].split('.')[0]
                # Determine the attack tag and extract features for query
                # The attacks are directed to the domain 'test.com'
                attack = 1 if domain == 'test.com' else 0
                features = FV_function(query, attack)
                outf.write("%s - %s | Features: %s\n" % (query, domain, features))
                # Append to features list
                feature_dictionary_list.append(features)
        # Create DataFrame from dictionary
        df = pd.DataFrame(feature_dictionary_list).fillna(0)

    return df

"""
Plotting functions
"""


def plot_dataset(X, y, xlabel, ylabel, alpha=0.1, legend_position='lower right'):
    """
    Plots the dataset.
    If there are more than two features, only the first two will be displayed.
    """
    # Plot the no attacks (y==0) with the two features
    plt.plot(X[:, 0][y==0], X[:, 1][y==0], 'bs', alpha=alpha, label="No attack")
    # Plot the attacks (y==1) with the two features
    plt.plot(X[:, 0][y==1], X[:, 1][y==1], 'r^', alpha=alpha, label="Attack")
    plt.grid(True, which='both')
    plt.xlabel(xlabel, fontsize=16)
    plt.ylabel(ylabel, fontsize=16)
    leg = plt.legend(loc=legend_position, fontsize=16)
    # In order to show the legend with an alpha of 1
    for lh in leg.legendHandles:
        lh._legmarker.set_alpha(1)


def plot_precision_recall_vs_threshold(precisions, recalls, thresholds):
    """
    Plots the precision and recall curves vs threshold.
    Used to analyse the SGD classifiers.
    It expects the "precisions" and "recalls" that are returned from the function
    "precision_recall_curve", so it removes the last value, as there is no
    corresponding threshold.
    """
    plt.plot(thresholds, precisions[:-1], 'b--', label="Precision", linewidth=2)
    plt.plot(thresholds, recalls[:-1], 'g-', label="Recall", linewidth=2)
    plt.xlabel("Threshold", fontsize=16)
    plt.legend(loc='upper left', fontsize=16)
    plt.ylim([0, 1])
    plt.grid(True, which='both')


def plot_predictions_for_logistic_regression(clf, axes):
    """
    Plots the predictions for a logistic regression model in a 2-D graph.
    """
    # Generate 1000 numbers for predictions, from the lowest axes to the highest
    x0s = np.linspace(axes[0], axes[1], 1000)
    x1s = np.linspace(axes[2], axes[3], 1000)
    # Create two matrices with all the numbers generated before
    # x0 represents the first feature, x1 the second feature
    x0, x1 = np.meshgrid(x0s, x1s)
    # Combine the two matrices to generate a combined feature vector
    X = np.c_[x0.ravel(), x1.ravel()]
    # Get the predicitons of the clasifier for our generated feature vector
    # y_proba holds two predictions (one per class) for each generated instance in X
    y_proba = clf.predict_proba(X)
    # Generate the different decision probability boundaries
    zz = y_proba[:, 1].reshape(x0.shape)
    contour = plt.contour(x0, x1, zz, 4) # Countour lines, 4 data intervals
    # Generate the main decision boundary
    left_right = np.array([axes[0], axes[1]])
    boundary = -(clf.coef_[0][0] * left_right + clf.intercept_[0]) / clf.coef_[0][1]
    # Plot the boundary lines that have been just generated
    plt.clabel(contour, inline=1, fontsize=12) # Print contour lines with label
    plt.plot(left_right, boundary, 'k--', linewidth=3)


def plot_predictions_for_SVC(clf, axes):
    """
    Plots the predictions and decision function values for a SVC model in a 2-D graph.
    """
    # Generate 100 numbers for predictions, from the lowest axes to the highest
    x0s = np.linspace(axes[0], axes[1], 100)
    x1s = np.linspace(axes[2], axes[3], 100)
    # Create two matrices with all the numbers generated before
    # x0 represents the first feature, x1 the second feature
    x0, x1 = np.meshgrid(x0s, x1s)
    # Combine the two matrices to generate a combined feature vector
    X = np.c_[x0.ravel(), x1.ravel()]
    # Get the predicitons of the clasifier for our generated feature vector
    y_pred = clf.predict(X).reshape(x0.shape)
    # Get the decision function of the sample for each class in the model
    # (this is the distance of the samples to the separating boundary or hyperplane)
    y_decision = clf.decision_function(X).reshape(x0.shape)
    # Plot the area of the predictions
    plt.contourf(x0, x1, y_pred, cmap=plt.cm.brg, alpha=0.2) # Filled countour
    # Plot the are of the decision function
    plt.contourf(x0, x1, y_decision, 10, cmap=plt.cm.brg, alpha=0.1) # Filled contour, 10 data intervals


def plot_predictions_for_KNN(clf, axes):
    """
    Plots the predictions for a KNN model in a 2-D graph.
    """
    # Generate 1000 numbers for predictions, from the lowest axes to the highest
    x0s = np.linspace(axes[0], axes[1], 1000)
    x1s = np.linspace(axes[2], axes[3], 1000)
    # Create two matrices with all the numbers generated before
    # x0 represents the first feature, x1 the second feature
    x0, x1 = np.meshgrid(x0s, x1s)
    # Combine the two matrices to generate a combined feature vector
    X = np.c_[x0.ravel(), x1.ravel()]
    # Get the predicitons of the clasifier for our generated feature vector
    y_pred = clf.predict(X).reshape(x0.shape)
    # Plot a color area around the different neighbors depending on their predicitons
    plt.pcolormesh(x0, x1, y_pred, cmap=plt.cm.binary)


"""
Data preparation functions
"""


def split_train_and_test_sets(data, target_variable, test_size=0.2):
    """
    Splits a given feature vector in a (80%) train set and (20%) test set.
    Uses Stratified Sampling with the variable passed in "target_variable".
    "data" must include the target_variable.
    """
    split = StratifiedShuffleSplit(n_splits=1, test_size=test_size, random_state=13)
    for train_index, test_index in split.split(data, data[target_variable]):
        train_set = data.loc[train_index]
        test_set = data.loc[test_index]
    return train_set, test_set


"""
Validation, evaluation and scoring functions
"""


def cross_validate_models(models, features, labels, scoring, cv=5, n_jobs=-1, return_train_score=False):
    """
    Gets a list of models and the data to train them.
    Returns the results of doing cross validation to all of them using the
    "scoring", "cv" and "n_jobs" passed as parameters.
    """
    results = []
    for model in models:
        cv_results = cross_validate(model, features, labels, scoring=scoring, cv=cv, n_jobs=n_jobs, return_train_score=return_train_score)
        results.append(cv_results)
    return results


def get_cross_validate_scores(cv_results, names, scoring):
    """
    Gets a list of cross validation results and the name of the models that have been used.
    Returns the test scores of these models as given in "scoring".
    It assumes that all the scores in scoring were returned by the cross validation.
    """
    cross_validate_scores = {}
    for result, name in zip(cv_results, names):
        scores = {}
        for score in scoring:
            scores[score] = np.mean(result['test_' + score])
        cross_validate_scores[name] = scores
    return cross_validate_scores


def evaluate_model_with_precision_and_recall(model, X_test, y_test):
    """
    Evaluates the predictions of a "model" for the data "X_test".
    Returns the precision, recall and F1 scores after comparing the predictions
    to the real values contained in "y_test".
    Also the confusion matrix is returned.
    """
    final_predictions = model.predict(X_test)
    final_precision = precision_score(y_test, final_predictions)
    final_recall = recall_score(y_test, final_predictions)
    final_f1 = f1_score(y_test, final_predictions)
    final_confusion_matrix = confusion_matrix(y_test, final_predictions)
    return final_precision, final_recall, final_f1, final_confusion_matrix


def print_scores(vector_name, scores):
    """
    Returns a string to print the scores in a nice format with a vector name.
    """
    scores_string = color.BOLD + vector_name + color.END + "\n"
    for model, model_scores in scores.items():
        scores_string += color.UNDERLINE + model + color.END + "\n"
        scores_string += tabulate([(sc_name, sc_result)
        for sc_name, sc_result in model_scores.items()], tablefmt="plain") + "\n"
    return scores_string

def start(input_log_file='pcaps/json_streaming_dns.log'):
    with open('models/knn.pkl', 'rb') as f:
        loaded_model = pickle.load(f)
    query_prediction = []
    df = create_feature_vector_from_log_file(input_log_file, extract_features_entropy_and_ratios,query_prediction)
    df = pd.concat([df], ignore_index=True)
    df.drop("attack",axis=1,inplace=True)
    res = loaded_model.predict(df)
    count = 0
    for i in range(len(res)):
        query_prediction[i]["prediction"] = res[i]
    # print("--------->",len(query_prediction),"&&&&&",len(res),"<-------------")
    for i in res:
        if i==1:
            count+=1
    print((len(res)-count)/len(res)*100)
    # print(query_prediction)
    result = pd.DataFrame(query_prediction)
    return result
    
