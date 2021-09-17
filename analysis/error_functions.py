
UNDERESTIMATE_PENALTY_FACTOR = 2.0

def RootMeanSquaredError(gold_costs, pred_costs):
    assert len(gold_costs) == len(pred_costs)
    sigma = 0.0
    for gold, pred in zip(gold_costs,pred_costs):
        delta = gold - pred
        sigma += delta ** 2
    
    avg = sigma / len(gold_costs)
    root = avg ** 0.5
    return root

def Bias(gold_costs, pred_costs):
    assert len(gold_costs) == len(pred_costs)
    sigma = 0.0
    for gold, pred in zip(gold_costs,pred_costs):
        delta = pred - gold
        sigma += delta
    
    avg = sigma / len(gold_costs)
    return avg


def RelativeBias(gold_costs, pred_costs):
    assert len(gold_costs) == len(pred_costs)
    sigma = 0.0
    num_points = 0
    for gold, pred in zip(gold_costs,pred_costs):
        if gold == 0.0:
            continue
        rel_delta = (pred - gold) / gold
        sigma += rel_delta
        num_points += 1
    
    avg = sigma / num_points
    return avg

def AbsoluteDifference(gold_costs, pred_costs):
    assert len(gold_costs) == len(pred_costs)
    sigma = 0.0
    for gold, pred in zip(gold_costs,pred_costs):
        delta = abs(pred - gold)
        sigma += delta
    
    avg = sigma / len(gold_costs)
    return avg

def RelativeAbsoluteDifference(gold_costs, pred_costs):
    assert len(gold_costs) == len(pred_costs)
    sigma = 0.0
    num_points = 0
    for gold, pred in zip(gold_costs,pred_costs):
        if gold == 0.0:
            continue
        delta = abs(pred - gold) / gold
        sigma += delta
        num_points += 1
    
    avg = sigma / num_points
    return avg

def PenalizedDifference(gold_costs, pred_costs):
    assert len(gold_costs) == len(pred_costs)
    sigma = 0.0
    for gold, pred in zip(gold_costs,pred_costs):
        if pred > gold:
            penalty_factor = 1.0
        else:
            penalty_factor = UNDERESTIMATE_PENALTY_FACTOR
        delta = penalty_factor * abs(pred - gold)
        sigma += delta
    avg = sigma / len(gold_costs)
    return avg

def RelativePenalizedDifference(gold_costs, pred_costs):
    assert len(gold_costs) == len(pred_costs)
    sigma = 0.0
    for gold, pred in zip(gold_costs,pred_costs):
        if gold == 0.0:
            continue
        if pred > gold:
            penalty_factor = 1.0
        else:
            penalty_factor = UNDERESTIMATE_PENALTY_FACTOR
        delta = penalty_factor * abs(pred - gold) / gold
        sigma += delta
    avg = sigma / len(gold_costs)
    return avg

all_functions = [
        RootMeanSquaredError,
        Bias,
        RelativeBias,
        AbsoluteDifference,
        RelativeAbsoluteDifference,
        PenalizedDifference,
        RelativePenalizedDifference,
        ]
