
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


all_functions = [
        RootMeanSquaredError,
        Bias,
        RelativeBias,
        AbsoluteDifference,
        RelativeAbsoluteDifference,
        ]
