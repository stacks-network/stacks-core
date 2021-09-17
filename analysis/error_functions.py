
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


all_functions = [
        RootMeanSquaredError,
        Bias,
        ]
