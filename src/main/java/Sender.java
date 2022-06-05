import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class Sender {

    private List<GOOSE> gooseList = new ArrayList<>();

    public void sender() {
        while (!gooseList.isEmpty()) {
            gooseList.parallelStream().forEach(GOOSE::send);
        }
    }

    public void changeGoose(GOOSE gse) {
        gooseList.stream()
                .filter(goose -> goose == gse)
                .findFirst()
                .ifPresent(GOOSE::setData);
    }
}
