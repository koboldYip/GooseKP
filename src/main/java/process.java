import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import lombok.SneakyThrows;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class process {

    @SneakyThrows
    public static void main(String[] args) {
        XmlMapper xmlMapper = new XmlMapper();
        Root value = xmlMapper.readValue(new File("src/main/resources/Cfg.xml"), Root.class);
        ControlBlock controlBlock = new ControlBlock();
        List<GOOSE> gse = new ArrayList<>();
        controlBlock.setGooseList(gse);
        value.getSenders().forEach(dataSet -> gse.add(new GOOSE(dataSet)));

        Executors.newSingleThreadScheduledExecutor().schedule(
                () -> {
                    value.getSenders().get(0).getItems().get(0).setValue("true");
                    value.getSenders().get(0).getItems().get(1).setValue("228");
                    value.getSenders().get(0).getItems().get(2).setValue("14.2");
                    controlBlock.changeGoose(gse.get(0));
                }
                , 10, TimeUnit.SECONDS);

        controlBlock.sender();

    }
}
