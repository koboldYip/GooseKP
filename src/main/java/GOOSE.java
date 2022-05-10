import lombok.Data;
import lombok.SneakyThrows;
import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Data
public class GOOSE implements Runnable {

    private byte[] destination = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] source = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private final byte[] type = {(byte) 0x88, (byte) 0xB8};

    private final byte[] appID = {0x00, 0x01};
    private final byte[] length = {0x00, 0x00};
    private final byte[] reserved1 = {0x00, 0x00};
    private final byte[] reserved2 = {0x00, 0x00};
    private final byte[] goosePdu = {0x61, (byte) 0x81, (byte) 0x8A};
    private byte[] timeAllowedToLive = {(byte) 0x81, 0x05};
    private final byte[] t = {(byte) 0x84, 0x08};
    private final byte[] stNum = {(byte) 0x85, 0x05};
    private final byte[] sqNum = {(byte) 0x86, 0x05};
    private final byte[] simulation = {(byte) 0x87, 0x01};
    private final byte[] confRev = {(byte) 0x88, 0x05};
    private final byte[] ndsCom = {(byte) 0x89, 0x01};
    private final byte[] numDatSetEntries = {(byte) 0x8A, 0x05};

    private final byte[] bool = {(byte) 0x83, 0x01};
    private final byte[] int32 = {(byte) 0x85, 0x05};

    private final byte[] goCBRef = {(byte) 0x80, 0x00};
    private final byte[] datSet = {(byte) 0x82, 0x00};
    private final byte[] goID = {(byte) 0x83, 0x00};

    private final byte[] allDate = {(byte) 0xAB, 0x00};

    private byte[] valueGoCBRef;
    private byte[] valueDatSet;
    private byte[] valueGoID;

    private byte[] valueStNum = {0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] valueSqNum = {0x00, 0x00, 0x00, 0x00, 0x00};
    private boolean valueSimulation = false;
    private byte[] valueConfRev = {0x00, 0x00, 0x00, 0x00, 0x00};
    private boolean valueNdsCom = false;

    private byte[] valueBool = {0x01};
    private byte[] valueInt32 = {0x00, 0x00, 0x00, 0x00, 0x00};

    private byte[] valueTimeAllowedToLive = {0x00, 0x00, 0x00, 0x00, 0x02};
    private byte[] valueT = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private byte[] valueNumDatSetEntries = {0x00, 0x00, 0x00, 0x00, 0x00};

    private int valueAllDate;

    private List<Item> dat = new ArrayList<>();

    private ByteBuffer buffer;

    private int time = 1;
    private int delay = 50;
    ScheduledExecutorService ses;

    private int lenGoose;
    private int conf;
    private int sq;
    private int st;

    private List<PcapNetworkInterface> ifs;
    private PcapHandle sendHandle;
    private EthernetPacket packet;


    public void createGOOSE(DataSet dataSet) {
        createHeader(dataSet);
        createData(dataSet);
    }

    @SneakyThrows
    public GOOSE() {
        conf = 0;
        sq = 0;
        st = 0;
        ses = Executors.newSingleThreadScheduledExecutor();
        ifs = Pcaps.findAllDevs();
        PcapNetworkInterface activeInterface = null;
        for (PcapNetworkInterface pcapIface : ifs) {
            if (pcapIface != null && pcapIface.getDescription().contains("Famatech")) {
                activeInterface = pcapIface;
                break;
            }
        }
        assert activeInterface != null;
        sendHandle = activeInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
    }

    @SneakyThrows
    public void createMessage() {
        buffer = ByteBuffer.allocate(lenGoose);

        buffer.put(destination)
                .put(source)
                .put(type)
                .put(appID)
                .put(length)
                .put(reserved1)
                .put(reserved2)
                .put(goosePdu)
                .put(goCBRef)
                .put(valueGoCBRef)
                .put(timeAllowedToLive)
                .put(valueTimeAllowedToLive)
                .put(datSet)
                .put(valueDatSet)
                .put(goID)
                .put(valueGoID)
                .put(t)
                .put(valueT)
                .put(stNum)
                .put(valueStNum)
                .put(sqNum)
                .put(valueSqNum)
                .put(simulation)
                .put(convertingToByte(valueSimulation))
                .put(confRev)
                .put(valueConfRev)
                .put(ndsCom)
                .put(convertingToByte(valueNdsCom))
                .put(numDatSetEntries)
                .put(valueNumDatSetEntries)
                .put(allDate);
        dat.forEach(this::typeValue);

        packet = EthernetPacket.newPacket(buffer.array(), 0, lenGoose);

    }

    private void typeValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> buffer.put(bool)
                    .put(convertingToByte(Boolean.valueOf(e.getValue())));

            case "Integer" -> buffer.put(int32)
                    .put(ByteBuffer.allocate(5).putInt(1, Integer.parseInt(e.getValue())).array());

        }
    }

    private void createHeader(DataSet dataSet) {

        valueT = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        valueSqNum = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00};
        valueConfRev = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00};
        valueStNum = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00};
        sq = 0;
        st++;
        valueConfRev = ByteBuffer.allocate(5).putInt(1, conf).array();
        valueStNum = ByteBuffer.allocate(5).putInt(1, st).array();
        valueDatSet = dataSet.getDatasetName().getBytes(StandardCharsets.UTF_8);
        conf++;

        valueT = ByteBuffer.allocate(8)
                .putInt((int) (Instant.now().getEpochSecond()))
                .putInt(Instant.now().getNano())
                .array();

        for (int i = 0; i < destination.length; i++) {
            destination[i] = (byte) Integer.parseInt(dataSet.getMacDestination().split(":")[i], 16);
        }
        for (int i = 0; i < source.length; i++) {
            source[i] = (byte) Integer.parseInt(dataSet.getMacSource().split(":")[i], 16);
        }

        valueGoCBRef = dataSet.getGoCbRef().getBytes(StandardCharsets.UTF_8);
        valueGoID = dataSet.getGoID().getBytes(StandardCharsets.UTF_8);

        datSet[datSet.length - 1] = (byte) valueDatSet.length;
        goCBRef[goCBRef.length - 1] = (byte) valueGoCBRef.length;
        goID[goID.length - 1] = (byte) valueGoID.length;

    }

    private void createData(DataSet dataSet) {

        valueNumDatSetEntries = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00};

        dat.clear();
        dat = dataSet.getItems();

        valueNumDatSetEntries = ByteBuffer.allocate(5).putInt(1, dat.size()).array();
        valueAllDate = (byte) dat.size();

        lenGoose = destination.length +
                source.length +
                type.length +
                appID.length +
                length.length +
                reserved1.length +
                reserved2.length +
                goosePdu.length +
                goCBRef.length +
                valueGoCBRef.length +
                timeAllowedToLive.length +
                valueTimeAllowedToLive.length +
                datSet.length +
                valueDatSet.length +
                goID.length +
                valueGoID.length +
                t.length +
                valueT.length +
                stNum.length +
                valueStNum.length +
                sqNum.length +
                valueSqNum.length +
                simulation.length +
                convertingToByte(valueSimulation).length +
                confRev.length +
                valueConfRev.length +
                ndsCom.length +
                convertingToByte(valueNdsCom).length +
                numDatSetEntries.length +
                valueNumDatSetEntries.length;

        dat.forEach(this::lengthValue);

        lenGoose += allDate.length;

        length[length.length - 1] = (byte) (lenGoose - destination.length - source.length - type.length);

    }

    private void lengthValue(Item e) {
        switch (e.getType()) {
            case "Boolean" -> {
                lenGoose += bool.length + valueBool.length;
                allDate[allDate.length - 1] += bool.length + valueBool.length;
            }
            case "Integer" -> {
                lenGoose += int32.length + valueInt32.length;
                allDate[allDate.length - 1] += int32.length + valueInt32.length;
            }
        }
    }


    public void run() {
        try {
            sendHandle.sendPacket(packet);
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        }
        ses.schedule(this, time, TimeUnit.MILLISECONDS);
        increaseParam();
    }

    private void increaseParam() {
        valueSqNum = ByteBuffer.allocate(5).putInt(1, ++sq).array();
        time = Math.min(time * 2, delay);
        valueTimeAllowedToLive = ByteBuffer.allocate(5)
                .putInt(1, Math.min(time * 2, delay))
                .array();
        this.createMessage();
    }

    public byte[] convertingToByte(Boolean bool) {
        if (bool) {
            return new byte[]{0x01};
        } else {
            return new byte[]{0x00};
        }
    }
}
